"""
AI Provider Module (`usz_sdk/provider.py`)
- On-chain Agent Registration (`register_agent`)
- `@charge_usz(price_usz="0.0005")` FastAPI Decorator / `USZPaymentMiddleware`:
  * Returns `HTTP 402 Payment Required` with `X-USZ-*` negotiation headers if no payment voucher is present.
  * Caches on-chain channel state on first call (`1` RPC read per channel), and verifies all subsequent
    thousands of streaming requests purely in memory (`0` RPC calls) using EIP-712 (`name="US Zetta"`) ECDSA recovery.
  * Supports `success_only=True` atomic rollback if the inference handler raises an exception.
  * Supports on-demand and threshold-based 0%-fee instant on-chain settlement (`settle_channel`, `settle_all`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import functools
import inspect
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union, get_type_hints

from eth_account import Account
from fastapi import Request
from fastapi.responses import JSONResponse
from web3 import Web3

from .crypto import (
    from_wei_18,
    load_abi,
    normalize_bytes32,
    normalize_bytes32_hex,
    recover_payment_voucher_signer,
    to_wei_18,
)
from .point_delegation import (
    decode_delegated_payment_header,
    format_point_balance,
    format_point_delta,
    validate_external_wallet_type,
)


@dataclass
class CachedChannelState:
    """In-memory cached state for an open streaming channel."""

    channel_id_hex: str
    agent_id_hex: str
    payer: str
    provider: str
    deposit_amount: int
    expiration_time: int
    is_closed: bool
    accepted_cumulative_amount: int = 0
    latest_nonce: int = 0
    latest_signature: Optional[str] = None
    settled_onchain: bool = False
    last_call_payment_type: str = "PAID_INSTANT"


class USZProvider:
    """
    US Zetta (USZ) AI Provider manager for registering AI endpoints on-chain,
    verifying high-speed off-chain EIP-712 (`name="US Zetta"`) streaming vouchers in memory,
    and settling accumulated earnings with 0% protocol fee (`PAID_INSTANT`).
    """

    def __init__(
        self,
        private_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        router_address: Optional[str] = None,
        token_address: Optional[str] = None,
        agent_id: Optional[Union[str, bytes]] = None,
        auto_settle_threshold_ratio: float = 0.90,
        delegation_router_address: Optional[str] = None,
    ) -> None:
        resolved_key = private_key or os.environ.get("USZ_PRIVATE_KEY")
        if not resolved_key:
            raise ValueError("private_key or USZ_PRIVATE_KEY environment variable is required")

        resolved_rpc = rpc_url or os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545")
        resolved_router = router_address or os.environ.get("USZ_ROUTER_ADDRESS")
        if not resolved_router:
            raise ValueError("router_address or USZ_ROUTER_ADDRESS environment variable is required")

        self.w3 = Web3(Web3.HTTPProvider(resolved_rpc))
        self.private_key = resolved_key
        self.account = Account.from_key(resolved_key)
        self.address = Web3.to_checksum_address(self.account.address)

        self.router_address = Web3.to_checksum_address(resolved_router)
        self.router_contract = self.w3.eth.contract(
            address=self.router_address,
            abi=load_abi("USZAgentRouter"),
        )

        resolved_token = token_address or os.environ.get("USZ_TOKEN_ADDRESS")
        if resolved_token is None:
            resolved_token = self.router_contract.functions.uszToken().call()
        self.token_address = Web3.to_checksum_address(resolved_token)
        self.token_contract = self.w3.eth.contract(
            address=self.token_address,
            abi=load_abi("USZToken"),
        )

        self.vault_address: Optional[str] = os.environ.get("USZ_VAULT_ADDRESS")
        if self.vault_address is None:
            try:
                raw_vault = self.token_contract.functions.vaultAddress().call()
                if int(raw_vault, 16) != 0:
                    self.vault_address = Web3.to_checksum_address(raw_vault)
            except Exception:
                self.vault_address = None
        else:
            self.vault_address = Web3.to_checksum_address(self.vault_address)

        self.vault_contract = (
            self.w3.eth.contract(address=self.vault_address, abi=load_abi("USZVault"))
            if self.vault_address is not None
            else None
        )

        resolved_delegation = delegation_router_address or os.environ.get(
            "USZ_DELEGATION_ROUTER_ADDRESS"
        )
        self.delegation_router_address: Optional[str] = (
            Web3.to_checksum_address(resolved_delegation) if resolved_delegation else None
        )

        self.chain_id: int = int(self.w3.eth.chain_id)
        self.agent_id_hex: Optional[str] = (
            normalize_bytes32_hex(agent_id) if agent_id is not None else None
        )
        self.auto_settle_threshold_ratio = float(auto_settle_threshold_ratio)

        # In-memory cache of channel_id_hex -> CachedChannelState
        self.channels: dict[str, CachedChannelState] = {}
        self.onchain_channel_reads: int = 0
        self.in_memory_verifications: int = 0
        self.settled_tx_hashes: list[str] = []

    def _send_tx(self, contract_fn: Any) -> dict[str, Any]:
        nonce = self.w3.eth.get_transaction_count(self.address, "pending")
        tx_params: dict[str, Any] = {
            "from": self.address,
            "chainId": self.chain_id,
            "nonce": nonce,
            "gasPrice": 0,
        }
        try:
            estimated_gas = contract_fn.estimate_gas({"from": self.address})
            tx_params["gas"] = int(estimated_gas * 1.2) + 20_000
        except Exception:
            tx_params["gas"] = 1_500_000

        tx = contract_fn.build_transaction(tx_params)
        signed = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        raw_tx = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
        return dict(receipt)

    def stake_provider(
        self,
        amount_usz: Union[str, int, float, Decimal],
    ) -> dict[str, Any]:
        """
        Approve `USZToken` and call `USZAgentRouter.stakeProviderUsz(amount)`.
        Minimum 1 USZ total stake is required to receive agent payments; first stake locks for 30 days.
        Reward-eligible stake for Phase 2 QIXX matching is capped at 500 USZ.
        """
        amount_wei = to_wei_18(amount_usz)
        if amount_wei <= 0:
            raise ValueError("stake amount_usz must be greater than 0")

        current_allowance = int(
            self.token_contract.functions.allowance(self.address, self.router_address).call()
        )
        approve_tx_hash: Optional[str] = None
        if current_allowance < amount_wei:
            approve_receipt = self._send_tx(
                self.token_contract.functions.approve(self.router_address, amount_wei)
            )
            approve_hex = approve_receipt["transactionHash"].hex()
            approve_tx_hash = approve_hex if approve_hex.startswith("0x") else f"0x{approve_hex}"

        receipt = self._send_tx(
            self.router_contract.functions.stakeProviderUsz(amount_wei)
        )
        tx_hex = receipt["transactionHash"].hex()
        stake_tx_hash = tx_hex if tx_hex.startswith("0x") else f"0x{tx_hex}"

        status = self.get_provider_status(self.address)
        status["stakeTxHash"] = stake_tx_hash
        status["approveTxHash"] = approve_tx_hash
        status["stakedAddedUsz"] = str(from_wei_18(amount_wei))
        return status

    def unstake_provider(
        self,
        amount_usz: Union[str, int, float, Decimal],
    ) -> dict[str, Any]:
        """
        Call `USZAgentRouter.unstakeProviderUsz(amount)` after the 30-day initial lockup has elapsed.
        Raises a descriptive ValueError with the exact unlock time if called during the 30-day lockup.
        """
        amount_wei = to_wei_18(amount_usz)
        if amount_wei <= 0:
            raise ValueError("unstake amount_usz must be greater than 0")

        current_stake_wei = int(self.router_contract.functions.stakedUSZ(self.address).call())
        if amount_wei > current_stake_wei:
            raise ValueError(
                f"Cannot unstake {from_wei_18(amount_wei)} USZ: current staked balance is {from_wei_18(current_stake_wei)} USZ."
            )

        unlock_ts = int(
            self.router_contract.functions.getProviderUnlockTimestamp(self.address).call()
        )
        latest_block = self.w3.eth.get_block("latest")
        now_ts = int(latest_block["timestamp"])

        if unlock_ts > 0 and now_ts < unlock_ts:
            remaining_sec = unlock_ts - now_ts
            remaining_days = remaining_sec / 86400.0
            unlock_iso = datetime.fromtimestamp(unlock_ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            raise ValueError(
                f"30-day initial provider stake lockup has not elapsed yet. "
                f"Unlock scheduled at {unlock_iso} ({remaining_days:.2f} days / {remaining_sec} seconds remaining)."
            )

        receipt = self._send_tx(
            self.router_contract.functions.unstakeProviderUsz(amount_wei)
        )
        tx_hex = receipt["transactionHash"].hex()
        unstake_tx_hash = tx_hex if tx_hex.startswith("0x") else f"0x{tx_hex}"

        status = self.get_provider_status(self.address)
        status["unstakeTxHash"] = unstake_tx_hash
        status["unstakedAmountUsz"] = str(from_wei_18(amount_wei))
        return status

    @classmethod
    def query_provider_status(
        cls,
        address: str,
        rpc_url: Optional[str] = None,
        router_address: Optional[str] = None,
        vault_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Query provider staking, 30-day lockup expiration, daily redeem limits (staked * 10),
        and cumulative external earned USZ without requiring a private key.
        """
        resolved_rpc = rpc_url or os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545")
        resolved_router = router_address or os.environ.get("USZ_ROUTER_ADDRESS")
        if not resolved_router:
            raise ValueError("router_address or USZ_ROUTER_ADDRESS environment variable is required")

        w3 = Web3(Web3.HTTPProvider(resolved_rpc))
        provider_addr = Web3.to_checksum_address(address)
        router_addr = Web3.to_checksum_address(resolved_router)
        router = w3.eth.contract(address=router_addr, abi=load_abi("USZAgentRouter"))

        staked_wei = int(router.functions.stakedUSZ(provider_addr).call())
        reward_eligible_wei = int(router.functions.rewardEligibleStakeUSZ(provider_addr).call())
        first_staked_at = int(router.functions.firstStakedAt(provider_addr).call())
        unlock_ts = int(router.functions.getProviderUnlockTimestamp(provider_addr).call())
        is_registered = bool(router.functions.isRegisteredProvider(provider_addr).call())
        external_earned_wei = int(
            router.functions.cumulativeExternalEarnedUSZ(provider_addr).call()
        )
        min_stake_wei = int(router.functions.minProviderStake().call())

        latest_block = w3.eth.get_block("latest")
        now_ts = int(latest_block["timestamp"])
        is_locked = bool(unlock_ts > 0 and now_ts < unlock_ts)
        unlock_iso = (
            datetime.fromtimestamp(unlock_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if unlock_ts > 0
            else "Not Staked"
        )

        resolved_vault = vault_address or os.environ.get("USZ_VAULT_ADDRESS")
        if resolved_vault is None:
            try:
                token_addr = router.functions.uszToken().call()
                token = w3.eth.contract(
                    address=Web3.to_checksum_address(token_addr),
                    abi=load_abi("USZToken"),
                )
                v_addr = token.functions.vaultAddress().call()
                if int(v_addr, 16) != 0:
                    resolved_vault = Web3.to_checksum_address(v_addr)
            except Exception:
                resolved_vault = None

        daily_limit_wei = staked_wei * 10
        redeemed_today_wei = 0
        remaining_today_wei = daily_limit_wei

        if resolved_vault:
            try:
                vault = w3.eth.contract(
                    address=Web3.to_checksum_address(resolved_vault),
                    abi=load_abi("USZVault"),
                )
                _staked, d_limit, d_used, d_rem = (
                    vault.functions.getProviderDailyRedeemStatus(provider_addr).call()
                )
                daily_limit_wei = int(d_limit)
                redeemed_today_wei = int(d_used)
                remaining_today_wei = int(d_rem)
            except Exception:
                pass

        return {
            "provider": provider_addr,
            "isRegisteredProvider": is_registered,
            "canReceivePayments": staked_wei >= min_stake_wei,
            "stakedWei": staked_wei,
            "stakedUsz": str(from_wei_18(staked_wei)),
            "rewardEligibleStakeWei": reward_eligible_wei,
            "rewardEligibleStakeUsz": str(from_wei_18(reward_eligible_wei)),
            "firstStakedAt": first_staked_at,
            "unlockTimestamp": unlock_ts,
            "unlockIsoUtc": unlock_iso,
            "isLockupActive": is_locked,
            "dailyRedeemLimitWei": daily_limit_wei,
            "dailyRedeemLimitUsz": str(from_wei_18(daily_limit_wei)),
            "redeemedTodayWei": redeemed_today_wei,
            "redeemedTodayUsz": str(from_wei_18(redeemed_today_wei)),
            "remainingDailyRedeemWei": remaining_today_wei,
            "remainingDailyRedeemUsz": str(from_wei_18(remaining_today_wei)),
            "cumulativeExternalEarnedWei": external_earned_wei,
            "cumulativeExternalEarnedUsz": str(from_wei_18(external_earned_wei)),
        }

    def get_provider_status(self, address: Optional[str] = None) -> dict[str, Any]:
        """Return staking, lockup, daily redeem limit, and external earnings status for `address` (defaults to self)."""
        target = address or self.address
        return self.query_provider_status(
            address=target,
            rpc_url=self.w3.provider.endpoint_uri,  # type: ignore[attr-defined]
            router_address=self.router_address,
            vault_address=self.vault_address,
        )

    def register_agent(
        self,
        endpoint_url: str,
        price_per_call: Union[str, int, float, Decimal] = "0.0005",
        stake_amount_usz: Optional[Union[str, int, float, Decimal]] = None,
    ) -> str:
        """
        Register this AI provider on `USZAgentRouter` with 0% protocol fee,
        optionally staking `stake_amount_usz` if provided, and return the `0x`-prefixed 32-byte `agentId`.
        """
        if stake_amount_usz is not None and Decimal(str(stake_amount_usz)) > 0:
            self.stake_provider(stake_amount_usz)

        price_wei = to_wei_18(price_per_call)
        receipt = self._send_tx(
            self.router_contract.functions.registerAgent(endpoint_url, price_wei)
        )
        logs = self.router_contract.events.AgentRegistered().process_receipt(receipt)
        if not logs:
            raise RuntimeError("AgentRegistered event not emitted")

        agent_id_bytes: bytes = logs[0]["args"]["agentId"]
        self.agent_id_hex = normalize_bytes32_hex(agent_id_bytes)
        return self.agent_id_hex

    def _load_or_cache_channel(self, channel_id_hex: str) -> CachedChannelState:
        """
        Fetch channel metadata from L3 on the very first request for `channel_id_hex`,
        then serve all subsequent checks from memory (`0` RPC calls).
        """
        norm_id = normalize_bytes32_hex(channel_id_hex)
        cached = self.channels.get(norm_id)
        if cached is not None:
            return cached

        raw_id = normalize_bytes32(norm_id)
        ch_tuple = self.router_contract.functions.channels(raw_id).call()
        self.onchain_channel_reads += 1

        (
            _ch_id_bytes,
            agent_id_bytes,
            payer,
            provider_addr,
            deposit_amt,
            exp_time,
            _challenge_end,
            _disputed_amt,
            _highest_nonce,
            is_closed,
        ) = ch_tuple
        if int(payer, 16) == 0:
            raise ValueError(f"Channel {norm_id} does not exist on-chain")
        if Web3.to_checksum_address(provider_addr) != self.address:
            raise ValueError(
                f"Channel {norm_id} belongs to provider {provider_addr}, not {self.address}"
            )
        if is_closed:
            raise ValueError(f"Channel {norm_id} is already closed on-chain")

        state = CachedChannelState(
            channel_id_hex=norm_id,
            agent_id_hex=normalize_bytes32_hex(agent_id_bytes),
            payer=Web3.to_checksum_address(payer),
            provider=Web3.to_checksum_address(provider_addr),
            deposit_amount=int(deposit_amt),
            expiration_time=int(exp_time),
            is_closed=bool(is_closed),
        )
        self.channels[norm_id] = state
        return state

    def verify_and_record_voucher(
        self,
        channel_id_hex: str,
        cumulative_amount: int,
        signature: str,
        required_delta_wei: int,
        nonce: int = 1,
    ) -> tuple[CachedChannelState, int, Optional[str], int]:
        """
        Verify an incoming EIP-712 `PaymentVoucher` in memory and advance the channel's cumulative amount.
        Returns `(channel_state, prev_cumulative_amount, prev_signature, prev_nonce)` for atomic rollback if needed.
        """
        state = self._load_or_cache_channel(channel_id_hex)
        if state.is_closed or state.settled_onchain:
            raise ValueError(f"Channel {state.channel_id_hex} is already settled/closed")

        if cumulative_amount > state.deposit_amount:
            raise ValueError(
                f"Voucher cumulativeAmount ({cumulative_amount}) exceeds channel deposit ({state.deposit_amount})"
            )

        expected_min = state.accepted_cumulative_amount + required_delta_wei
        if cumulative_amount < expected_min:
            raise ValueError(
                f"Insufficient voucher increment: got {cumulative_amount}, expected >= {expected_min}"
            )

        recovered_signer = recover_payment_voucher_signer(
            signature=signature,
            chain_id=self.chain_id,
            verifying_contract=self.router_address,
            channel_id=state.channel_id_hex,
            cumulative_amount=cumulative_amount,
            nonce=nonce,
        )
        if recovered_signer != state.payer:
            raise ValueError(
                f"Invalid EIP-712 voucher signer: recovered {recovered_signer}, expected payer {state.payer}"
            )

        prev_amt = state.accepted_cumulative_amount
        prev_sig = state.latest_signature
        prev_nonce = state.latest_nonce

        state.accepted_cumulative_amount = cumulative_amount
        state.latest_signature = signature
        state.latest_nonce = nonce
        state.last_call_payment_type = "PAID_INSTANT"
        self.in_memory_verifications += 1

        return state, prev_amt, prev_sig, prev_nonce

    def settle_channel(self, channel_id_hex: str) -> str:
        """
        Submit the highest-value signed voucher for `channel_id_hex` to `USZAgentRouter.settleChannelByProvider`
        in a single on-chain transaction (0% protocol fee, 100% instant `USZ` payout).
        """
        norm_id = normalize_bytes32_hex(channel_id_hex)
        state = self.channels.get(norm_id)
        if state is None:
            raise KeyError(f"Channel {norm_id} not found in provider cache")
        if state.settled_onchain:
            raise RuntimeError(f"Channel {norm_id} was already settled on-chain")
        if not state.latest_signature:
            raise RuntimeError(f"Channel {norm_id} has no signed voucher to settle")

        raw_id = normalize_bytes32(norm_id)
        sig_bytes = bytes.fromhex(
            state.latest_signature[2:]
            if state.latest_signature.startswith(("0x", "0X"))
            else state.latest_signature
        )

        receipt = self._send_tx(
            self.router_contract.functions.settleChannelByProvider(
                raw_id,
                int(state.accepted_cumulative_amount),
                int(state.latest_nonce),
                sig_bytes,
            )
        )
        state.settled_onchain = True
        state.is_closed = True
        tx_hex = receipt["transactionHash"].hex()
        tx_hash_str = tx_hex if tx_hex.startswith("0x") else f"0x{tx_hex}"
        self.settled_tx_hashes.append(tx_hash_str)
        return tx_hash_str

    def settle_all(self) -> list[str]:
        """Settle all active cached channels that have unsubmitted vouchers."""
        settled: list[str] = []
        for ch_id, state in list(self.channels.items()):
            if (
                not state.settled_onchain
                and state.latest_signature
                and state.accepted_cumulative_amount > 0
            ):
                settled.append(self.settle_channel(ch_id))
        return settled

    def preflight_delegated_payment(
        self,
        delegated_header: str,
        required_amount_wei: int,
    ) -> tuple[Any, str, int]:
        """
        Verify a Zero-Custody / Zero-PII `X-USZ-Delegated-Payment` header (`SpendPermission` +
        `DelegatedChargeIntent`) via static call against `USZSpendDelegationRouter` before inference.
        """
        envelope = decode_delegated_payment_header(delegated_header)
        validate_external_wallet_type(str(envelope.get("walletType", "")))

        router_candidate = self.delegation_router_address or envelope.get("delegationRouter")
        if not router_candidate:
            raise ValueError("Missing USZSpendDelegationRouter address")
        delegation_addr = Web3.to_checksum_address(str(router_candidate))

        if (
            self.delegation_router_address is not None
            and delegation_addr != self.delegation_router_address
        ):
            raise ValueError("Delegation router mismatch with provider configuration")

        is_trusted = bool(
            self.router_contract.functions.trustedDelegationRouters(delegation_addr).call()
        )
        if not is_trusted:
            raise ValueError(f"Untrusted delegation router: {delegation_addr}")

        perm = envelope["permission"]
        intent = envelope["intent"]

        payer_addr = Web3.to_checksum_address(str(perm["payer"]))
        session_signer_addr = Web3.to_checksum_address(str(perm["sessionSigner"]))
        intent_provider = Web3.to_checksum_address(str(intent["provider"]))
        if intent_provider != self.address:
            raise ValueError(
                f"DelegatedChargeIntent provider mismatch: expected {self.address}, got {intent_provider}"
            )

        amount_wei = int(intent["amountUSZ"])
        if amount_wei < int(required_amount_wei):
            raise ValueError(
                f"DelegatedChargeIntent amount {amount_wei} below required {required_amount_wei}"
            )

        perm_tuple = (
            payer_addr,
            session_signer_addr,
            int(perm["maxPerTxUSZ"]),
            int(perm["dailyLimitUSZ"]),
            int(perm["validAfter"]),
            int(perm["validUntil"]),
            int(perm["salt"]),
            int(perm["masterNonce"]),
        )
        intent_tuple = (
            normalize_bytes32(intent["permissionHash"]),
            intent_provider,
            amount_wei,
            normalize_bytes32(intent.get("serviceRef", b"\x00" * 32)),
            int(intent["intentNonce"]),
            int(intent["deadline"]),
        )

        payer_sig_hex = str(envelope["payerSignature"])
        session_sig_hex = str(envelope["sessionSignature"])
        payer_sig_bytes = bytes.fromhex(
            payer_sig_hex[2:] if payer_sig_hex.startswith("0x") else payer_sig_hex
        )
        session_sig_bytes = bytes.fromhex(
            session_sig_hex[2:] if session_sig_hex.startswith("0x") else session_sig_hex
        )

        delegation_contract = self.w3.eth.contract(
            address=delegation_addr,
            abi=load_abi("USZSpendDelegationRouter"),
        )
        prepared_call = delegation_contract.functions.executeDelegatedCharge(
            perm_tuple,
            payer_sig_bytes,
            intent_tuple,
            session_sig_bytes,
        )
        # Static preflight validates ECDSA/EIP-1271 signatures, per-tx/daily caps, expiry, revocation & balance
        prepared_call.call({"from": self.address})
        return prepared_call, payer_addr, amount_wei

    def settle_delegated_payment(
        self,
        prepared_call: Any,
        payer_address: str,
        amount_wei: int,
    ) -> dict[str, Any]:
        """Submit validated `executeDelegatedCharge` on-chain (Zero-Gas L3) and return web point summary."""
        receipt = self._send_tx(prepared_call)
        tx_hex = receipt["transactionHash"].hex()
        tx_hash_str = tx_hex if tx_hex.startswith("0x") else f"0x{tx_hex}"
        self.settled_tx_hashes.append(tx_hash_str)
        remaining_bal = int(self.token_contract.functions.balanceOf(payer_address).call())
        return {
            "txHash": tx_hash_str,
            "remainingBalanceWei": remaining_bal,
            "pointsBalanceDisplay": format_point_balance(remaining_bal),
            "pointDebitDisplay": format_point_delta(amount_wei, is_debit=True),
        }

    def charge_usz(
        self,
        price_usz: Union[str, int, float, Decimal, None] = None,
        *,
        price: Union[str, int, float, Decimal, None] = None,
        mode: str = "streaming",
        success_only: bool = True,
    ) -> Callable[..., Any]:
        """Decorator bound to this `USZProvider` instance."""
        resolved_price = price_usz if price_usz is not None else (price if price is not None else "0.0005")
        return charge_usz(
            price_usz=resolved_price,
            mode=mode,
            success_only=success_only,
            provider=self,
        )


def charge_usz(
    price_usz: Union[str, int, float, Decimal, None] = None,
    *,
    price: Union[str, int, float, Decimal, None] = None,
    mode: str = "streaming",
    success_only: bool = True,
    provider: Optional[USZProvider] = None,
) -> Callable[..., Any]:
    """
    FastAPI route decorator that protects an AI endpoint with `HTTP 402 Payment Required`
    and in-memory EIP-712 (`name="US Zetta"`) voucher verification.
    """
    effective_price = price_usz if price_usz is not None else (price if price is not None else "0.0005")
    call_price_wei = to_wei_18(effective_price)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(func)
        expects_request = "request" in sig.parameters

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Optional[Request] = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            active_provider = provider
            if active_provider is None and request is not None:
                active_provider = getattr(request.app.state, "usz_provider", None)

            if active_provider is None or request is None:
                raise RuntimeError(
                    "USZProvider not configured on @charge_usz or app.state.usz_provider"
                )

            channel_id_hdr = request.headers.get("X-USZ-Channel-Id")
            cum_amount_hdr = request.headers.get("X-USZ-Cumulative-Amount")
            signature_hdr = request.headers.get("X-USZ-Signature")
            nonce_hdr = request.headers.get("X-USZ-Voucher-Nonce", "1")
            direct_tx_hdr = request.headers.get("X-USZ-Tx-Hash")
            delegated_hdr = request.headers.get("X-USZ-Delegated-Payment")

            payment_meta_headers = {
                "X-USZ-Agent-Id": active_provider.agent_id_hex or "",
                "X-USZ-Provider": active_provider.address,
                "X-USZ-Router": active_provider.router_address,
                "X-USZ-Delegation-Router": active_provider.delegation_router_address or "",
                "X-USZ-Token": active_provider.token_address,
                "X-USZ-Price": str(call_price_wei),
                "X-USZ-Price-USZ": str(from_wei_18(call_price_wei)),
                "X-USZ-Price-Points": format_point_balance(call_price_wei),
                "X-USZ-Chain-Id": str(active_provider.chain_id),
                "X-USZ-Mode": mode,
                "X-USZ-Payment-Type": "PAID_INSTANT",
            }

            # Case 0: Zero-Custody / Zero-PII Delegated Point Payment (`X-USZ-Delegated-Payment`)
            if delegated_hdr:
                t_start_del = time.perf_counter()
                try:
                    prepared_call, payer_addr, charge_amount_wei = (
                        active_provider.preflight_delegated_payment(
                            delegated_header=delegated_hdr,
                            required_amount_wei=call_price_wei,
                        )
                    )
                except Exception as exc:
                    return JSONResponse(
                        status_code=402,
                        content={"error": f"Invalid delegated point payment: {exc}"},
                        headers=payment_meta_headers,
                    )
                verify_ms_del = (time.perf_counter() - t_start_del) * 1000.0

                call_kwargs = dict(kwargs)
                if not expects_request and "request" in call_kwargs:
                    call_kwargs.pop("request")

                try:
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **call_kwargs)
                    else:
                        result = func(*args, **call_kwargs)
                except Exception:
                    if not success_only:
                        active_provider.settle_delegated_payment(
                            prepared_call, payer_addr, charge_amount_wei
                        )
                    raise

                settlement = active_provider.settle_delegated_payment(
                    prepared_call, payer_addr, charge_amount_wei
                )
                delegated_resp_headers = {
                    "X-USZ-Verify-Ms": f"{verify_ms_del:.4f}",
                    "X-USZ-Payment-Type": "PAID_DELEGATED_POINTS",
                    "X-USZ-Point-Debit": settlement["pointDebitDisplay"],
                    "X-USZ-Point-Balance": settlement["pointsBalanceDisplay"],
                    "X-USZ-Settlement-Tx": settlement["txHash"],
                }
                if isinstance(result, JSONResponse):
                    for k, v in delegated_resp_headers.items():
                        result.headers[k] = v
                    return result
                return JSONResponse(
                    status_code=200,
                    content=result,
                    headers=delegated_resp_headers,
                )

            # Case 1: Direct single-call txHash mode
            if mode == "direct" or (direct_tx_hdr and not signature_hdr):
                if not direct_tx_hdr:
                    return JSONResponse(
                        status_code=402,
                        content={
                            "error": "Payment Required",
                            "message": "Provide X-USZ-Tx-Hash or open a streaming channel.",
                            "priceWei": str(call_price_wei),
                        },
                        headers=payment_meta_headers,
                    )
                receipt = active_provider.w3.eth.get_transaction_receipt(direct_tx_hdr)
                if receipt is None or receipt["status"] != 1:
                    return JSONResponse(
                        status_code=402,
                        content={"error": "Invalid or failed direct payment transaction"},
                        headers=payment_meta_headers,
                    )
                call_kwargs = dict(kwargs)
                if not expects_request and "request" in call_kwargs:
                    call_kwargs.pop("request")
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **call_kwargs)
                return func(*args, **call_kwargs)

            # Case 2: Streaming EIP-712 State Channel mode
            if not (channel_id_hdr and cum_amount_hdr and signature_hdr):
                return JSONResponse(
                    status_code=402,
                    content={
                        "error": "Payment Required",
                        "message": "Attach EIP-712 signed voucher headers (X-USZ-Channel-Id, X-USZ-Cumulative-Amount, X-USZ-Signature).",
                        "agentId": active_provider.agent_id_hex,
                        "router": active_provider.router_address,
                        "token": active_provider.token_address,
                        "priceWei": str(call_price_wei),
                        "chainId": active_provider.chain_id,
                    },
                    headers=payment_meta_headers,
                )

            t_start = time.perf_counter()
            try:
                cum_amount_wei = int(cum_amount_hdr)  # type: ignore[arg-type]
                voucher_nonce = int(nonce_hdr)
                ch_state, prev_amt, prev_sig, prev_nonce = (
                    active_provider.verify_and_record_voucher(
                        channel_id_hex=channel_id_hdr,  # type: ignore[arg-type]
                        cumulative_amount=cum_amount_wei,
                        signature=signature_hdr,  # type: ignore[arg-type]
                        required_delta_wei=call_price_wei,
                        nonce=voucher_nonce,
                    )
                )
            except Exception as exc:
                return JSONResponse(
                    status_code=402,
                    content={"error": f"Invalid payment voucher: {exc}"},
                    headers=payment_meta_headers,
                )
            verify_ms = (time.perf_counter() - t_start) * 1000.0

            call_kwargs = dict(kwargs)
            if not expects_request and "request" in call_kwargs:
                call_kwargs.pop("request")

            try:
                if inspect.iscoroutinefunction(func):
                    result = await func(*args, **call_kwargs)
                else:
                    result = func(*args, **call_kwargs)
            except Exception:
                if success_only:
                    ch_state.accepted_cumulative_amount = prev_amt
                    ch_state.latest_signature = prev_sig
                    ch_state.latest_nonce = prev_nonce
                raise

            if (
                active_provider.auto_settle_threshold_ratio > 0
                and ch_state.deposit_amount > 0
                and not ch_state.settled_onchain
            ):
                usage_ratio = ch_state.accepted_cumulative_amount / ch_state.deposit_amount
                if usage_ratio >= active_provider.auto_settle_threshold_ratio:
                    active_provider.settle_channel(ch_state.channel_id_hex)

            response_headers = {
                "X-USZ-Verify-Ms": f"{verify_ms:.4f}",
                "X-USZ-Accepted-Cumulative": str(ch_state.accepted_cumulative_amount),
                "X-USZ-Payment-Type": "PAID_INSTANT",
            }

            if isinstance(result, JSONResponse):
                for k, v in response_headers.items():
                    result.headers[k] = v
                return result

            return JSONResponse(
                status_code=200,
                content=result,
                headers=response_headers,
            )

        try:
            resolved_hints = get_type_hints(func, include_extras=True)
        except Exception:
            resolved_hints = dict(getattr(func, "__annotations__", {}))

        resolved_params: list[inspect.Parameter] = []
        for param in sig.parameters.values():
            if param.name in resolved_hints:
                resolved_params.append(param.replace(annotation=resolved_hints[param.name]))
            else:
                resolved_params.append(param)

        if not expects_request:
            resolved_params.append(
                inspect.Parameter(
                    "request",
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=Request,
                )
            )
            resolved_hints["request"] = Request

        if hasattr(wrapper, "__wrapped__"):
            delattr(wrapper, "__wrapped__")
        wrapper.__annotations__ = resolved_hints
        wrapper.__signature__ = sig.replace(parameters=resolved_params)  # type: ignore[attr-defined]

        return wrapper

    return decorator


class USZPaymentMiddleware:
    """
    ASGI / FastAPI Middleware wrapper that binds a `USZProvider` instance to `app.state.usz_provider`.
    """

    def __init__(self, app: Any, provider: USZProvider) -> None:
        self.app = app
        self.provider = provider
        if hasattr(app, "state"):
            app.state.usz_provider = provider

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        await self.app(scope, receive, send)
