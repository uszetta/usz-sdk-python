"""
AI Buyer Client Module (`usz_sdk/buyer.py`)
- `USZAgentClient` (aliased as `USZBuyerClient` / `USZClient`): Drop-in HTTP client
  (`client.post(url, json=...)`, `client.get(url)`) that transparently negotiates
  `HTTP 402 Payment Required` responses from US Zetta (USZ) AI Providers.
- Built-in AI Spend Limit Guardrails:
  * `max_per_call_usz: Decimal | str | None = "1.00"`: Rejects any single API call whose requested
    price exceeds the per-call cap before signing or submitting an on-chain transaction (`SpendLimitExceededError`).
  * `daily_spend_limit_usz: Decimal | str | None = "50.00"`: Tracks rolling 24-hour cumulative spend
    and rejects requests that would exceed the daily cap (`SpendLimitExceededError`).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional, Union

import httpx
from eth_account import Account
from web3 import Web3

from .crypto import (
    from_wei_18,
    load_abi,
    normalize_bytes32,
    normalize_bytes32_hex,
    sign_payment_voucher,
    to_wei_18,
)


class SpendLimitExceededError(RuntimeError):
    """
    Raised when an AI provider requests a per-call price exceeding `max_per_call_usz`
    or when a payment would cause the buyer's rolling 24-hour cumulative spend to exceed
    `daily_spend_limit_usz`.
    """


@dataclass
class ActiveBuyerChannel:
    """Client-side state for an open streaming payment channel."""

    channel_id_hex: str
    agent_id_hex: str
    router_address: str
    chain_id: int
    deposit_amount_wei: int
    price_per_call_wei: int
    cumulative_amount_wei: int = 0
    nonce: int = 1


class USZAgentClient:
    """
    Autonomous AI Buyer HTTP client with client-side spend guardrails (`max_per_call_usz`,
    `daily_spend_limit_usz`), automatic `HTTP 402` negotiation, on-chain `openChannel` / `payAgent`,
    and sub-millisecond off-chain EIP-712 (`name="US Zetta"`) voucher signing.
    """

    ROLLING_WINDOW_SECONDS = 86_400.0

    def __init__(
        self,
        private_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        router_address: Optional[str] = None,
        token_address: Optional[str] = None,
        default_channel_deposit: Union[str, int, float, Decimal] = "10",
        default_channel_duration: int = 86400,
        payment_mode: str = "channel",
        max_per_call_usz: Union[Decimal, str, int, float, None] = "1.00",
        daily_spend_limit_usz: Union[Decimal, str, int, float, None] = "50.00",
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        resolved_key = private_key or os.environ.get("USZ_PRIVATE_KEY")
        if not resolved_key:
            raise ValueError("private_key or USZ_PRIVATE_KEY environment variable is required")

        resolved_rpc = rpc_url or os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545")
        resolved_router = router_address or os.environ.get("USZ_ROUTER_ADDRESS")
        resolved_token = token_address or os.environ.get("USZ_TOKEN_ADDRESS")

        self.w3 = Web3(Web3.HTTPProvider(resolved_rpc))
        self.private_key = resolved_key
        self.account = Account.from_key(resolved_key)
        self.address = Web3.to_checksum_address(self.account.address)
        try:
            self.chain_id = int(self.w3.eth.chain_id)
        except Exception:
            self.chain_id = int(os.environ.get("USZ_CHAIN_ID", "777777"))

        self.router_address = (
            Web3.to_checksum_address(resolved_router) if resolved_router else None
        )
        self.token_address = (
            Web3.to_checksum_address(resolved_token) if resolved_token else None
        )

        self.default_channel_deposit_wei = to_wei_18(default_channel_deposit)
        self.default_channel_duration = int(default_channel_duration)
        self.payment_mode = payment_mode

        self.max_per_call_wei: Optional[int] = (
            to_wei_18(max_per_call_usz) if max_per_call_usz is not None else None
        )
        self.daily_spend_limit_wei: Optional[int] = (
            to_wei_18(daily_spend_limit_usz) if daily_spend_limit_usz is not None else None
        )

        # Rolling 24h spend ledger: list of (monotonic_timestamp, amount_wei)
        self._spend_history: list[tuple[float, int]] = []

        self.http = http_client or httpx.Client(timeout=30.0)

        # Cache of agentId -> ActiveBuyerChannel and endpoint -> agentId
        self.channels_by_agent: dict[str, ActiveBuyerChannel] = {}
        self.endpoint_to_agent: dict[str, str] = {}

        # Telemetry metrics
        self.open_channel_tx_count: int = 0
        self.direct_pay_tx_count: int = 0
        self.signing_latencies_ms: list[float] = []

    def _prune_and_get_daily_spend_wei(self, now_ts: Optional[float] = None) -> int:
        now = time.monotonic() if now_ts is None else now_ts
        cutoff = now - self.ROLLING_WINDOW_SECONDS
        self._spend_history = [(ts, amt) for ts, amt in self._spend_history if ts >= cutoff]
        return sum(amt for _, amt in self._spend_history)

    @property
    def daily_spent_usz(self) -> Decimal:
        """Return total USZ spent within the rolling 24-hour window."""
        return from_wei_18(self._prune_and_get_daily_spend_wei())

    def _enforce_and_record_spend_limits(self, call_price_wei: int) -> tuple[float, int]:
        """
        Validate `call_price_wei` against `max_per_call_usz` and `daily_spend_limit_usz`.
        Raises `SpendLimitExceededError` BEFORE any voucher signature or on-chain transaction.
        Returns the recorded `(timestamp, call_price_wei)` entry for rollback if needed.
        """
        if self.max_per_call_wei is not None and call_price_wei > self.max_per_call_wei:
            raise SpendLimitExceededError(
                f"Per-call spend limit exceeded: provider requested "
                f"{from_wei_18(call_price_wei)} USZ, which exceeds max_per_call_usz="
                f"{from_wei_18(self.max_per_call_wei)} USZ."
            )

        now = time.monotonic()
        spent_24h_wei = self._prune_and_get_daily_spend_wei(now)
        if (
            self.daily_spend_limit_wei is not None
            and spent_24h_wei + call_price_wei > self.daily_spend_limit_wei
        ):
            raise SpendLimitExceededError(
                f"Daily spend limit exceeded: spending {from_wei_18(call_price_wei)} USZ "
                f"with current 24h spend {from_wei_18(spent_24h_wei)} USZ would exceed "
                f"daily_spend_limit_usz={from_wei_18(self.daily_spend_limit_wei)} USZ."
            )

        entry = (now, call_price_wei)
        self._spend_history.append(entry)
        return entry

    def _rollback_spend_entry(self, entry: tuple[float, int]) -> None:
        try:
            self._spend_history.remove(entry)
        except ValueError:
            pass

    def _get_contracts(self, router_addr: str, token_addr: Optional[str] = None) -> tuple[Any, Any]:
        checksum_router = Web3.to_checksum_address(router_addr)
        router_contract = self.w3.eth.contract(
            address=checksum_router,
            abi=load_abi("USZAgentRouter"),
        )
        if token_addr is None:
            token_addr = self.token_address or router_contract.functions.uszToken().call()
        checksum_token = Web3.to_checksum_address(token_addr)
        token_contract = self.w3.eth.contract(
            address=checksum_token,
            abi=load_abi("USZToken"),
        )
        return router_contract, token_contract

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
            raise RuntimeError(f"Buyer transaction reverted: {tx_hash.hex()}")
        return dict(receipt)

    def ensure_allowance(self, router_addr: str, token_addr: str, min_amount_wei: int) -> None:
        _, token_contract = self._get_contracts(router_addr, token_addr)
        current_allowance = int(
            token_contract.functions.allowance(
                self.address, Web3.to_checksum_address(router_addr)
            ).call()
        )
        if current_allowance < min_amount_wei:
            approve_amount = max(min_amount_wei * 10, to_wei_18("100000"))
            self._send_tx(
                token_contract.functions.approve(
                    Web3.to_checksum_address(router_addr), approve_amount
                )
            )

    def open_channel_onchain(
        self,
        agent_id_hex: str,
        router_address: str,
        deposit_amount_wei: int,
        price_per_call_wei: int,
        token_address: Optional[str] = None,
        duration_seconds: Optional[int] = None,
    ) -> ActiveBuyerChannel:
        """
        Open a state channel on `USZAgentRouter` with a single on-chain transaction.
        """
        router_contract, token_contract = self._get_contracts(router_address, token_address)
        resolved_token = token_contract.address
        self.ensure_allowance(router_contract.address, resolved_token, deposit_amount_wei)

        agent_bytes = normalize_bytes32(agent_id_hex)
        dur = int(duration_seconds or self.default_channel_duration)

        receipt = self._send_tx(
            router_contract.functions.openChannel(
                agent_bytes,
                int(deposit_amount_wei),
                dur,
            )
        )
        logs = router_contract.events.ChannelOpened().process_receipt(receipt)
        if not logs:
            raise RuntimeError("ChannelOpened event not emitted")
        channel_id_bytes: bytes = logs[0]["args"]["channelId"]
        channel_id_hex = normalize_bytes32_hex(channel_id_bytes)
        self.open_channel_tx_count += 1

        active_ch = ActiveBuyerChannel(
            channel_id_hex=channel_id_hex,
            agent_id_hex=normalize_bytes32_hex(agent_id_hex),
            router_address=router_contract.address,
            chain_id=self.chain_id,
            deposit_amount_wei=int(deposit_amount_wei),
            price_per_call_wei=int(price_per_call_wei),
            cumulative_amount_wei=0,
            nonce=1,
        )
        self.channels_by_agent[active_ch.agent_id_hex] = active_ch
        return active_ch

    def pay_agent_direct_onchain(
        self,
        agent_id_hex: str,
        router_address: str,
        amount_wei: int,
        token_address: Optional[str] = None,
    ) -> str:
        """Execute a direct on-chain `payAgent(agentId, amount)` call and return the txHash."""
        router_contract, token_contract = self._get_contracts(router_address, token_address)
        self.ensure_allowance(router_contract.address, token_contract.address, amount_wei)

        receipt = self._send_tx(
            router_contract.functions.payAgent(
                normalize_bytes32(agent_id_hex),
                int(amount_wei),
                b"\x00" * 32,
            )
        )
        self.direct_pay_tx_count += 1
        tx_hex = receipt["transactionHash"].hex()
        return tx_hex if tx_hex.startswith("0x") else f"0x{tx_hex}"

    def _build_signed_voucher_headers(
        self,
        channel: ActiveBuyerChannel,
        call_price_wei: Optional[int] = None,
    ) -> dict[str, str]:
        delta = int(call_price_wei if call_price_wei is not None else channel.price_per_call_wei)
        new_cumulative = channel.cumulative_amount_wei + delta
        if new_cumulative > channel.deposit_amount_wei:
            raise ValueError(
                f"Channel {channel.channel_id_hex} deposit exhausted: "
                f"{new_cumulative} > {channel.deposit_amount_wei}"
            )

        t0 = time.perf_counter()
        sig = sign_payment_voucher(
            private_key=self.private_key,
            chain_id=channel.chain_id,
            verifying_contract=channel.router_address,
            channel_id=channel.channel_id_hex,
            cumulative_amount=new_cumulative,
            nonce=channel.nonce,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.signing_latencies_ms.append(elapsed_ms)

        channel.cumulative_amount_wei = new_cumulative
        return {
            "X-USZ-Channel-Id": channel.channel_id_hex,
            "X-USZ-Cumulative-Amount": str(new_cumulative),
            "X-USZ-Voucher-Nonce": str(channel.nonce),
            "X-USZ-Signature": sig,
        }

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """
        Send an HTTP request to an AI Provider endpoint, automatically enforcing spend guardrails
        and handling `HTTP 402` negotiation via EIP-712 streaming vouchers or direct on-chain payment.
        """
        headers = dict(kwargs.pop("headers", None) or {})

        known_agent_id = self.endpoint_to_agent.get(url)
        if self.payment_mode == "channel" and known_agent_id in self.channels_by_agent:
            active_ch = self.channels_by_agent[known_agent_id]
            if (
                active_ch.cumulative_amount_wei + active_ch.price_per_call_wei
                <= active_ch.deposit_amount_wei
            ):
                spend_entry = self._enforce_and_record_spend_limits(active_ch.price_per_call_wei)
                prev_cum = active_ch.cumulative_amount_wei
                voucher_headers = self._build_signed_voucher_headers(active_ch)
                merged_headers = {**headers, **voucher_headers}
                try:
                    resp = self.http.request(method, url, headers=merged_headers, **kwargs)
                except Exception:
                    active_ch.cumulative_amount_wei = prev_cum
                    self._rollback_spend_entry(spend_entry)
                    raise
                if resp.status_code >= 500:
                    active_ch.cumulative_amount_wei = prev_cum
                    self._rollback_spend_entry(spend_entry)
                return resp

        response = self.http.request(method, url, headers=headers, **kwargs)
        if response.status_code != 402:
            return response

        agent_id_hex = response.headers.get("X-USZ-Agent-Id")
        router_addr = response.headers.get("X-USZ-Router") or self.router_address
        token_addr = response.headers.get("X-USZ-Token") or self.token_address
        price_str = response.headers.get("X-USZ-Price", "0")

        if not agent_id_hex or not router_addr:
            raise RuntimeError(
                "Received HTTP 402 but missing X-USZ-Agent-Id or X-USZ-Router headers"
            )

        norm_agent_id = normalize_bytes32_hex(agent_id_hex)
        call_price_wei = int(price_str)

        spend_entry = self._enforce_and_record_spend_limits(call_price_wei)
        self.endpoint_to_agent[url] = norm_agent_id

        if self.payment_mode == "direct":
            try:
                tx_hash = self.pay_agent_direct_onchain(
                    agent_id_hex=norm_agent_id,
                    router_address=router_addr,
                    amount_wei=call_price_wei,
                    token_address=token_addr,
                )
            except Exception:
                self._rollback_spend_entry(spend_entry)
                raise
            retry_headers = {**headers, "X-USZ-Tx-Hash": tx_hash}
            return self.http.request(method, url, headers=retry_headers, **kwargs)

        active_ch = self.channels_by_agent.get(norm_agent_id)
        if (
            active_ch is None
            or active_ch.cumulative_amount_wei + call_price_wei > active_ch.deposit_amount_wei
        ):
            deposit_wei = max(self.default_channel_deposit_wei, call_price_wei * 10)
            try:
                active_ch = self.open_channel_onchain(
                    agent_id_hex=norm_agent_id,
                    router_address=router_addr,
                    deposit_amount_wei=deposit_wei,
                    price_per_call_wei=call_price_wei,
                    token_address=token_addr,
                )
            except Exception:
                self._rollback_spend_entry(spend_entry)
                raise

        prev_cum = active_ch.cumulative_amount_wei
        voucher_headers = self._build_signed_voucher_headers(active_ch, call_price_wei)
        retry_headers = {**headers, **voucher_headers}
        try:
            resp = self.http.request(method, url, headers=retry_headers, **kwargs)
        except Exception:
            active_ch.cumulative_amount_wei = prev_cum
            self._rollback_spend_entry(spend_entry)
            raise
        if resp.status_code >= 500:
            active_ch.cumulative_amount_wei = prev_cum
            self._rollback_spend_entry(spend_entry)
        return resp

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)


USZBuyerClient = USZAgentClient
USZClient = USZAgentClient
