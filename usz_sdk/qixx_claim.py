"""
QIXX Gasless Claim Request Builder & Pre-Check Helpers (`usz_sdk/qixx_claim.py`)
@custom:website https://qixx.io
@custom:security-contact admin@qixx.io

Enables `0 ETH` users (`3-A` 180-day USZ marketing stakers) and AI providers (`30-day` cliff
epoch reward recipients) to query claim eligibility and construct Zero-Custody / Zero-PII
gasless relay payloads for `QIXXClaimRelayer` without touching smart contracts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
from typing import Any, Mapping, Optional, Sequence, Union

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from .crypto import (
    from_wei_18,
    load_abi,
    normalize_bytes32,
    normalize_bytes32_hex,
    to_wei_18,
)
from .point_delegation import (
    ZeroPIIViolationError,
    assert_zero_pii_payload,
)

QIXX_MARKETING_DOMAIN_NAME = "QIXX Marketing Vault"
QIXX_MARKETING_DOMAIN_VERSION = "1"


def build_marketing_claim_typed_data(
    *,
    chain_id: int,
    verifying_contract: str,
    l3_claim_id: Union[bytes, str],
    l3_position_id: int,
    recipient: str,
    qixx_amount_wei: int,
    deadline: int,
) -> dict[str, Any]:
    """
    Build EIP-712 typed data matching `QIXXMarketingVault.sol`:
      - Domain: `name="QIXX Marketing Vault"`, `version="1"`
      - Struct: `MarketingClaimVoucher(bytes32 l3ClaimId,uint256 l3PositionId,address recipient,uint256 qixxAmount,uint256 deadline)`
    """
    claim_id_bytes = normalize_bytes32(l3_claim_id)
    if int.from_bytes(claim_id_bytes, "big") == 0:
        raise ValueError("l3_claim_id cannot be zero bytes32")

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "MarketingClaimVoucher": [
                {"name": "l3ClaimId", "type": "bytes32"},
                {"name": "l3PositionId", "type": "uint256"},
                {"name": "recipient", "type": "address"},
                {"name": "qixxAmount", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "MarketingClaimVoucher",
        "domain": {
            "name": QIXX_MARKETING_DOMAIN_NAME,
            "version": QIXX_MARKETING_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": Web3.to_checksum_address(verifying_contract),
        },
        "message": {
            "l3ClaimId": claim_id_bytes,
            "l3PositionId": int(l3_position_id),
            "recipient": Web3.to_checksum_address(recipient),
            "qixxAmount": int(qixx_amount_wei),
            "deadline": int(deadline),
        },
    }


def sign_marketing_claim_voucher(
    *,
    settlement_signer_private_key: str,
    chain_id: int,
    verifying_contract: str,
    l3_claim_id: Union[bytes, str],
    l3_position_id: int,
    recipient: str,
    qixx_amount: Union[str, int, float, Decimal],
    deadline: int,
) -> str:
    """Sign an EIP-712 `MarketingClaimVoucher` with the official bridge `settlementSigner` key."""
    amount_wei = to_wei_18(qixx_amount)
    typed = build_marketing_claim_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        l3_claim_id=l3_claim_id,
        l3_position_id=l3_position_id,
        recipient=recipient,
        qixx_amount_wei=amount_wei,
        deadline=deadline,
    )
    signable = encode_typed_data(full_message=typed)
    signed = Account.sign_message(signable, private_key=settlement_signer_private_key)
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def recover_marketing_claim_signer(
    *,
    chain_id: int,
    verifying_contract: str,
    l3_claim_id: Union[bytes, str],
    l3_position_id: int,
    recipient: str,
    qixx_amount_wei: int,
    deadline: int,
    signature: Union[bytes, str],
) -> str:
    """Recover the checksummed EIP-712 signer address for a `MarketingClaimVoucher`."""
    typed = build_marketing_claim_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        l3_claim_id=l3_claim_id,
        l3_position_id=l3_position_id,
        recipient=recipient,
        qixx_amount_wei=int(qixx_amount_wei),
        deadline=int(deadline),
    )
    signable = encode_typed_data(full_message=typed)
    sig_bytes = (
        bytes.fromhex(signature.removeprefix("0x"))
        if isinstance(signature, str)
        else bytes(signature)
    )
    if len(sig_bytes) != 65:
        raise ValueError(f"Expected 65-byte ECDSA signature, got {len(sig_bytes)} bytes")
    recovered = Account.recover_message(signable, signature=sig_bytes)
    return Web3.to_checksum_address(recovered)


def compute_provider_reward_leaf(
    *,
    chain_id: int,
    pool_address: str,
    epoch_id: int,
    provider: str,
    amount_qixx_wei: int,
) -> bytes:
    """
    Compute the exact Double-Hashed Merkle Leaf matching `QIXXProviderRewardPool.computeRewardLeaf`:
      `keccak256(bytes.concat(keccak256(abi.encode(chainId, poolAddress, epochId, provider, amountQIXX))))`
    """
    inner_encoded = abi_encode(
        ["uint256", "address", "uint256", "address", "uint256"],
        [
            int(chain_id),
            Web3.to_checksum_address(pool_address),
            int(epoch_id),
            Web3.to_checksum_address(provider),
            int(amount_qixx_wei),
        ],
    )
    inner_hash = bytes(Web3.keccak(inner_encoded))
    return bytes(Web3.keccak(inner_hash))


def verify_provider_merkle_proof(
    merkle_proof: Sequence[Union[bytes, str]],
    merkle_root: Union[bytes, str],
    leaf: Union[bytes, str],
) -> bool:
    """
    Verify a sorted-pair OpenZeppelin `MerkleProof.verify` proof off-chain with zero gas cost.
    """
    computed = normalize_bytes32(leaf)
    target_root = normalize_bytes32(merkle_root)
    if int.from_bytes(target_root, "big") == 0:
        return False

    for sibling_raw in merkle_proof:
        sibling = normalize_bytes32(sibling_raw)
        if int.from_bytes(computed, "big") < int.from_bytes(sibling, "big"):
            computed = bytes(Web3.keccak(computed + sibling))
        else:
            computed = bytes(Web3.keccak(sibling + computed))

    return computed == target_root


def build_gasless_marketing_claim_request(
    *,
    l3_claim_id: Union[bytes, str],
    l3_position_id: int,
    recipient: str,
    qixx_amount: Union[str, int, float, Decimal],
    deadline: int,
    signature: Union[bytes, str],
    marketing_vault_address: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    as_json: bool = False,
) -> Union[dict[str, Any], str]:
    """
    Construct a canonical Zero-PII gasless marketing claim request payload for `qixx.io` -> `QIXXClaimRelayer`.
    """
    assert_zero_pii_payload(metadata)
    if isinstance(l3_claim_id, str) and not l3_claim_id.startswith("0x"):
        assert_zero_pii_payload(l3_claim_id)

    claim_id_hex = normalize_bytes32_hex(l3_claim_id)
    if int(claim_id_hex, 16) == 0:
        raise ValueError("l3_claim_id cannot be zero bytes32")

    checksum_recipient = Web3.to_checksum_address(recipient)
    if int(checksum_recipient, 16) == 0:
        raise ValueError("recipient cannot be zero address")

    amount_wei = to_wei_18(qixx_amount)
    if amount_wei <= 0:
        raise ValueError("qixx_amount must be greater than 0")

    sig_hex = (
        "0x" + signature.hex()
        if isinstance(signature, bytes)
        else (signature if signature.startswith("0x") else f"0x{signature}")
    )
    raw_sig = bytes.fromhex(sig_hex.removeprefix("0x"))
    if len(raw_sig) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(raw_sig)} bytes")

    payload: dict[str, Any] = {
        "claimType": "marketing_3a",
        "l3ClaimId": claim_id_hex,
        "l3PositionId": int(l3_position_id),
        "recipient": checksum_recipient,
        "qixxAmountWei": str(amount_wei),
        "qixxAmount": str(from_wei_18(amount_wei)),
        "deadline": int(deadline),
        "signature": sig_hex.lower() if sig_hex.startswith("0x") else f"0x{sig_hex.lower()}",
    }
    if marketing_vault_address:
        payload["marketingVaultAddress"] = Web3.to_checksum_address(marketing_vault_address)
    if metadata:
        payload["metadata"] = dict(metadata)

    # Final Zero-PII sweep on the serialized request envelope
    assert_zero_pii_payload(payload)

    if as_json:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return payload


def build_gasless_provider_claim_request(
    *,
    epoch_id: int,
    provider: str,
    amount_qixx: Union[str, int, float, Decimal],
    merkle_proof: Sequence[Union[bytes, str]],
    reward_pool_address: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    as_json: bool = False,
) -> Union[dict[str, Any], str]:
    """
    Construct a canonical Zero-PII gasless provider reward claim payload for `usz-cli` / `qixx.io` -> `QIXXClaimRelayer`.
    """
    assert_zero_pii_payload(metadata)

    if int(epoch_id) < 0:
        raise ValueError("epoch_id must be >= 0")

    checksum_provider = Web3.to_checksum_address(provider)
    if int(checksum_provider, 16) == 0:
        raise ValueError("provider cannot be zero address")

    amount_wei = to_wei_18(amount_qixx)
    if amount_wei <= 0:
        raise ValueError("amount_qixx must be greater than 0")

    normalized_proof = [normalize_bytes32_hex(node) for node in merkle_proof]

    payload: dict[str, Any] = {
        "claimType": "provider_reward",
        "epochId": int(epoch_id),
        "provider": checksum_provider,
        "amountQIXXWei": str(amount_wei),
        "amountQIXX": str(from_wei_18(amount_wei)),
        "merkleProof": normalized_proof,
    }
    if reward_pool_address:
        payload["rewardPoolAddress"] = Web3.to_checksum_address(reward_pool_address)
    if metadata:
        payload["metadata"] = dict(metadata)

    assert_zero_pii_payload(payload)

    if as_json:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return payload


def query_qixx_claim_status(
    *,
    rpc_url: str,
    claim_type: str,
    wallet_address: str,
    marketing_vault_address: Optional[str] = None,
    reward_pool_address: Optional[str] = None,
    l3_claim_id: Optional[Union[bytes, str]] = None,
    epoch_id: Optional[int] = None,
    amount_qixx: Optional[Union[str, int, float, Decimal]] = None,
    merkle_proof: Optional[Sequence[Union[bytes, str]]] = None,
) -> dict[str, Any]:
    """
    Query on-chain L2 claim readiness (`isClaimed`, `cliffElapsed`, `ethBalanceWei`, `qixxBalance`)
    with zero gas cost (`eth_call` only) for `usz-cli qixx claim-status`.
    """
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    checksum_wallet = Web3.to_checksum_address(wallet_address)
    eth_balance_wei = int(w3.eth.get_balance(checksum_wallet))
    latest_ts = int(w3.eth.get_block("latest")["timestamp"])

    normalized_type = claim_type.strip().lower()
    if normalized_type in ("marketing", "marketing_3a"):
        if not marketing_vault_address:
            raise ValueError("marketing_vault_address is required for marketing claim-status")
        if l3_claim_id is None:
            raise ValueError("l3_claim_id is required for marketing claim-status")

        vault_addr = Web3.to_checksum_address(marketing_vault_address)
        vault = w3.eth.contract(address=vault_addr, abi=load_abi("QIXXMarketingVault"))
        qixx_token_addr = Web3.to_checksum_address(vault.functions.qixxToken().call())
        qixx_token = w3.eth.contract(address=qixx_token_addr, abi=load_abi("QIXXToken"))

        claim_id_bytes = normalize_bytes32(l3_claim_id)
        already_claimed = bool(vault.functions.isClaimedL3Id(claim_id_bytes).call())
        remaining_vault_wei = int(vault.functions.remainingVaultQIXX().call())
        wallet_qixx_wei = int(qixx_token.functions.balanceOf(checksum_wallet).call())

        return {
            "claimType": "marketing_3a",
            "wallet": checksum_wallet,
            "ethBalanceWei": eth_balance_wei,
            "qixxBalance": str(from_wei_18(wallet_qixx_wei)),
            "marketingVaultAddress": vault_addr,
            "l3ClaimId": normalize_bytes32_hex(claim_id_bytes),
            "alreadyClaimed": already_claimed,
            "remainingVaultQIXX": str(from_wei_18(remaining_vault_wei)),
            "readyForGaslessRelay": (not already_claimed) and remaining_vault_wei > 0,
            "checkedAtTimestamp": latest_ts,
        }

    if normalized_type in ("provider", "provider_reward"):
        if not reward_pool_address:
            raise ValueError("reward_pool_address is required for provider claim-status")
        if epoch_id is None:
            raise ValueError("epoch_id is required for provider claim-status")

        pool_addr = Web3.to_checksum_address(reward_pool_address)
        pool = w3.eth.contract(address=pool_addr, abi=load_abi("QIXXProviderRewardPool"))
        qixx_token_addr = Web3.to_checksum_address(pool.functions.qixxToken().call())
        qixx_token = w3.eth.contract(address=qixx_token_addr, abi=load_abi("QIXXToken"))

        ep = int(epoch_id)
        is_finalized = bool(pool.functions.isEpochFinalized(ep).call())
        already_claimed = bool(pool.functions.isEpochClaimed(ep, checksum_wallet).call())
        unlock_ts = int(pool.functions.epochUnlockTimestamp(ep).call()) if is_finalized else 0
        cliff_elapsed = is_finalized and (latest_ts >= unlock_ts)
        remaining_cliff_sec = max(0, unlock_ts - latest_ts) if is_finalized else None
        unlock_iso = (
            datetime.fromtimestamp(unlock_ts, tz=timezone.utc).isoformat()
            if unlock_ts > 0
            else None
        )
        wallet_qixx_wei = int(qixx_token.functions.balanceOf(checksum_wallet).call())

        proof_valid: Optional[bool] = None
        if is_finalized and amount_qixx is not None and merkle_proof is not None:
            amt_wei = to_wei_18(amount_qixx)
            root_bytes = pool.functions.epochMerkleRoots(ep).call()
            leaf_bytes = compute_provider_reward_leaf(
                chain_id=int(w3.eth.chain_id),
                pool_address=pool_addr,
                epoch_id=ep,
                provider=checksum_wallet,
                amount_qixx_wei=amt_wei,
            )
            proof_valid = verify_provider_merkle_proof(merkle_proof, root_bytes, leaf_bytes)

        ready = is_finalized and cliff_elapsed and (not already_claimed)
        if proof_valid is False:
            ready = False

        return {
            "claimType": "provider_reward",
            "wallet": checksum_wallet,
            "ethBalanceWei": eth_balance_wei,
            "qixxBalance": str(from_wei_18(wallet_qixx_wei)),
            "rewardPoolAddress": pool_addr,
            "epochId": ep,
            "isEpochFinalized": is_finalized,
            "alreadyClaimed": already_claimed,
            "unlockTimestamp": unlock_ts,
            "unlockIsoUtc": unlock_iso,
            "cliffElapsed": cliff_elapsed,
            "remainingCliffSeconds": remaining_cliff_sec,
            "merkleProofValid": proof_valid,
            "readyForGaslessRelay": ready,
            "checkedAtTimestamp": latest_ts,
        }

    raise ValueError(
        f"Unsupported claim_type '{claim_type}'; expected 'marketing' or 'provider'"
    )


__all__ = [
    "QIXX_MARKETING_DOMAIN_NAME",
    "QIXX_MARKETING_DOMAIN_VERSION",
    "ZeroPIIViolationError",
    "build_gasless_marketing_claim_request",
    "build_gasless_provider_claim_request",
    "build_marketing_claim_typed_data",
    "compute_provider_reward_leaf",
    "query_qixx_claim_status",
    "recover_marketing_claim_signer",
    "sign_marketing_claim_voucher",
    "verify_provider_merkle_proof",
]
