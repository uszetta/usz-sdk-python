"""
EIP-712 Cryptographic Voucher Signing, Recovery, and ABI Loader for USZAgentRouter.sol
Exact 1-to-1 specification match with `contracts/USZAgentRouter.sol`:
  - EIP712 Domain: name="US Zetta", version="1", chainId=<uint256>, verifyingContract=<address>
  - Struct Type: PaymentVoucher(bytes32 channelId,uint256 cumulativeAmount,uint256 nonce)
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Union

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

DECIMALS_18 = Decimal(10) ** 18
EIP712_DOMAIN_NAME = "US Zetta"
EIP712_DOMAIN_VERSION = "1"
ABI_DIR = Path(__file__).resolve().parent / "abis"


def load_abi(contract_name: str) -> list[dict[str, Any]]:
    """Load embedded contract ABI JSON from `usz_sdk/abis/<contract_name>.json`."""
    abi_path = ABI_DIR / f"{contract_name}.json"
    if not abi_path.exists():
        raise FileNotFoundError(f"Embedded ABI not found: {abi_path}")
    with abi_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["abi"] if isinstance(data, dict) and "abi" in data else data


def to_wei_18(amount: Union[str, int, float, Decimal]) -> int:
    """
    Convert human-readable USZ string/Decimal/float or integer wei into exact 18-decimal integer wei.
    If an int is passed directly, it is treated as already in wei;
    strings or Decimals like "0.0005" or "100" are scaled by 10**18.
    """
    if isinstance(amount, int):
        return amount
    dec = Decimal(str(amount))
    return int((dec * DECIMALS_18).to_integral_exact())


def from_wei_18(wei_amount: int) -> Decimal:
    """Convert 18-decimal integer wei into Decimal USZ."""
    return Decimal(int(wei_amount)) / DECIMALS_18


def normalize_bytes32(value: Union[bytes, str]) -> bytes:
    """Normalize a 32-byte hex string ('0x...') or bytes into raw 32-byte `bytes`."""
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(value)}")
        return value
    hex_str = value[2:] if value.startswith(("0x", "0X")) else value
    raw = bytes.fromhex(hex_str.zfill(64))
    if len(raw) != 32:
        raise ValueError(f"Expected 32 bytes from hex, got {len(raw)}")
    return raw


def normalize_bytes32_hex(value: Union[bytes, str]) -> str:
    """Normalize a 32-byte value into a 0x-prefixed 64-character lowercase hex string."""
    return "0x" + normalize_bytes32(value).hex()


def build_voucher_typed_data(
    chain_id: int,
    verifying_contract: str,
    channel_id: Union[bytes, str],
    cumulative_amount: int,
    nonce: int = 1,
) -> dict[str, Any]:
    """
    Build the exact EIP-712 typed data payload matching `USZAgentRouter.sol`:
      EIP712("US Zetta", "1")
      VOUCHER_TYPEHASH = keccak256("PaymentVoucher(bytes32 channelId,uint256 cumulativeAmount,uint256 nonce)")
    """
    channel_bytes = normalize_bytes32(channel_id)
    checksum_router = Web3.to_checksum_address(verifying_contract)

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PaymentVoucher": [
                {"name": "channelId", "type": "bytes32"},
                {"name": "cumulativeAmount", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
            ],
        },
        "primaryType": "PaymentVoucher",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": checksum_router,
        },
        "message": {
            "channelId": channel_bytes,
            "cumulativeAmount": int(cumulative_amount),
            "nonce": int(nonce),
        },
    }


def sign_payment_voucher(
    private_key: str,
    chain_id: int,
    verifying_contract: str,
    channel_id: Union[bytes, str],
    cumulative_amount: int,
    nonce: int = 1,
) -> str:
    """
    Sign an off-chain EIP-712 PaymentVoucher and return a 0x-prefixed 65-byte hex signature.
    Matches `USZAgentRouter.getVoucherDigest(channelId, cumulativeAmount, nonce)` byte-for-byte.
    """
    typed_data = build_voucher_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        channel_id=channel_id,
        cumulative_amount=cumulative_amount,
        nonce=nonce,
    )
    signable = encode_typed_data(full_message=typed_data)
    signed = Account.sign_message(signable, private_key=private_key)
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def recover_payment_voucher_signer(
    signature: Union[str, bytes],
    chain_id: int,
    verifying_contract: str,
    channel_id: Union[bytes, str],
    cumulative_amount: int,
    nonce: int = 1,
) -> str:
    """
    Recover the checksummed Ethereum address that signed the EIP-712 PaymentVoucher.
    """
    typed_data = build_voucher_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        channel_id=channel_id,
        cumulative_amount=cumulative_amount,
        nonce=nonce,
    )
    signable = encode_typed_data(full_message=typed_data)
    if isinstance(signature, str):
        sig_bytes = bytes.fromhex(signature[2:] if signature.startswith(("0x", "0X")) else signature)
    else:
        sig_bytes = signature
    recovered = Account.recover_message(signable, signature=sig_bytes)
    return Web3.to_checksum_address(recovered)
