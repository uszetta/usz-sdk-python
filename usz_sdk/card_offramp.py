"""
Non-Custodial BIN Sponsorship Visa/Mastercard Offramp Module (`usz_sdk/card_offramp.py`)
@custom:website https://uszetta.com
@custom:security-contact admin@uszetta.com

- Zero-Custody / Zero-PII / PCI-DSS Isolated Architecture:
  * Card issuance, KYC, Apple Pay / Google Pay provisioning, and merchant fiat clearing are handled
    exclusively by licensed external Web3 BIN sponsors (`kulipa`, `rain`, `baanx`, `gnosis_pay`).
  * User `USZ` remains 100% in the user's own external wallet (`Coinbase Smart Wallet` Passkey or
    `MetaMask` / `Rabby` / `Trust Wallet` / `WalletConnect`) until the exact moment of POS swipe.
  * Never accepts or transmits PAN, CVV, expiry date, Track-2, cardholder name, or billing address.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Mapping, Optional, Union

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from .crypto import (
    EIP712_DOMAIN_NAME,
    EIP712_DOMAIN_VERSION,
    from_wei_18,
    load_abi,
    normalize_bytes32,
    normalize_bytes32_hex,
    to_wei_18,
)
from .point_delegation import (
    ZeroPIIViolationError,
    assert_zero_pii_payload,
    format_point_balance,
    is_luhn_card_number,
    validate_external_wallet_type,
)

SUPPORTED_BIN_SPONSORS: tuple[str, ...] = (
    "kulipa",
    "rain",
    "baanx",
    "gnosis_pay",
)

DEFAULT_CARD_PER_SWIPE_USZ = Decimal("500.00")
DEFAULT_CARD_DAILY_LIMIT_USZ = Decimal("2000.00")
DEFAULT_CARD_VALIDITY_DAYS = 30
HOLD_EXPIRY_SECONDS = 7 * 86_400
SPONSOR_TIMELOCK_DELAY_SECONDS = 48 * 3_600


class UnsupportedBinSponsorError(ValueError):
    """Raised when an unverified BIN sponsor identifier is supplied."""


class InvalidWebhookSignatureError(ValueError):
    """Raised when a BIN sponsor JIT POS webhook fails HMAC-SHA256 or replay window verification."""


def validate_bin_sponsor(bin_sponsor: str) -> str:
    """Validate that `bin_sponsor` is one of `('kulipa', 'rain', 'baanx', 'gnosis_pay')`."""
    if not isinstance(bin_sponsor, str) or not bin_sponsor.strip():
        raise UnsupportedBinSponsorError(
            f"BIN sponsor identifier is required; supported sponsors: {SUPPORTED_BIN_SPONSORS}"
        )
    normalized = bin_sponsor.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in SUPPORTED_BIN_SPONSORS:
        raise UnsupportedBinSponsorError(
            f"Unsupported BIN sponsor '{bin_sponsor}'. "
            f"Supported licensed Web3 BIN sponsors: {SUPPORTED_BIN_SPONSORS}"
        )
    return normalized


def derive_card_token_hash(opaque_card_token_id: str) -> str:
    """
    Convert a non-sensitive external BIN sponsor card token ID (e.g. `'tok_kulipa_01HXYZ'`)
    into a `0x`-prefixed `bytes32` hash after enforcing PCI-DSS / Zero-PII checks.
    """
    if not isinstance(opaque_card_token_id, str) or not opaque_card_token_id.strip():
        raise ValueError("Non-empty opaque_card_token_id is required")
    cleaned = opaque_card_token_id.strip()
    if is_luhn_card_number(cleaned):
        raise ZeroPIIViolationError(
            "PCI-DSS / Zero-PII violation: raw Luhn card PAN cannot be used as opaque_card_token_id"
        )
    assert_zero_pii_payload(cleaned)
    return normalize_bytes32_hex(Web3.keccak(text=f"usz-card-token:{cleaned}"))


def _format_2dec(amount: Union[str, int, float, Decimal]) -> Decimal:
    if isinstance(amount, int) and amount >= 10**12:
        dec = from_wei_18(amount)
    else:
        dec = Decimal(str(amount))
    return dec.quantize(Decimal("0.01"), rounding=ROUND_DOWN)


def format_card_pos_receipt(
    spent_usz: Union[str, int, float, Decimal],
    remaining_usz: Union[str, int, float, Decimal],
    *,
    network: str = "Visa/Mastercard",
) -> str:
    """
    Format a merchant POS deduction receipt in unified web-point notation:
    Example: `"Paid -12.50 P ($12.50) via Visa/Mastercard | Remaining: 87.50 P"`
    """
    spent_dec = abs(_format_2dec(spent_usz))
    rem_dec = _format_2dec(remaining_usz)
    return (
        f"Paid -{spent_dec:,.2f} P (${spent_dec:,.2f}) via {network} | "
        f"Remaining: {rem_dec:,.2f} P"
    )


@dataclass
class CardSpendPermissionConfig:
    """
    User-adjustable Visa/Mastercard non-custodial spend permission configuration.
    Defaults to `$500.00` per swipe, `$2,000.00` daily UTC cap, and `30` days validity.
    """

    max_per_swipe_usz: Union[str, int, float, Decimal] = DEFAULT_CARD_PER_SWIPE_USZ
    daily_card_limit_usz: Union[str, int, float, Decimal] = DEFAULT_CARD_DAILY_LIMIT_USZ
    validity_days: int = DEFAULT_CARD_VALIDITY_DAYS
    valid_after: Optional[int] = None
    valid_until: Optional[int] = None
    salt: Optional[int] = None
    card_master_nonce: int = 0

    def __post_init__(self) -> None:
        self.max_per_swipe_usz = Decimal(str(self.max_per_swipe_usz))
        self.daily_card_limit_usz = Decimal(str(self.daily_card_limit_usz))
        self.validity_days = int(self.validity_days)

        if self.max_per_swipe_usz <= Decimal("0"):
            raise ValueError("max_per_swipe_usz must be greater than 0")
        if self.daily_card_limit_usz < self.max_per_swipe_usz:
            raise ValueError("daily_card_limit_usz must be >= max_per_swipe_usz")
        if self.validity_days <= 0 and self.valid_until is None:
            raise ValueError("validity_days must be greater than 0")

    @property
    def max_per_swipe_wei(self) -> int:
        return to_wei_18(self.max_per_swipe_usz)

    @property
    def daily_card_limit_wei(self) -> int:
        return to_wei_18(self.daily_card_limit_usz)

    def to_permission_dict(
        self,
        *,
        cardholder_wallet: str,
        bin_sponsor_operator: str,
        card_token_hash: Union[str, bytes],
        now_ts: Optional[int] = None,
    ) -> dict[str, Any]:
        if isinstance(card_token_hash, str) and not card_token_hash.startswith("0x"):
            # Treat non-hex string as opaque sponsor token ID after Zero-PII/Luhn check
            token_hash_hex = derive_card_token_hash(card_token_hash)
        else:
            token_hash_hex = normalize_bytes32_hex(card_token_hash)

        if int(token_hash_hex, 16) == 0:
            raise ValueError("card_token_hash cannot be zero bytes32")

        base_ts = int(now_ts if now_ts is not None else time.time())
        v_after = int(self.valid_after) if self.valid_after is not None else max(0, base_ts - 60)
        v_until = (
            int(self.valid_until)
            if self.valid_until is not None
            else base_ts + (self.validity_days * 86_400)
        )
        resolved_salt = (
            int(self.salt)
            if self.salt is not None
            else int.from_bytes(secrets.token_bytes(16), "big")
        )
        return {
            "cardholderWallet": Web3.to_checksum_address(cardholder_wallet),
            "binSponsorOperator": Web3.to_checksum_address(bin_sponsor_operator),
            "cardTokenHash": token_hash_hex,
            "maxPerSwipeUSZ": self.max_per_swipe_wei,
            "dailyCardLimitUSZ": self.daily_card_limit_wei,
            "validAfter": v_after,
            "validUntil": v_until,
            "salt": resolved_salt,
            "cardMasterNonce": int(self.card_master_nonce),
        }


CARD_SPEND_PERMISSION_TYPEHASH = Web3.keccak(
    text=(
        "CardSpendPermission(address cardholderWallet,address binSponsorOperator,"
        "bytes32 cardTokenHash,uint256 maxPerSwipeUSZ,uint256 dailyCardLimitUSZ,"
        "uint64 validAfter,uint64 validUntil,uint256 salt,uint256 cardMasterNonce)"
    )
)


def compute_card_permission_struct_hash(permission: Mapping[str, Any]) -> bytes:
    """Compute the exact 32-byte `getCardPermissionStructHash(permission)` matching `USZCardOfframpRouter.sol`."""
    token_hash_bytes = normalize_bytes32(permission["cardTokenHash"])
    encoded = Web3.solidity_keccak(
        [
            "bytes32",
            "uint256",
            "uint256",
            "bytes32",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
        ],
        [
            CARD_SPEND_PERMISSION_TYPEHASH,
            int(Web3.to_checksum_address(permission["cardholderWallet"]), 16),
            int(Web3.to_checksum_address(permission["binSponsorOperator"]), 16),
            token_hash_bytes,
            int(permission["maxPerSwipeUSZ"]),
            int(permission["dailyCardLimitUSZ"]),
            int(permission["validAfter"]),
            int(permission["validUntil"]),
            int(permission["salt"]),
            int(permission["cardMasterNonce"]),
        ],
    )
    return bytes(encoded)


def build_card_spend_permission_typed_data(
    *,
    chain_id: int,
    verifying_contract: str,
    permission: Mapping[str, Any],
) -> dict[str, Any]:
    """Build EIP-712 (`name='US Zetta'`, `version='1'`) typed data for external wallet signing."""
    token_hash_bytes = normalize_bytes32(permission["cardTokenHash"])
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "CardSpendPermission": [
                {"name": "cardholderWallet", "type": "address"},
                {"name": "binSponsorOperator", "type": "address"},
                {"name": "cardTokenHash", "type": "bytes32"},
                {"name": "maxPerSwipeUSZ", "type": "uint256"},
                {"name": "dailyCardLimitUSZ", "type": "uint256"},
                {"name": "validAfter", "type": "uint64"},
                {"name": "validUntil", "type": "uint64"},
                {"name": "salt", "type": "uint256"},
                {"name": "cardMasterNonce", "type": "uint256"},
            ],
        },
        "primaryType": "CardSpendPermission",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": Web3.to_checksum_address(verifying_contract),
        },
        "message": {
            "cardholderWallet": Web3.to_checksum_address(permission["cardholderWallet"]),
            "binSponsorOperator": Web3.to_checksum_address(permission["binSponsorOperator"]),
            "cardTokenHash": token_hash_bytes,
            "maxPerSwipeUSZ": int(permission["maxPerSwipeUSZ"]),
            "dailyCardLimitUSZ": int(permission["dailyCardLimitUSZ"]),
            "validAfter": int(permission["validAfter"]),
            "validUntil": int(permission["validUntil"]),
            "salt": int(permission["salt"]),
            "cardMasterNonce": int(permission["cardMasterNonce"]),
        },
    }


def sign_card_spend_permission_eoa(
    *,
    cardholder_private_key: str,
    chain_id: int,
    verifying_contract: str,
    permission: Mapping[str, Any],
) -> str:
    """Sign `CardSpendPermission` using an EOA external wallet (`eth_signTypedData_v4`)."""
    typed = build_card_spend_permission_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        permission=permission,
    )
    signable = encode_typed_data(full_message=typed)
    signed = Account.sign_message(signable, private_key=cardholder_private_key)
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def sign_jit_pos_webhook(
    payload: Union[Mapping[str, Any], bytes, str],
    webhook_secret: Union[str, bytes],
    *,
    timestamp: Optional[int] = None,
) -> tuple[bytes, str, Optional[str]]:
    """
    Helper to sign a Zero-PII JIT POS webhook payload with HMAC-SHA256 (`sha256=<hex>`),
    optionally binding `<timestamp>.<raw_body>`.
    """
    if isinstance(payload, Mapping):
        assert_zero_pii_payload(payload)
        raw_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    elif isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
    else:
        raw_bytes = bytes(payload)

    secret_bytes = (
        webhook_secret.encode("utf-8") if isinstance(webhook_secret, str) else bytes(webhook_secret)
    )
    ts_str = str(int(timestamp)) if timestamp is not None else None
    signing_input = f"{ts_str}.".encode("utf-8") + raw_bytes if ts_str is not None else raw_bytes
    mac_hex = hmac.new(secret_bytes, signing_input, hashlib.sha256).hexdigest()
    return raw_bytes, f"sha256={mac_hex}", ts_str


def verify_jit_pos_webhook(
    raw_body: Union[bytes, str],
    signature_header: str,
    webhook_secret: Union[str, bytes],
    *,
    timestamp_header: Optional[str] = None,
    tolerance_seconds: int = 300,
    now_ts: Optional[int] = None,
) -> dict[str, Any]:
    """
    Verify an incoming BIN sponsor (`Kulipa`, `Rain`, `Baanx`, `Gnosis Pay`) JIT POS webhook:
      1. Constant-time HMAC-SHA256 verification (`hmac.compare_digest`).
      2. Optional timestamp freshness check (`tolerance_seconds`).
      3. Strict PCI-DSS / Zero-PII payload inspection (`ZeroPIIViolationError` on any PAN/CVV/PII).
      4. BIN sponsor allowlist check (`SUPPORTED_BIN_SPONSORS`).
    """
    if not signature_header or not isinstance(signature_header, str):
        raise InvalidWebhookSignatureError("Missing webhook HMAC signature header")

    raw_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else bytes(raw_body)
    secret_bytes = (
        webhook_secret.encode("utf-8") if isinstance(webhook_secret, str) else bytes(webhook_secret)
    )

    if timestamp_header is not None:
        try:
            ts_int = int(str(timestamp_header).strip())
        except ValueError as exc:
            raise InvalidWebhookSignatureError("Invalid webhook timestamp header") from exc
        ref_now = int(now_ts if now_ts is not None else time.time())
        if abs(ref_now - ts_int) > int(tolerance_seconds):
            raise InvalidWebhookSignatureError(
                f"Webhook timestamp outside {tolerance_seconds}s replay tolerance"
            )
        signing_input = f"{ts_int}.".encode("utf-8") + raw_bytes
    else:
        signing_input = raw_bytes

    provided_hex = signature_header.strip()
    if provided_hex.lower().startswith("sha256="):
        provided_hex = provided_hex.split("=", 1)[1].strip()

    expected_hex = hmac.new(secret_bytes, signing_input, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_hex.lower(), expected_hex.lower()):
        raise InvalidWebhookSignatureError("JIT POS webhook HMAC-SHA256 signature mismatch")

    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("JIT POS webhook body must be a JSON object")

    # Enforce strict PCI-DSS / Zero-PII inspection on the parsed payload
    assert_zero_pii_payload(parsed)

    if "binSponsor" in parsed:
        parsed["binSponsor"] = validate_bin_sponsor(str(parsed["binSponsor"]))

    return parsed


class USZCardOfframpClient:
    """
    Zero-Custody / Zero-PII Visa & Mastercard Offramp Client wrapping L3 `USZCardOfframpRouter`.
    """

    def __init__(
        self,
        *,
        cardholder_wallet: str,
        wallet_type: str,
        bin_sponsor: str,
        bin_sponsor_operator: str,
        card_token_hash: Union[str, bytes],
        card_offramp_router_address: str,
        rpc_url: str = "http://127.0.0.1:8545",
        config: Optional[CardSpendPermissionConfig] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.wallet_type = validate_external_wallet_type(wallet_type)
        self.bin_sponsor = validate_bin_sponsor(bin_sponsor)
        assert_zero_pii_payload(metadata)

        self.cardholder_wallet = Web3.to_checksum_address(cardholder_wallet)
        self.bin_sponsor_operator = Web3.to_checksum_address(bin_sponsor_operator)
        self.router_address = Web3.to_checksum_address(card_offramp_router_address)

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = int(self.w3.eth.chain_id)
        self.router = self.w3.eth.contract(
            address=self.router_address,
            abi=load_abi("USZCardOfframpRouter"),
        )

        token_addr = self.router.functions.uszToken().call()
        self.token_address = Web3.to_checksum_address(token_addr)
        self.token_contract = self.w3.eth.contract(
            address=self.token_address,
            abi=load_abi("USZToken"),
        )

        onchain_nonce = int(self.router.functions.cardMasterNonce(self.cardholder_wallet).call())
        latest_block = self.w3.eth.get_block("latest")
        now_ts = int(latest_block["timestamp"])

        effective_cfg = config or CardSpendPermissionConfig(card_master_nonce=onchain_nonce)
        if effective_cfg.card_master_nonce == 0 and onchain_nonce > 0:
            effective_cfg.card_master_nonce = onchain_nonce

        self.config = effective_cfg
        self.permission = effective_cfg.to_permission_dict(
            cardholder_wallet=self.cardholder_wallet,
            bin_sponsor_operator=self.bin_sponsor_operator,
            card_token_hash=card_token_hash,
            now_ts=now_ts,
        )
        self.permission_hash_bytes = compute_card_permission_struct_hash(self.permission)
        self.permission_hash_hex = normalize_bytes32_hex(self.permission_hash_bytes)
        self.cardholder_signature: Optional[str] = None

    def get_external_wallet_typed_data(self) -> dict[str, Any]:
        """Return EIP-712 `CardSpendPermission` typed data for 1-time external wallet signing."""
        return build_card_spend_permission_typed_data(
            chain_id=self.chain_id,
            verifying_contract=self.router_address,
            permission=self.permission,
        )

    def attach_cardholder_signature(self, signature: str) -> None:
        if not signature or not isinstance(signature, str):
            raise ValueError("Valid hex cardholder signature is required")
        self.cardholder_signature = signature if signature.startswith("0x") else f"0x{signature}"

    def permission_tuple(self) -> tuple[Any, ...]:
        return (
            self.permission["cardholderWallet"],
            self.permission["binSponsorOperator"],
            normalize_bytes32(self.permission["cardTokenHash"]),
            int(self.permission["maxPerSwipeUSZ"]),
            int(self.permission["dailyCardLimitUSZ"]),
            int(self.permission["validAfter"]),
            int(self.permission["validUntil"]),
            int(self.permission["salt"]),
            int(self.permission["cardMasterNonce"]),
        )

    def signature_bytes(self) -> bytes:
        if not self.cardholder_signature:
            raise RuntimeError("Cardholder signature not attached; call attach_cardholder_signature()")
        raw = self.cardholder_signature.removeprefix("0x")
        return bytes.fromhex(raw)

    def get_card_summary(self) -> dict[str, Any]:
        usz_bal, rem_daily, max_swipe, valid_until, is_frozen, is_active = (
            self.router.functions.getCardAccountSummaryForPermission(self.permission_tuple()).call()
        )
        return {
            "pointsDisplay": format_point_balance(int(usz_bal)),
            "remainingDailyDisplay": format_point_balance(int(rem_daily)),
            "maxPerSwipeDisplay": format_point_balance(int(max_swipe)),
            "uszBalanceWei": int(usz_bal),
            "remainingDailyLimitWei": int(rem_daily),
            "maxPerSwipeWei": int(max_swipe),
            "validUntil": int(valid_until),
            "isFrozen": bool(is_frozen),
            "isActive": bool(is_active),
            "walletType": self.wallet_type,
            "binSponsor": self.bin_sponsor,
        }
