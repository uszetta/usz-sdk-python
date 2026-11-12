"""
Zero-Custody / Zero-PII External Wallet Spend Delegation & Point UX Module (`usz_sdk/point_delegation.py`)
Website: https://uszetta.com | Security Contact: admin@uszetta.com

- Strictly enforces the 5 verified non-custodial external wallets:
  `("coinbase_smart_wallet", "metamask", "rabby", "trust_wallet", "walletconnect")`
- Blocks any embedded/custodial wallet type (`UnsupportedCustodialWalletError`) and any PII/secret
  leakage (`ZeroPIIViolationError` via `assert_zero_pii_payload`).
- Default SpendPermission limits: `$10.00` per tx / `$100.00` daily / `30 days` validity (freely adjustable by user).
- Ephemeral client-side session signer (`USZDelegatedPointClient`) executes popup-free HTTP 402 micro-payments
  and formats balances as standard web points (`49.98 P ($49.98)`, `-0.02 P`).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN
import json
import re
import secrets
import time
from typing import Any, Mapping, Optional, Union

from eth_account import Account
from eth_account.messages import encode_typed_data
import httpx
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

SUPPORTED_EXTERNAL_WALLETS: tuple[str, ...] = (
    "coinbase_smart_wallet",
    "metamask",
    "rabby",
    "trust_wallet",
    "walletconnect",
)

DEFAULT_MAX_PER_TX_USZ = Decimal("10.00")
DEFAULT_DAILY_LIMIT_USZ = Decimal("100.00")
DEFAULT_VALIDITY_DAYS = 30

FORBIDDEN_PII_KEYS: frozenset[str] = frozenset(
    {
        "email",
        "e_mail",
        "user_email",
        "phone",
        "phone_number",
        "mobile",
        "name",
        "full_name",
        "first_name",
        "last_name",
        "real_name",
        "cardholder_name",
        "card_number",
        "card_num",
        "credit_card",
        "pan",
        "cvv",
        "cvc",
        "cvv2",
        "cvc2",
        "expiry_date",
        "expiration_date",
        "card_expiry",
        "exp_month",
        "exp_year",
        "track1",
        "track2",
        "magnetic_stripe",
        "pin_block",
        "ssn",
        "resident_id",
        "passport",
        "dob",
        "date_of_birth",
        "billing_address",
        "home_address",
        "private_key",
        "mnemonic",
        "seed_phrase",
        "recovery_share",
        "custodial_secret",
    }
)

_EMAIL_VALUE_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CARD_DIGITS_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_TRACK2_RE = re.compile(r";?\d{13,19}=\d{4,}")


def is_luhn_card_number(candidate: str) -> bool:
    """Return True if `candidate` contains 13-19 digits passing the ISO/IEC 7812 Luhn checksum."""
    digits = re.sub(r"\D", "", candidate or "")
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        d = ord(ch) - 48
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class UnsupportedCustodialWalletError(ValueError):
    """Raised when an unapproved custodial, embedded, or email-based wallet type is supplied."""


class ZeroPIIViolationError(ValueError):
    """Raised when personal identifiable information (PII) or secret key material is detected in a payload."""


def validate_external_wallet_type(wallet_type: str) -> str:
    """
    Ensure `wallet_type` belongs to the 5 verified non-custodial external wallets.
    Raises `UnsupportedCustodialWalletError` on any custodial/embedded/unknown wallet identifier.
    """
    if not isinstance(wallet_type, str) or not wallet_type.strip():
        raise UnsupportedCustodialWalletError(
            f"External wallet type is required; supported wallets: {SUPPORTED_EXTERNAL_WALLETS}"
        )
    normalized = wallet_type.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in SUPPORTED_EXTERNAL_WALLETS:
        raise UnsupportedCustodialWalletError(
            f"Wallet '{wallet_type}' is prohibited under US Zetta Zero-Custody policy. "
            f"Only verified external wallets {SUPPORTED_EXTERNAL_WALLETS} are allowed."
        )
    return normalized


def _normalize_key_identifier(raw_key: str) -> str:
    s1 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(raw_key).strip())
    return re.sub(r"[^a-z0-9]+", "_", s1.lower()).strip("_")


def assert_zero_pii_payload(payload: Any, *, _path: str = "root") -> None:
    """
    Recursively inspect metadata/session payloads and immediately reject any PII or key-custody fields.
    """
    if payload is None:
        return

    if isinstance(payload, Mapping):
        for k, v in payload.items():
            norm_k = _normalize_key_identifier(str(k))
            if norm_k in FORBIDDEN_PII_KEYS:
                raise ZeroPIIViolationError(
                    f"Zero-PII policy violation: forbidden sensitive key '{k}' detected at {_path}.{k}"
                )
            assert_zero_pii_payload(v, _path=f"{_path}.{k}")
        return

    if isinstance(payload, (list, tuple, set)):
        for idx, item in enumerate(payload):
            assert_zero_pii_payload(item, _path=f"{_path}[{idx}]")
        return

    if isinstance(payload, str):
        stripped = payload.strip()
        if not stripped or stripped.startswith(("0x", "0X", "http://", "https://")):
            return
        leaf_key = _normalize_key_identifier(_path.rsplit(".", 1)[-1].split("[", 1)[0])
        if leaf_key.endswith("_wei") and stripped.isdigit():
            return
        if _EMAIL_VALUE_RE.search(stripped):
            raise ZeroPIIViolationError(
                f"Zero-PII policy violation: email address value detected at {_path}"
            )
        if _TRACK2_RE.search(stripped):
            raise ZeroPIIViolationError(
                f"Zero-PII / PCI-DSS violation: ISO-7813 Track-2 card data detected at {_path}"
            )
        card_match = _CARD_DIGITS_RE.search(stripped)
        if card_match:
            digits_only = re.sub(r"\D", "", card_match.group(0))
            if 13 <= len(digits_only) <= 19:
                luhn_tag = " (Luhn PAN)" if is_luhn_card_number(digits_only) else ""
                raise ZeroPIIViolationError(
                    f"Zero-PII / PCI-DSS violation: raw payment card number{luhn_tag} detected at {_path}"
                )


def _format_decimal_points(dec_val: Decimal) -> str:
    abs_val = abs(dec_val)
    quantized_2 = abs_val.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
    if abs_val == quantized_2:
        return f"{quantized_2:.2f}"
    trimmed = format(abs_val.normalize(), "f")
    if "." not in trimmed:
        return f"{trimmed}.00"
    int_part, frac_part = trimmed.split(".", 1)
    if len(frac_part) < 2:
        frac_part = frac_part.ljust(2, "0")
    return f"{int_part}.{frac_part}"


def format_point_balance(amount: Union[str, int, float, Decimal]) -> str:
    """
    Format an 18-decimal wei integer or human-readable USZ amount as web points:
      e.g. `49.98` -> `"49.98 P ($49.98)"`, `50 * 10**18` -> `"50.00 P ($50.00)"`.
    """
    dec = from_wei_18(amount) if isinstance(amount, int) else Decimal(str(amount))
    sign_prefix = "-" if dec < 0 else ""
    formatted = _format_decimal_points(dec)
    return f"{sign_prefix}{formatted} P ({sign_prefix}${formatted})"


def format_point_delta(
    amount: Union[str, int, float, Decimal],
    *,
    is_debit: bool = True,
) -> str:
    """
    Format a point deduction or credit without blockchain jargon:
      e.g. `0.02` (`is_debit=True`) -> `"-0.02 P"`.
    """
    dec = from_wei_18(amount) if isinstance(amount, int) else Decimal(str(amount))
    formatted = _format_decimal_points(abs(dec))
    prefix = "-" if (is_debit or dec < 0) else "+"
    return f"{prefix}{formatted} P"


@dataclass
class SpendPermissionConfig:
    """
    User-adjustable spend delegation configuration.
    Defaults to `$10.00` max per tx, `$100.00` daily limit, and `30` days validity.
    """

    max_per_tx_usz: Decimal = DEFAULT_MAX_PER_TX_USZ
    daily_limit_usz: Decimal = DEFAULT_DAILY_LIMIT_USZ
    validity_days: int = DEFAULT_VALIDITY_DAYS
    valid_after: Optional[int] = None
    valid_until: Optional[int] = None
    salt: Optional[int] = None
    master_nonce: int = 0

    def __post_init__(self) -> None:
        self.max_per_tx_usz = Decimal(str(self.max_per_tx_usz))
        self.daily_limit_usz = Decimal(str(self.daily_limit_usz))
        self.validity_days = int(self.validity_days)

        if self.max_per_tx_usz <= Decimal("0"):
            raise ValueError("max_per_tx_usz must be greater than 0")
        if self.daily_limit_usz < self.max_per_tx_usz:
            raise ValueError("daily_limit_usz must be >= max_per_tx_usz")
        if self.validity_days <= 0 and self.valid_until is None:
            raise ValueError("validity_days must be greater than 0")

    @property
    def max_per_tx_wei(self) -> int:
        return to_wei_18(self.max_per_tx_usz)

    @property
    def daily_limit_wei(self) -> int:
        return to_wei_18(self.daily_limit_usz)

    def to_permission_dict(
        self,
        *,
        payer: str,
        session_signer: str,
        now_ts: Optional[int] = None,
    ) -> dict[str, Any]:
        base_ts = int(now_ts if now_ts is not None else time.time())
        v_after = int(self.valid_after) if self.valid_after is not None else max(0, base_ts - 60)
        v_until = (
            int(self.valid_until)
            if self.valid_until is not None
            else base_ts + (self.validity_days * 86_400)
        )
        resolved_salt = (
            int(self.salt) if self.salt is not None else int.from_bytes(secrets.token_bytes(16), "big")
        )
        return {
            "payer": Web3.to_checksum_address(payer),
            "sessionSigner": Web3.to_checksum_address(session_signer),
            "maxPerTxUSZ": to_wei_18(self.max_per_tx_usz),
            "dailyLimitUSZ": to_wei_18(self.daily_limit_usz),
            "validAfter": v_after,
            "validUntil": v_until,
            "salt": resolved_salt,
            "masterNonce": int(self.master_nonce),
        }


SPEND_PERMISSION_TYPEHASH = Web3.keccak(
    text=(
        "SpendPermission(address payer,address sessionSigner,uint256 maxPerTxUSZ,"
        "uint256 dailyLimitUSZ,uint64 validAfter,uint64 validUntil,uint256 salt,uint256 masterNonce)"
    )
)


def compute_permission_struct_hash(permission: Mapping[str, Any]) -> bytes:
    """Compute the exact 32-byte `getPermissionStructHash(permission)` matching `USZSpendDelegationRouter.sol`."""
    encoded = Web3.solidity_keccak(
        [
            "bytes32",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
        ],
        [
            SPEND_PERMISSION_TYPEHASH,
            int(Web3.to_checksum_address(permission["payer"]), 16),
            int(Web3.to_checksum_address(permission["sessionSigner"]), 16),
            int(permission["maxPerTxUSZ"]),
            int(permission["dailyLimitUSZ"]),
            int(permission["validAfter"]),
            int(permission["validUntil"]),
            int(permission["salt"]),
            int(permission["masterNonce"]),
        ],
    )
    return bytes(encoded)


def build_spend_permission_typed_data(
    *,
    chain_id: int,
    verifying_contract: str,
    permission: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Build EIP-712 (`name="US Zetta"`, `version="1"`) typed data for 1-time external wallet signing
    (`eth_signTypedData_v4` across Coinbase Smart Wallet, MetaMask, Rabby, Trust Wallet, WalletConnect).
    """
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "SpendPermission": [
                {"name": "payer", "type": "address"},
                {"name": "sessionSigner", "type": "address"},
                {"name": "maxPerTxUSZ", "type": "uint256"},
                {"name": "dailyLimitUSZ", "type": "uint256"},
                {"name": "validAfter", "type": "uint64"},
                {"name": "validUntil", "type": "uint64"},
                {"name": "salt", "type": "uint256"},
                {"name": "masterNonce", "type": "uint256"},
            ],
        },
        "primaryType": "SpendPermission",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": Web3.to_checksum_address(verifying_contract),
        },
        "message": {
            "payer": Web3.to_checksum_address(permission["payer"]),
            "sessionSigner": Web3.to_checksum_address(permission["sessionSigner"]),
            "maxPerTxUSZ": int(permission["maxPerTxUSZ"]),
            "dailyLimitUSZ": int(permission["dailyLimitUSZ"]),
            "validAfter": int(permission["validAfter"]),
            "validUntil": int(permission["validUntil"]),
            "salt": int(permission["salt"]),
            "masterNonce": int(permission["masterNonce"]),
        },
    }


def sign_spend_permission_eoa(
    *,
    payer_private_key: str,
    chain_id: int,
    verifying_contract: str,
    permission: Mapping[str, Any],
) -> str:
    """Helper for test suites / local EOA external wallet simulation (`eth_signTypedData_v4`)."""
    typed = build_spend_permission_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        permission=permission,
    )
    signable = encode_typed_data(full_message=typed)
    signed = Account.sign_message(signable, private_key=payer_private_key)
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def build_delegated_charge_intent_typed_data(
    *,
    chain_id: int,
    verifying_contract: str,
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    """Build EIP-712 typed data for popup-free client session key signing (`DelegatedChargeIntent`)."""
    perm_hash_bytes = normalize_bytes32(intent["permissionHash"])
    service_ref_bytes = normalize_bytes32(intent.get("serviceRef", b"\x00" * 32))
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "DelegatedChargeIntent": [
                {"name": "permissionHash", "type": "bytes32"},
                {"name": "provider", "type": "address"},
                {"name": "amountUSZ", "type": "uint256"},
                {"name": "serviceRef", "type": "bytes32"},
                {"name": "intentNonce", "type": "uint256"},
                {"name": "deadline", "type": "uint64"},
            ],
        },
        "primaryType": "DelegatedChargeIntent",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": Web3.to_checksum_address(verifying_contract),
        },
        "message": {
            "permissionHash": perm_hash_bytes,
            "provider": Web3.to_checksum_address(intent["provider"]),
            "amountUSZ": int(intent["amountUSZ"]),
            "serviceRef": service_ref_bytes,
            "intentNonce": int(intent["intentNonce"]),
            "deadline": int(intent["deadline"]),
        },
    }


def sign_delegated_charge_intent(
    *,
    session_private_key: str,
    chain_id: int,
    verifying_contract: str,
    intent: Mapping[str, Any],
) -> str:
    """Sign a `DelegatedChargeIntent` silently in memory using the ephemeral local session key."""
    typed = build_delegated_charge_intent_typed_data(
        chain_id=chain_id,
        verifying_contract=verifying_contract,
        intent=intent,
    )
    signable = encode_typed_data(full_message=typed)
    signed = Account.sign_message(signable, private_key=session_private_key)
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"


def encode_delegated_payment_header(envelope: Mapping[str, Any]) -> str:
    """Encode a Zero-PII delegated payment envelope into a compact base64url header string."""
    assert_zero_pii_payload(envelope)
    raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_delegated_payment_header(header_value: str) -> dict[str, Any]:
    """Decode `X-USZ-Delegated-Payment` header (base64url or raw JSON) and enforce Zero-PII check."""
    stripped = header_value.strip()
    if stripped.startswith("{"):
        parsed = json.loads(stripped)
    else:
        padded = stripped + ("=" * (-len(stripped) % 4))
        parsed = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decoded X-USZ-Delegated-Payment payload must be a JSON object")
    assert_zero_pii_payload(parsed)
    return parsed


class USZDelegatedPointClient:
    """
    Zero-Custody / Zero-PII client that keeps an ephemeral session key strictly in client memory,
    binds a 1-time external wallet `SpendPermission` signature, and performs popup-free HTTP 402
    point payments with `X-USZ-Delegated-Payment`.
    """

    def __init__(
        self,
        *,
        payer_address: str,
        wallet_type: str,
        delegation_router_address: str,
        rpc_url: str = "http://127.0.0.1:8545",
        config: Optional[SpendPermissionConfig] = None,
        session_private_key: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.wallet_type = validate_external_wallet_type(wallet_type)
        assert_zero_pii_payload(metadata)

        self.payer_address = Web3.to_checksum_address(payer_address)
        self.delegation_router_address = Web3.to_checksum_address(delegation_router_address)
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = int(self.w3.eth.chain_id)
        self.delegation_router = self.w3.eth.contract(
            address=self.delegation_router_address,
            abi=load_abi("USZSpendDelegationRouter"),
        )
        token_addr = self.delegation_router.functions.uszToken().call()
        self.token_address = Web3.to_checksum_address(token_addr)
        self.token_contract = self.w3.eth.contract(
            address=self.token_address,
            abi=load_abi("USZToken"),
        )

        # Ephemeral client-memory session key (never sent to or stored by any server)
        if session_private_key is None:
            ephemeral_acct = Account.create()
            self._session_private_key = ephemeral_acct.key.hex()
            self.session_signer = Web3.to_checksum_address(ephemeral_acct.address)
        else:
            ephemeral_acct = Account.from_key(session_private_key)
            self._session_private_key = session_private_key
            self.session_signer = Web3.to_checksum_address(ephemeral_acct.address)

        onchain_master_nonce = int(
            self.delegation_router.functions.delegationMasterNonce(self.payer_address).call()
        )
        latest_block = self.w3.eth.get_block("latest")
        now_ts = int(latest_block["timestamp"])

        effective_cfg = config or SpendPermissionConfig(master_nonce=onchain_master_nonce)
        if effective_cfg.master_nonce == 0 and onchain_master_nonce > 0:
            effective_cfg.master_nonce = onchain_master_nonce

        self.config = effective_cfg
        self.permission = effective_cfg.to_permission_dict(
            payer=self.payer_address,
            session_signer=self.session_signer,
            now_ts=now_ts,
        )
        self.permission_hash_bytes = compute_permission_struct_hash(self.permission)
        self.permission_hash_hex = normalize_bytes32_hex(self.permission_hash_bytes)
        self.payer_signature: Optional[str] = None
        self._intent_nonce = 0

    def get_external_wallet_typed_data(self) -> dict[str, Any]:
        """Return the EIP-712 payload to pass once to the user's external wallet (`eth_signTypedData_v4`)."""
        return build_spend_permission_typed_data(
            chain_id=self.chain_id,
            verifying_contract=self.delegation_router_address,
            permission=self.permission,
        )

    def attach_payer_signature(self, payer_signature: str) -> None:
        """Bind the 1-time signature returned by the user's external wallet (`ECDSA` or `EIP-1271`)."""
        if not payer_signature or not isinstance(payer_signature, str):
            raise ValueError("Valid hex payer_signature is required")
        self.payer_signature = (
            payer_signature if payer_signature.startswith("0x") else f"0x{payer_signature}"
        )

    def build_charge_header(
        self,
        *,
        provider_address: str,
        amount_wei: int,
        service_ref: Union[bytes, str, None] = None,
        ttl_seconds: int = 300,
    ) -> str:
        """Silently sign a `DelegatedChargeIntent` with the local ephemeral session key (0 wallet popups)."""
        if not self.payer_signature:
            raise RuntimeError(
                "External wallet SpendPermission signature not attached yet; call attach_payer_signature() first."
            )

        self._intent_nonce += 1
        latest_block = self.w3.eth.get_block("latest")
        deadline = int(latest_block["timestamp"]) + int(ttl_seconds)

        if service_ref is None:
            ref_hex = normalize_bytes32_hex(
                Web3.keccak(text=f"usz-point-call:{self.permission_hash_hex}:{self._intent_nonce}")
            )
        else:
            ref_hex = normalize_bytes32_hex(service_ref)

        intent = {
            "permissionHash": self.permission_hash_hex,
            "provider": Web3.to_checksum_address(provider_address),
            "amountUSZ": int(amount_wei),
            "serviceRef": ref_hex,
            "intentNonce": int(self._intent_nonce),
            "deadline": deadline,
        }
        session_sig = sign_delegated_charge_intent(
            session_private_key=self._session_private_key,
            chain_id=self.chain_id,
            verifying_contract=self.delegation_router_address,
            intent=intent,
        )

        envelope = {
            "walletType": self.wallet_type,
            "delegationRouter": self.delegation_router_address,
            "permission": self.permission,
            "payerSignature": self.payer_signature,
            "intent": intent,
            "sessionSignature": session_sig,
        }
        return encode_delegated_payment_header(envelope)

    def get_point_summary(self) -> dict[str, Any]:
        """Query `getPointAccountSummaryForPermission` and format in web point notation (`49.95 P ($49.95)`)."""
        perm_tuple = (
            self.permission["payer"],
            self.permission["sessionSigner"],
            int(self.permission["maxPerTxUSZ"]),
            int(self.permission["dailyLimitUSZ"]),
            int(self.permission["validAfter"]),
            int(self.permission["validUntil"]),
            int(self.permission["salt"]),
            int(self.permission["masterNonce"]),
        )
        usz_bal, rem_daily, max_tx, valid_until, is_active = (
            self.delegation_router.functions.getPointAccountSummaryForPermission(perm_tuple).call()
        )
        return {
            "pointsDisplay": format_point_balance(int(usz_bal)),
            "remainingDailyDisplay": format_point_balance(int(rem_daily)),
            "maxPerTxDisplay": format_point_balance(int(max_tx)),
            "uszBalanceWei": int(usz_bal),
            "remainingDailyLimitWei": int(rem_daily),
            "maxPerTxWei": int(max_tx),
            "validUntil": int(valid_until),
            "isActive": bool(is_active),
            "walletType": self.wallet_type,
        }

    def post(
        self,
        url: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        client: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        """
        Execute a popup-free HTTP 402 request:
        1. Sends initial request (inspecting 402 negotiation headers if payment required).
        2. Signs `DelegatedChargeIntent` locally in memory and retries with `X-USZ-Delegated-Payment`.
        """
        assert_zero_pii_payload(json_body)
        req_headers = dict(headers or {})
        http = client or httpx.Client()
        close_after = client is None

        try:
            res = http.post(url, json=json_body, headers=req_headers)
            if res.status_code != 402:
                return res

            price_wei = int(res.headers.get("X-USZ-Price", "0"))
            provider_addr = res.headers.get("X-USZ-Provider")
            if not provider_addr:
                router_addr = res.headers.get("X-USZ-Router")
                agent_id_hex = res.headers.get("X-USZ-Agent-Id")
                if router_addr and agent_id_hex:
                    router = self.w3.eth.contract(
                        address=Web3.to_checksum_address(router_addr),
                        abi=load_abi("USZAgentRouter"),
                    )
                    agent_info = router.functions.agents(normalize_bytes32(agent_id_hex)).call()
                    provider_addr = agent_info[1]

            if not provider_addr or price_wei <= 0:
                raise RuntimeError("HTTP 402 response missing X-USZ-Provider or X-USZ-Price headers")

            delegated_hdr = self.build_charge_header(
                provider_address=provider_addr,
                amount_wei=price_wei,
            )
            paid_headers = dict(req_headers)
            paid_headers["X-USZ-Delegated-Payment"] = delegated_hdr
            return http.post(url, json=json_body, headers=paid_headers)
        finally:
            if close_after:
                http.close()
