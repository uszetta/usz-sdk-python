"""
Zero-Custody / Zero-PII External Credit Card Onramp Redirect Builder (`usz_sdk/card_onramp.py`)
Website: https://uszetta.com | Security Contact: admin@uszetta.com

Generates client-side redirect URLs and hashed `orderId` bindings for licensed external onramps
(`Coinbase Onramp`, `Stripe Crypto Onramp`, `MoonPay`, `Wert`) so credit card / KYC data never
passes through or touches any US Zetta or AI provider server.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_DOWN
import secrets
from typing import Any, Mapping, Optional, Union
from urllib.parse import urlencode

from web3 import Web3

from .crypto import normalize_bytes32_hex
from .point_delegation import (
    assert_zero_pii_payload,
    format_point_balance,
    validate_external_wallet_type,
)

SUPPORTED_ONRAMP_PROVIDERS: dict[str, str] = {
    "coinbase_onramp": "https://pay.coinbase.com/buy/select-asset",
    "stripe_crypto_onramp": "https://crypto.link.com",
    "moonpay": "https://buy.moonpay.com",
    "wert": "https://widget.wert.io/default/widget",
}

DECIMALS_6 = Decimal(10) ** 6


def build_external_onramp_redirect(
    *,
    user_external_wallet: str,
    wallet_type: str,
    amount_usd: Union[str, int, float, Decimal],
    onramp_provider: str = "coinbase_onramp",
    order_id: Optional[Union[str, bytes]] = None,
    target_provider: Optional[str] = None,
    service_ref: Optional[Union[str, bytes]] = None,
    extra_metadata: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build a Zero-PII external onramp checkout URL binding ONLY:
      - `user_external_wallet` (`0x...` checksum address)
      - `amount_usd` (`USDC 6 decimals` equivalent)
      - `order_id` (`bytes32` non-PII hash)
    """
    verified_wallet_type = validate_external_wallet_type(wallet_type)
    assert_zero_pii_payload(extra_metadata)

    provider_key = onramp_provider.strip().lower().replace("-", "_").replace(" ", "_")
    if provider_key not in SUPPORTED_ONRAMP_PROVIDERS:
        raise ValueError(
            f"Unsupported onramp_provider '{onramp_provider}'. "
            f"Supported: {tuple(SUPPORTED_ONRAMP_PROVIDERS.keys())}"
        )

    checksum_wallet = Web3.to_checksum_address(user_external_wallet)
    dec_usd = Decimal(str(amount_usd)).quantize(Decimal("0.01"), rounding=ROUND_DOWN)
    if dec_usd <= Decimal("0"):
        raise ValueError("amount_usd must be greater than 0")

    usdc_amount_6 = int((dec_usd * DECIMALS_6).to_integral_exact())

    if order_id is None:
        nonce_hex = secrets.token_hex(16)
        order_hash = Web3.keccak(
            text=f"usz-onramp:{provider_key}:{checksum_wallet}:{usdc_amount_6}:{nonce_hex}"
        )
        order_id_hex = normalize_bytes32_hex(order_hash)
    else:
        order_id_hex = normalize_bytes32_hex(order_id)

    flow_mode = "direct_pay" if target_provider else "point_topup"
    query_params: dict[str, str] = {
        "destinationWallet": checksum_wallet,
        "destinationNetwork": "arbitrum",
        "asset": "USDC",
        "presetFiatAmount": f"{dec_usd:.2f}",
        "fiatCurrency": "USD",
        "partnerOrderId": order_id_hex,
        "flow": flow_mode,
    }

    checksum_target: Optional[str] = None
    service_ref_hex: Optional[str] = None
    if target_provider is not None:
        checksum_target = Web3.to_checksum_address(target_provider)
        query_params["targetProvider"] = checksum_target
        service_ref_hex = (
            normalize_bytes32_hex(service_ref)
            if service_ref is not None
            else normalize_bytes32_hex(Web3.keccak(text=f"usz-direct-pay:{order_id_hex}"))
        )
        query_params["serviceRef"] = service_ref_hex

    base_url = SUPPORTED_ONRAMP_PROVIDERS[provider_key]
    redirect_url = f"{base_url}?{urlencode(query_params)}"

    return {
        "url": redirect_url,
        "onrampProvider": provider_key,
        "walletType": verified_wallet_type,
        "walletAddress": checksum_wallet,
        "orderId": order_id_hex,
        "flowMode": flow_mode,
        "amountUsd": f"{dec_usd:.2f}",
        "amountUsdc6": usdc_amount_6,
        "pointsPreview": format_point_balance(dec_usd),
        "targetProvider": checksum_target,
        "serviceRef": service_ref_hex,
        "zeroPiiVerified": True,
    }
