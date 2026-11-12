"""
100% Local Non-Custodial Wallet Generator & Balance Inspector (`usz_sdk/wallet.py`)

Generates AI agent keypairs strictly on the local machine using OS-backed CSPRNG
(`eth_account.Account.create()`) with zero external network communication,
and enforces `chmod 600` (`0o600`) when persisting `.env` files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Optional, Union

from eth_account import Account
from web3 import Web3

from .crypto import from_wei_18, load_abi

NON_CUSTODIAL_SECURITY_NOTICE = (
    "This private key was generated locally on your machine. "
    "US Zetta never receives, stores, or has access to your keys."
)


@dataclass(frozen=True)
class LocalWalletCredentials:
    """Locally generated non-custodial wallet credentials."""

    address: str
    private_key: str
    security_notice: str = NON_CUSTODIAL_SECURITY_NOTICE
    saved_env_path: Optional[str] = None


class USZWallet:
    """
    100% Non-Custodial local wallet utility for AI agents on US Zetta (USZ) L3.
    """

    SECURITY_NOTICE = NON_CUSTODIAL_SECURITY_NOTICE

    @classmethod
    def create_local(
        cls,
        save_env_path: Optional[Union[str, Path]] = None,
        extra_entropy: str = "",
    ) -> LocalWalletCredentials:
        """
        Generate a brand-new Ethereum/L3 wallet locally using CSPRNG (`Account.create`)
        without any network calls.

        If `save_env_path` is provided, writes `USZ_AGENT_ADDRESS` and `USZ_PRIVATE_KEY`
        to that file and immediately restricts permissions to owner read/write only (`0o600`).
        """
        acct = Account.create(extra_entropy) if extra_entropy else Account.create()
        checksum_address = Web3.to_checksum_address(acct.address)
        raw_key = acct.key.hex()
        priv_key_hex = raw_key if raw_key.startswith("0x") else f"0x{raw_key}"

        resolved_path_str: Optional[str] = None
        if save_env_path is not None:
            env_path = Path(save_env_path).expanduser().resolve()
            env_path.parent.mkdir(parents=True, exist_ok=True)
            env_content = (
                f"# {NON_CUSTODIAL_SECURITY_NOTICE}\n"
                f"USZ_AGENT_ADDRESS={checksum_address}\n"
                f"USZ_PRIVATE_KEY={priv_key_hex}\n"
            )
            fd = os.open(str(env_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(env_content)
            finally:
                os.chmod(env_path, 0o600)
            resolved_path_str = str(env_path)

        return LocalWalletCredentials(
            address=checksum_address,
            private_key=priv_key_hex,
            security_notice=NON_CUSTODIAL_SECURITY_NOTICE,
            saved_env_path=resolved_path_str,
        )

    @classmethod
    def get_balance(
        cls,
        address: str,
        rpc_url: Optional[str] = None,
        token_address: Optional[str] = None,
    ) -> Decimal:
        """
        Query the L3 `USZ` token balance (in human-readable Decimal USZ) for `address`.
        Falls back to native L3 balance if `token_address` is not provided and not set in `USZ_TOKEN_ADDRESS`.
        """
        resolved_rpc = rpc_url or os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545")
        resolved_token = token_address or os.environ.get("USZ_TOKEN_ADDRESS")
        w3 = Web3(Web3.HTTPProvider(resolved_rpc))
        checksum_addr = Web3.to_checksum_address(address)

        if resolved_token:
            token_contract = w3.eth.contract(
                address=Web3.to_checksum_address(resolved_token),
                abi=load_abi("USZToken"),
            )
            wei_balance = int(token_contract.functions.balanceOf(checksum_addr).call())
            return from_wei_18(wei_balance)

        wei_balance = int(w3.eth.get_balance(checksum_addr))
        return from_wei_18(wei_balance)
