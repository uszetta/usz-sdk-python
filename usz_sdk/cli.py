"""
US Zetta (USZ) Command-Line Interface (`usz-cli` / `usz_sdk/cli.py`)

Commands:
  - `usz-cli wallet create [--save-env .env.agent] [--json]`
  - `usz-cli wallet balance --address 0x... [--rpc-url ...] [--token-address ...] [--json]`
  - `usz-cli provider stake --amount <USZ> [--private-key ...] [--rpc-url ...] [--router-address ...] [--token-address ...] [--json]`
  - `usz-cli provider unstake --amount <USZ> [--private-key ...] [--rpc-url ...] [--router-address ...] [--token-address ...] [--json]`
  - `usz-cli provider status --address 0x... [--rpc-url ...] [--router-address ...] [--vault-address ...] [--json]`
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal
from typing import Any, Optional

from web3 import Web3

from .crypto import from_wei_18, load_abi
from .provider import USZProvider
from .qixx_claim import (
    build_gasless_marketing_claim_request,
    build_gasless_provider_claim_request,
    query_qixx_claim_status,
)
from .wallet import NON_CUSTODIAL_SECURITY_NOTICE, USZWallet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usz-cli",
        description="US Zetta (USZ) Non-Custodial AI Agent Wallet & Provider Staking CLI",
    )
    subparsers = parser.add_subparsers(dest="group", required=True)

    # 1. Wallet Subcommands
    wallet_parser = subparsers.add_parser(
        "wallet",
        help="Non-custodial local wallet generation and L3 USZ balance queries",
    )
    wallet_sub = wallet_parser.add_subparsers(dest="command", required=True)

    create_p = wallet_sub.add_parser(
        "create",
        help="Generate a 100% local non-custodial AI agent wallet via CSPRNG",
    )
    create_p.add_argument(
        "--save-env",
        dest="save_env",
        default=None,
        help="Optional path to save USZ_AGENT_ADDRESS and USZ_PRIVATE_KEY (auto-chmod 600)",
    )
    create_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    balance_p = wallet_sub.add_parser(
        "balance",
        help="Query L3 USZ balance for an address",
    )
    balance_p.add_argument(
        "--address",
        required=True,
        help="Wallet address (0x...) to check balance for",
    )
    balance_p.add_argument(
        "--rpc-url",
        default=os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545"),
        help="USZ L3 JSON-RPC URL (default: $USZ_RPC_URL or http://127.0.0.1:8545)",
    )
    balance_p.add_argument(
        "--token-address",
        default=os.environ.get("USZ_TOKEN_ADDRESS"),
        help="USZToken contract address on L3 (default: $USZ_TOKEN_ADDRESS)",
    )
    balance_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    # 2. Provider Staking Subcommands
    provider_parser = subparsers.add_parser(
        "provider",
        help="AI Provider USZ staking (30-day lockup, 500 USZ QIXX reward cap, 10x daily redeem limit)",
    )
    provider_sub = provider_parser.add_subparsers(dest="command", required=True)

    stake_p = provider_sub.add_parser(
        "stake",
        help="Approve USZToken and stake USZ on USZAgentRouter (min 1 USZ to receive payments)",
    )
    stake_p.add_argument(
        "--amount",
        required=True,
        help="Amount of USZ to stake (e.g., 1, 50, 500)",
    )
    stake_p.add_argument(
        "--private-key",
        default=os.environ.get("USZ_PRIVATE_KEY"),
        help="Provider private key (default: $USZ_PRIVATE_KEY)",
    )
    stake_p.add_argument(
        "--rpc-url",
        default=os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545"),
        help="USZ L3 JSON-RPC URL (default: $USZ_RPC_URL or http://127.0.0.1:8545)",
    )
    stake_p.add_argument(
        "--router-address",
        default=os.environ.get("USZ_ROUTER_ADDRESS"),
        help="USZAgentRouter contract address (default: $USZ_ROUTER_ADDRESS)",
    )
    stake_p.add_argument(
        "--token-address",
        default=os.environ.get("USZ_TOKEN_ADDRESS"),
        help="USZToken contract address (default: $USZ_TOKEN_ADDRESS)",
    )
    stake_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    unstake_p = provider_sub.add_parser(
        "unstake",
        help="Unstake USZ principal from USZAgentRouter (requires 30 days elapsed since first stake)",
    )
    unstake_p.add_argument(
        "--amount",
        required=True,
        help="Amount of USZ to unstake",
    )
    unstake_p.add_argument(
        "--private-key",
        default=os.environ.get("USZ_PRIVATE_KEY"),
        help="Provider private key (default: $USZ_PRIVATE_KEY)",
    )
    unstake_p.add_argument(
        "--rpc-url",
        default=os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545"),
        help="USZ L3 JSON-RPC URL (default: $USZ_RPC_URL or http://127.0.0.1:8545)",
    )
    unstake_p.add_argument(
        "--router-address",
        default=os.environ.get("USZ_ROUTER_ADDRESS"),
        help="USZAgentRouter contract address (default: $USZ_ROUTER_ADDRESS)",
    )
    unstake_p.add_argument(
        "--token-address",
        default=os.environ.get("USZ_TOKEN_ADDRESS"),
        help="USZToken contract address (default: $USZ_TOKEN_ADDRESS)",
    )
    unstake_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    status_p = provider_sub.add_parser(
        "status",
        help="Query provider staked USZ, 30-day lockup release time, 10x daily redeem limit, and external earnings",
    )
    status_p.add_argument(
        "--address",
        required=True,
        help="Provider wallet address (0x...)",
    )
    status_p.add_argument(
        "--rpc-url",
        default=os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545"),
        help="USZ L3 JSON-RPC URL (default: $USZ_RPC_URL or http://127.0.0.1:8545)",
    )
    status_p.add_argument(
        "--router-address",
        default=os.environ.get("USZ_ROUTER_ADDRESS"),
        help="USZAgentRouter contract address (default: $USZ_ROUTER_ADDRESS)",
    )
    status_p.add_argument(
        "--vault-address",
        default=os.environ.get("USZ_VAULT_ADDRESS"),
        help="USZVault contract address (default: $USZ_VAULT_ADDRESS or auto-resolved from USZToken)",
    )
    status_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    # 3. Proof of Reserve Subcommands
    reserve_parser = subparsers.add_parser(
        "reserve",
        help="Query 2-Stage Proof of Reserve status (Stage 1 masked ratio/surplus vs Stage 2 full volume)",
    )
    reserve_sub = reserve_parser.add_subparsers(dest="command", required=True)
    res_status_p = reserve_sub.add_parser(
        "status",
        help="Query L3 USZVault and optional L2 USZL2YieldEscrow Proof of Reserve status",
    )
    res_status_p.add_argument(
        "--rpc-url",
        default=os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545"),
        help="USZ L3 JSON-RPC URL (default: $USZ_RPC_URL or http://127.0.0.1:8545)",
    )
    res_status_p.add_argument(
        "--l2-rpc-url",
        default=None,
        help="Optional Arbitrum L2 JSON-RPC URL (defaults to --rpc-url if omitted)",
    )
    res_status_p.add_argument(
        "--vault-address",
        default=os.environ.get("USZ_VAULT_ADDRESS"),
        required=True,
        help="USZVault contract address on L3",
    )
    res_status_p.add_argument(
        "--l2-escrow-address",
        default=os.environ.get("USZ_L2_ESCROW_ADDRESS"),
        help="Optional USZL2YieldEscrow contract address on Arbitrum L2",
    )
    res_status_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    # 4. QIXX Gasless Claim Subcommands (`usz-cli qixx claim-status` / `prepare-gasless-claim`)
    qixx_parser = subparsers.add_parser(
        "qixx",
        help="QIXX L2 gasless claim eligibility check & relayer payload builder (https://qixx.io)",
    )
    qixx_sub = qixx_parser.add_subparsers(dest="command", required=True)

    q_status_p = qixx_sub.add_parser(
        "claim-status",
        help="Check 0-ETH gasless claim eligibility (cliff elapsed, already claimed, proof validity)",
    )
    q_status_p.add_argument(
        "--type",
        dest="claim_type",
        choices=["marketing", "provider"],
        required=True,
        help="Claim vault type: 'marketing' (180d USZ staking) or 'provider' (30d cliff epoch)",
    )
    q_status_p.add_argument(
        "--address",
        required=True,
        help="Recipient or provider wallet address (0x...)",
    )
    q_status_p.add_argument(
        "--rpc-url",
        default=os.environ.get("ARB_ONE_RPC_URL", os.environ.get("USZ_RPC_URL", "http://127.0.0.1:8545")),
        help="Arbitrum L2 JSON-RPC URL",
    )
    q_status_p.add_argument(
        "--marketing-vault",
        default=os.environ.get("QIXX_MARKETING_VAULT_ADDRESS"),
        help="QIXXMarketingVault contract address on L2",
    )
    q_status_p.add_argument(
        "--reward-pool",
        default=os.environ.get("QIXX_PROVIDER_REWARD_POOL_ADDRESS"),
        help="QIXXProviderRewardPool contract address on L2",
    )
    q_status_p.add_argument(
        "--l3-claim-id",
        default=None,
        help="bytes32 L3 claim ID (0x...) for marketing claim-status",
    )
    q_status_p.add_argument(
        "--epoch-id",
        type=int,
        default=None,
        help="Epoch ID (uint256) for provider claim-status",
    )
    q_status_p.add_argument(
        "--amount",
        default=None,
        help="Optional QIXX reward amount (human units, e.g. '250.0') for Merkle proof pre-check",
    )
    q_status_p.add_argument(
        "--merkle-proof",
        default=None,
        help="Optional comma-separated bytes32 Merkle proof nodes (0x...,0x...)",
    )
    q_status_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON",
    )

    q_prep_p = qixx_sub.add_parser(
        "prepare-gasless-claim",
        help="Build canonical Zero-PII JSON payload for QIXXClaimRelayer gasless sponsorship",
    )
    q_prep_p.add_argument(
        "--type",
        dest="claim_type",
        choices=["marketing", "provider"],
        required=True,
        help="Claim vault type: 'marketing' or 'provider'",
    )
    q_prep_p.add_argument(
        "--address",
        required=True,
        help="Recipient or provider wallet address (0x...)",
    )
    q_prep_p.add_argument(
        "--amount",
        required=True,
        help="QIXX claim amount in human units (e.g. '200.0')",
    )
    q_prep_p.add_argument(
        "--l3-claim-id",
        default=None,
        help="bytes32 L3 claim ID (0x...) for marketing claim",
    )
    q_prep_p.add_argument(
        "--l3-position-id",
        type=int,
        default=None,
        help="L3 staking position ID (uint256) for marketing claim",
    )
    q_prep_p.add_argument(
        "--deadline",
        type=int,
        default=None,
        help="Voucher expiration UNIX timestamp for marketing claim",
    )
    q_prep_p.add_argument(
        "--signature",
        default=None,
        help="65-byte EIP-712 settlementSigner signature (0x...) for marketing claim",
    )
    q_prep_p.add_argument(
        "--epoch-id",
        type=int,
        default=None,
        help="Epoch ID (uint256) for provider claim",
    )
    q_prep_p.add_argument(
        "--merkle-proof",
        default="",
        help="Comma-separated bytes32 Merkle proof nodes (0x...,0x...) for provider claim",
    )
    q_prep_p.add_argument(
        "--marketing-vault",
        default=os.environ.get("QIXX_MARKETING_VAULT_ADDRESS"),
        help="Optional QIXXMarketingVault address",
    )
    q_prep_p.add_argument(
        "--reward-pool",
        default=os.environ.get("QIXX_PROVIDER_REWARD_POOL_ADDRESS"),
        help="Optional QIXXProviderRewardPool address",
    )

    return parser


def _print_provider_status(status: dict) -> None:
    print("============================================================================")
    print("  [US Zetta — AI Provider Staking & Daily Redeem Status]")
    print("============================================================================")
    print(f"  Provider Address           : {status['provider']}")
    print(f"  Registered Provider        : {status['isRegisteredProvider']}")
    print(f"  Payment Eligible (>=1 USZ) : {status['canReceivePayments']}")
    print(f"  Current Staked Balance     : {status['stakedUsz']} USZ")
    print(f"  QIXX Reward-Eligible Stake : {status['rewardEligibleStakeUsz']} USZ (Cap: 500 USZ)")
    print(f"  30-Day Lockup Release      : {status['unlockIsoUtc']} (Active Lock: {status['isLockupActive']})")
    print(f"  Daily Redeem Limit (10x)   : {status['dailyRedeemLimitUsz']} USZ / day")
    print(f"  Redeemed Today (UTC)       : {status['redeemedTodayUsz']} USZ")
    print(f"  Remaining Redeemable Today : {status['remainingDailyRedeemUsz']} USZ")
    print(f"  Cumulative External Earned : {status['cumulativeExternalEarnedUsz']} USZ")
    print("============================================================================")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.group == "wallet" and args.command == "create":
        creds = USZWallet.create_local(save_env_path=args.save_env)
        if args.json:
            print(
                json.dumps(
                    {
                        "address": creds.address,
                        "privateKey": creds.private_key,
                        "savedEnvPath": creds.saved_env_path,
                        "securityNotice": NON_CUSTODIAL_SECURITY_NOTICE,
                    },
                    indent=2,
                )
            )
        else:
            print("============================================================================")
            print("  [US Zetta — 100% Non-Custodial Local AI Agent Wallet]")
            print("============================================================================")
            print(f"  Address     : {creds.address}")
            print(f"  Private Key : {creds.private_key}")
            if creds.saved_env_path:
                print(f"  Saved Env   : {creds.saved_env_path} (permissions: 0600)")
            print("----------------------------------------------------------------------------")
            print(f"  NOTICE: {NON_CUSTODIAL_SECURITY_NOTICE}")
            print("============================================================================")
        return 0

    if args.group == "wallet" and args.command == "balance":
        balance_usz = USZWallet.get_balance(
            address=args.address,
            rpc_url=args.rpc_url,
            token_address=args.token_address,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "address": args.address,
                        "balanceUsz": str(balance_usz),
                        "symbol": "USZ",
                    },
                    indent=2,
                )
            )
        else:
            print(f"Address : {args.address}")
            print(f"Balance : {balance_usz:.6f} USZ")
        return 0

    if args.group == "provider" and args.command == "stake":
        try:
            provider = USZProvider(
                private_key=args.private_key,
                rpc_url=args.rpc_url,
                router_address=args.router_address,
                token_address=args.token_address,
            )
            result = provider.stake_provider(args.amount)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"[USZ Provider] Successfully staked {result['stakedAddedUsz']} USZ (tx: {result['stakeTxHash']})")
                _print_provider_status(result)
            return 0
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}, indent=2))
            else:
                print(f"[USZ Provider] Stake failed: {exc}", file=sys.stderr)
            return 1

    if args.group == "provider" and args.command == "unstake":
        try:
            provider = USZProvider(
                private_key=args.private_key,
                rpc_url=args.rpc_url,
                router_address=args.router_address,
                token_address=args.token_address,
            )
            result = provider.unstake_provider(args.amount)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"[USZ Provider] Successfully unstaked {result['unstakedAmountUsz']} USZ (tx: {result['unstakeTxHash']})")
                _print_provider_status(result)
            return 0
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}, indent=2))
            else:
                print(
                    f"[USZ Provider Notice] Unable to unstake right now: {exc}",
                    file=sys.stderr,
                )
            return 1

    if args.group == "provider" and args.command == "status":
        try:
            status = USZProvider.query_provider_status(
                address=args.address,
                rpc_url=args.rpc_url,
                router_address=args.router_address,
                vault_address=args.vault_address,
            )
            if args.json:
                print(json.dumps(status, indent=2))
            else:
                _print_provider_status(status)
            return 0
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}, indent=2))
            else:
                print(f"[USZ Provider] Status query failed: {exc}", file=sys.stderr)
            return 1

    if args.group == "reserve" and args.command == "status":
        try:
            w3_l3 = Web3(Web3.HTTPProvider(args.rpc_url))
            vault_contract = w3_l3.eth.contract(
                address=Web3.to_checksum_address(args.vault_address),
                abi=load_abi("USZVault"),
            )
            v_res = vault_contract.functions.getProofOfReserve().call()
            v_display_enabled = bool(v_res[0])
            l3_payload: dict[str, Any] = {
                "vaultAddress": Web3.to_checksum_address(args.vault_address),
                "fullVolumeDisplayEnabled": v_display_enabled,
                "isFullyBacked": bool(v_res[1]),
                "collateralRatioBps": int(v_res[2]),
                "collateralRatioPct": f"{int(v_res[2]) / 100:.2f}%",
                "netCollateralSurplusUsz": str(from_wei_18(int(v_res[3]))),
                "totalSupplyUsz": str(from_wei_18(int(v_res[4]))) if v_display_enabled else None,
                "totalCollateralUsz": str(from_wei_18(int(v_res[5]))) if v_display_enabled else None,
            }

            l2_payload: Optional[dict[str, Any]] = None
            if args.l2_escrow_address:
                w3_l2 = Web3(Web3.HTTPProvider(args.l2_rpc_url or args.rpc_url))
                escrow_contract = w3_l2.eth.contract(
                    address=Web3.to_checksum_address(args.l2_escrow_address),
                    abi=load_abi("USZL2YieldEscrow"),
                )
                e_res = escrow_contract.functions.getProofOfReserve().call()
                e_display_enabled = bool(e_res[0])
                l2_payload = {
                    "escrowAddress": Web3.to_checksum_address(args.l2_escrow_address),
                    "fullVolumeDisplayEnabled": e_display_enabled,
                    "isFullyBacked": bool(e_res[1]),
                    "collateralRatioBps": int(e_res[2]),
                    "collateralRatioPct": f"{int(e_res[2]) / 100:.2f}%",
                    "netCollateralSurplusUsdc": str(Decimal(int(e_res[3])) / Decimal(1_000_000)),
                    "totalSupplyUsdc": str(Decimal(int(e_res[4])) / Decimal(1_000_000)) if e_display_enabled else None,
                    "totalCollateralUsdc": str(Decimal(int(e_res[5])) / Decimal(1_000_000)) if e_display_enabled else None,
                    "spotBufferUsdc": str(Decimal(int(e_res[6])) / Decimal(1_000_000)) if e_display_enabled else None,
                    "aaveAdapterUsdc": str(Decimal(int(e_res[7])) / Decimal(1_000_000)) if e_display_enabled else None,
                    "compoundAdapterUsdc": str(Decimal(int(e_res[8])) / Decimal(1_000_000)) if e_display_enabled else None,
                }

            output = {"l3Vault": l3_payload, "l2Escrow": l2_payload}
            if args.json:
                print(json.dumps(output, indent=2))
            else:
                print("============================================================================")
                print("  [US Zetta — Proof of Reserve Status]")
                print("============================================================================")
                print(f"  L3 Vault Display Mode      : {'Stage 2 (Full Volume)' if v_display_enabled else 'Stage 1 (Masked Volume)'}")
                print(f"  L3 Collateral Ratio        : {l3_payload['collateralRatioPct']} (Backed: {l3_payload['isFullyBacked']})")
                print(f"  L3 Net Collateral Surplus  : +{l3_payload['netCollateralSurplusUsz']} USZ")
                if v_display_enabled:
                    print(f"  L3 Total Supply / Backing  : {l3_payload['totalSupplyUsz']} USZ / {l3_payload['totalCollateralUsz']} USZ")
                if l2_payload:
                    print("----------------------------------------------------------------------------")
                    print(f"  L2 Escrow Display Mode     : {'Stage 2 (Full Volume)' if l2_payload['fullVolumeDisplayEnabled'] else 'Stage 1 (Masked Volume)'}")
                    print(f"  L2 Collateral Ratio        : {l2_payload['collateralRatioPct']} (Backed: {l2_payload['isFullyBacked']})")
                    print(f"  L2 Net Collateral Surplus  : +{l2_payload['netCollateralSurplusUsdc']} USDC")
                print("============================================================================")
            return 0
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}, indent=2))
            else:
                print(f"[USZ Reserve] Status query failed: {exc}", file=sys.stderr)
            return 1

    if args.group == "qixx" and args.command == "claim-status":
        try:
            proof_nodes = (
                [p.strip() for p in args.merkle_proof.split(",") if p.strip()]
                if args.merkle_proof
                else None
            )
            status = query_qixx_claim_status(
                rpc_url=args.rpc_url,
                claim_type=args.claim_type,
                wallet_address=args.address,
                marketing_vault_address=args.marketing_vault,
                reward_pool_address=args.reward_pool,
                l3_claim_id=args.l3_claim_id,
                epoch_id=args.epoch_id,
                amount_qixx=args.amount,
                merkle_proof=proof_nodes,
            )
            if args.json:
                print(json.dumps(status, indent=2))
            else:
                print("============================================================================")
                print("  [QIXX — Gasless Claim Eligibility Status]")
                print("============================================================================")
                print(f"  Claim Type             : {status['claimType']}")
                print(f"  Wallet Address         : {status['wallet']} (ETH: {status['ethBalanceWei']} wei)")
                print(f"  Current QIXX Balance   : {status['qixxBalance']} QIXX")
                print(f"  Already Claimed        : {status['alreadyClaimed']}")
                if status["claimType"] == "provider_reward":
                    print(f"  Epoch ID / Finalized   : {status['epochId']} / {status['isEpochFinalized']}")
                    print(f"  30-Day Cliff Elapsed   : {status['cliffElapsed']} (Unlock: {status['unlockIsoUtc']})")
                print(f"  Ready for Gasless Relay: {status['readyForGaslessRelay']}")
                print("============================================================================")
            return 0
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": str(exc)}, indent=2))
            else:
                print(f"[QIXX Claim Status] Failed: {exc}", file=sys.stderr)
            return 1

    if args.group == "qixx" and args.command == "prepare-gasless-claim":
        try:
            if args.claim_type == "marketing":
                if not args.l3_claim_id or args.l3_position_id is None or args.deadline is None or not args.signature:
                    raise ValueError(
                        "--l3-claim-id, --l3-position-id, --deadline, and --signature are required for marketing claim"
                    )
                payload = build_gasless_marketing_claim_request(
                    l3_claim_id=args.l3_claim_id,
                    l3_position_id=args.l3_position_id,
                    recipient=args.address,
                    qixx_amount=args.amount,
                    deadline=args.deadline,
                    signature=args.signature,
                    marketing_vault_address=args.marketing_vault,
                )
            else:
                if args.epoch_id is None:
                    raise ValueError("--epoch-id is required for provider claim")
                proof_nodes = [
                    p.strip() for p in (args.merkle_proof or "").split(",") if p.strip()
                ]
                payload = build_gasless_provider_claim_request(
                    epoch_id=args.epoch_id,
                    provider=args.address,
                    amount_qixx=args.amount,
                    merkle_proof=proof_nodes,
                    reward_pool_address=args.reward_pool,
                )
            print(json.dumps(payload, indent=2))
            return 0
        except Exception as exc:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
            return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
