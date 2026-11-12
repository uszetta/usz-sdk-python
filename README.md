# US Zetta Python SDK (`usz-sdk` v0.0.5)

Official open-source Python SDK for **US Zetta** (`USZ`, Chain ID: `777777`, Zero-Gas 100% 1:1 USDC-Backed Stablecoin, `https://uszetta.com`), enabling autonomous AI agents, Zero-Custody / Zero-PII web point delegation (`$10 / $100 / 30d`), non-custodial BIN sponsor Visa/Mastercard merchant offramp (`$500 / $2,000 / 30d`), and `0 ETH` gasless `QIXX` reward claim builders (`https://qixx.io`).

---

## Installation

```bash
pip install usz-sdk
# or for local development:
pip install -e .
```

---

## Quickstart

### 1. Generate a 100% Non-Custodial Local Agent Wallet & Manage Provider Staking (`usz-cli`)
```bash
# Non-custodial local wallet generation & balance query
usz-cli wallet create --save-env .env.agent
usz-cli wallet balance --address 0xYourAgentAddress

# AI Provider staking (min 1 USZ to receive payments, 30-day initial lockup, 10x daily redeem limit)
usz-cli provider stake --amount 50
usz-cli provider status --address 0xYourProviderAddress
usz-cli provider unstake --amount 10
```

### 2. AI Provider (5 Lines)
```python
from fastapi import FastAPI
from usz_sdk import USZProvider

app = FastAPI()
provider = USZProvider(private_key="0x...", rpc_url="http://127.0.0.1:8545", router_address="0x...", token_address="0x...")
agent_id = provider.register_agent("https://my-agent.uszetta.com/v1/infer", price_per_call="0.0005")

@app.post("/v1/infer")
@provider.charge_usz(price_usz="0.0005", mode="streaming", success_only=True)
async def infer(payload: dict):
    return {"answer": f"Processed: {payload['prompt']}"}
```

### 3. AI Buyer with Spend Guardrails (5 Lines)
```python
from usz_sdk import USZAgentClient

buyer = USZAgentClient(
    private_key="0x...",
    rpc_url="http://127.0.0.1:8545",
    router_address="0x...",
    token_address="0x...",
    default_channel_deposit="10",
    max_per_call_usz="1.00",
    daily_spend_limit_usz="50.00",
)
response = buyer.post("http://127.0.0.1:8000/v1/infer", json={"prompt": "Analyze market liquidity"})
print(response.json())
```

---

## Key Features
- **100% 1:1 USDC Collateralized & 0% Protocol Fee**: Every `USZ` token is 100% backed by real USDC, and 100% of every payment settles directly and instantly (`PAID_INSTANT`) to the AI provider wallet.
- **100% Non-Custodial Local Wallet (`usz-cli wallet create`)**: Generates AI agent keys locally via CSPRNG (`eth_account.Account.create()`) with `chmod 600` file permissions and zero external network calls.
- **AI Spend Guardrails (`max_per_call_usz`, `daily_spend_limit_usz`)**: Protects developers against runaway AI spending by enforcing per-call and rolling 24-hour spend caps before any signature or transaction is created.
- **HTTP 402 Automatic Negotiation (`X-USZ-*`)**: Automatically detects `402 Payment Required`, opens an on-chain state channel (`openChannel`) once, and streams EIP-712 signed vouchers (`name="US Zetta"`) on every subsequent HTTP call with zero on-chain latency.
- **Atomic Rollback (`success_only=True`)**: If the AI inference handler raises an exception, the voucher state is rolled back automatically so the buyer is never charged for failed calls.
