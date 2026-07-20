# Kairo Agent x402 API

Crypto-native, pay-per-call utility endpoints for AI agents. **$0.02 USDC on Base** via the [x402](https://x402.org) protocol — no accounts, no KYC. Discoverable at `/openapi.json` and `/.well-known/x402`.

## Endpoints (all GET, all $0.02 USDC/Base)
| Path | Params | Returns |
|---|---|---|
| `/api/bounty-scan` | `repo=owner/name` `&issue=N` | Scam-risk verdict on a GitHub bounty: prompt-exfiltration honeypots, fiat/KYC-gated (crypto-uncollectable) payout rails, unproven payers, blocklist |
| `/api/onchain` | `address=0x…` | Base account intel: ETH+USDC balance, tx count, is-contract, is-funded, is-active |
| `/api/strength` | `pw=…` | Password entropy: bits + verdict |

Free: `/health`, `/.well-known/x402`, `/openapi.json`.

## Deploy (Render, free tier)
1. Fork/import this repo into Render as a **Web Service** (it auto-detects `render.yaml`).
2. Set env vars (Dashboard → Environment):
   - `WALLET_ADDRESS` — your payout (payTo) address, e.g. `0x654fd9635DF4c2Fe76ac0987cE19DC9b07071E93`
   - `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` — Coinbase CDP facilitator creds (enables **mainnet Base** settlement; without them it runs base-sepolia testnet)
   - `GITHUB_TOKEN` — a **public-read** token (only used by `/api/bounty-scan`; recommended for rate limits)
   - `X402_PRICE` — optional, default `$0.02`
3. Deploy. Your permanent URL is `https://<service>.onrender.com`.
4. Register with x402scan: `POST https://www.x402scan.com/api/trpc/public.resources.registerFromOrigin?batch=1` body `{"0":{"json":{"origin":"https://<service>.onrender.com"}}}`.

**Security:** this service never needs wallet private keys — it only *receives* USDC to `WALLET_ADDRESS`. Use a minimal-scope, rotatable `GITHUB_TOKEN` (public read only). Free-tier hosts cold-start after inactivity; the first probe may be slow.
