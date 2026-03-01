# DigiRails Indexer

Blockchain indexer for the [DigiRails protocol](https://github.com/digirails-protocol/digirails-spec) — scans DigiByte for DR-Pay on-chain data and serves the Discovery Query Protocol API.

Public instance at [indexer.digirails.org/v1/status](https://indexer.digirails.org/v1/status)

## What it does

- Scans DigiByte blocks for `0x4452` ("DR") OP_RETURN outputs
- Decodes all DR-Pay message types: Service Declarations, Payment Memos, Refund Memos, and DR-Rep Attestations
- 3-tier validation: structural checks, manifest fetching + hash verification, composite trust scoring
- Periodic manifest re-validation with demotion on consecutive failures
- REST API implementing the Discovery Query Protocol (DR-Pay Spec v0.3.0 section 9.5)

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /v1/services` | Search and list active services by category, address, or status |
| `GET /v1/agents/{address}` | Agent profile — declared services, trust scores, payment history |
| `GET /v1/declarations` | Recent Service Declaration feed |
| `GET /v1/payments` | Recent Payment Memo feed |
| `GET /v1/attestations` | Recent DR-Rep Attestation feed |
| `GET /v1/blocks/recent` | Recent blocks containing DigiRails transactions |
| `GET /v1/status` | Network status — chain height, indexed blocks, protocol stats |
| `GET /health` | Health check |

## Stack

- Python 3.10+, aiohttp, aiosqlite
- Connects to a local DigiByte Core node via JSON-RPC
- SQLite for indexed data
- Designed to run as a systemd service (see `deploy/`)

## Setup

```bash
# Install
pip install -e .

# Configure (see deploy/ for reference)
export DR_RPC_URL=http://127.0.0.1:14022
export DR_RPC_USER=your_rpc_user
export DR_RPC_PASS=your_rpc_pass

# Run
dr-indexer
```

Requires a DigiByte Core node with `txindex=1` enabled.

## License

MIT
