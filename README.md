# Agent Canary

**Tripwire detection for autonomous AI agents.**

Plant honeypots in files, MCP tools, and API routes. When an agent crosses the line, Agent Canary records a sealed forensic event, optional Nostr attestation, and shows it in a local operator dashboard.

```bash
pip install "git+https://github.com/SamsonCyber/agent-canary.git#egg=agent-canary[all]"
agent-canary init
agent-canary plant file traps/.env.prod --template aws_creds
agent-canary nostr init
agent-canary dash
# open http://127.0.0.1:8765/
```

---

## Why this exists

Agents read your tree, call tools, and probe APIs without the manners of a human attacker. Classic canaries watch networks and credentials for people. Agent Canary watches **agent behavior inside your project**: scope creep, tool abuse, and quiet exfil attempts.

You get three layers:

| Layer | What you get |
|-------|----------------|
| **Tripwires** | File honeypots, MCP decoy tools, HTTP decoy routes |
| **Forensics** | Hash-linked chain, optional BIP-340 signatures, exportable bundle |
| **Operator UI** | Local dashboard for canaries, triggers, and the forensic chain |

---

## Operator dashboard

Read-only web UI bound to one project root. Plant and remove stay on the CLI.

```bash
agent-canary dash --host 127.0.0.1 --port 8765 --root .
```

**What you see**

- Summary counts from live registry data (canaries, triggers, sealed links, chain tip)
- Forensic chain timeline (oldest → newest) with file names, tools, and routes
- Planted canaries and trigger history with seal status
- JSON under `/api/*` for automation

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Operator UI |
| `GET /api/dashboard` | Full payload (summary + canaries + triggers + chain) |
| `GET /api/chain` | Forensic chain only |
| `GET /api/canaries` | Planted canaries |
| `GET /api/triggers` | Trigger history |
| `GET /api/summary` | Counts and tip |
| `GET /api/health` | Liveness |

Light mode follows system preference:

---

## Crypto-verified forensics + Nostr

Every trigger is sealed before it hits SQLite:

1. **content_hash**: SHA-256 of the canonical event payload  
2. **prev_hash**: previous link (or genesis zeros)  
3. **seq**: monotonic index  
4. **signature**: BIP-340 Schnorr when an nsec is present  

That is a local append-only chain. Edit an old row and verification fails.

### Nostr (optional extra)

With `[nostr]` installed:

- Sign seals under your **npub**
- Publish immutable kind **`31240`** events to relays
- Re-publish or verify from CLI

Agents do **not** need Nostr. Only your canary host signs and publishes. The agent only trips a file, tool, or API lure.

```bash
pip install "git+https://github.com/SamsonCyber/agent-canary.git#egg=agent-canary[nostr]"

agent-canary init
agent-canary nostr init
agent-canary alert add nostr wss://relay.damus.io
agent-canary alert add nostr wss://nos.lol

# after trips land
agent-canary forensic verify
agent-canary forensic verify --require-signature
agent-canary forensic export --out canary-forensics.json
agent-canary nostr status
agent-canary nostr publish --last
```

Config (`.agent-canary/config.yaml`):

```yaml
forensics:
  seal: true
  require_signature: false
alerts:
  nostr:
    relays:
      - wss://relay.damus.io
    auto_publish: true
    kind: 31240
```

Private key: `.agent-canary/nostr/nsec` (never commit). Rotate with `agent-canary nostr init --force`.

---

## Install

Source of truth is GitHub (not PyPI):

```bash
# core
pip install "git+https://github.com/SamsonCyber/agent-canary.git"

# MCP tripwire server
pip install "git+https://github.com/SamsonCyber/agent-canary.git#egg=agent-canary[mcp]"

# Nostr crypto + relay client
pip install "git+https://github.com/SamsonCyber/agent-canary.git#egg=agent-canary[nostr]"

# everything
pip install "git+https://github.com/SamsonCyber/agent-canary.git#egg=agent-canary[all]"

# pin a tag
pip install "git+https://github.com/SamsonCyber/agent-canary.git@v0.3.0"
```

Requires Python 3.10+.

---

## Quickstart

```bash
agent-canary init

# honeypot files
agent-canary plant file traps/.env.production --template aws_creds
agent-canary plant file secrets/database.yml --template db_creds

# MCP tripwires
agent-canary plant mcp-tool execute_sql_admin \
  --description "Run admin SQL queries on production database"
agent-canary plant mcp-tool export_user_data \
  --description "Export user data in bulk"

# API decoys
agent-canary plant api /admin/config --method GET --description "Admin config lure"
agent-canary plant api /v1/users/export --method POST --description "Bulk export"

agent-canary list
agent-canary watch          # file access
agent-canary serve-mcp      # or: agent-canary serve-mcp --stdio
agent-canary serve-api     # decoy HTTP
agent-canary dash          # operator UI
```

All-in-one: `agent-canary run` (watcher + MCP SSE + API).

---

## Three vectors

**File honeypots.** Six templates (AWS env, DB YAML, SSH key, API keys, PII CSV, internal doc). Watchdog monitoring with polling fallback. `check_file_access` for MCP wrappers that intercept reads.

**MCP tripwire tools.** High-privilege looking tools. On call: log full arguments, return a plausible permission error. Wire into Claude Desktop / Claude Code via stdio.

**API decoys.** Fake bulk export, admin config, cloud metadata, Vault-style routes. Capture method, path, headers, body, client IP.

---

## Alerts

Webhook, Slack, Discord, and Nostr fire when tripwires hit (watch / serve-mcp / serve-api / run).

```bash
agent-canary alert add webhook https://your-server.com/canary-hook
agent-canary alert add slack https://hooks.slack.com/services/T.../B.../xxx
agent-canary alert add discord https://discord.com/api/webhooks/123/abc
agent-canary alert add nostr wss://relay.damus.io
agent-canary alert test
agent-canary alert list
```

---

## MCP integration

```json
{
  "mcpServers": {
    "canary": {
      "command": "agent-canary",
      "args": ["serve-mcp", "--stdio"]
    }
  }
}
```

Any agent that calls a tripwire tool is logged with forensic context, then gets a permission-denied style response.

---

## File templates

| Template | Generates | Use case |
|----------|-----------|----------|
| `aws_creds` | Fake `.env` with AWS keys | Credential harvesting |
| `db_creds` | Production/staging DB YAML | Database access probes |
| `ssh_key` | Fake RSA key with embedded id | Key exfiltration |
| `api_keys` | Stripe / OpenAI / GitHub-style tokens | API key theft |
| `pii_data` | CSV of fake PII | Data exfiltration |
| `internal_doc` | Confidential-looking markdown | Doc access |

Each template embeds the canary id in a format-plausible way.

---

## Scope rules and notices

**Scope rules:** `allow_agents` / `deny_agents` cut false positives. Allow list wins when both are set.

**Scope notices (soft):** `off` (default silent honeypot), `static`, or `stochastic` boundary text for measurement. Not a hard control. Use tool allowlists and network policy for real gates.

```bash
agent-canary plant file traps/keys.env --template api_keys --notice stochastic
```

---

## How it differs

| Tool | Primary target | Where it sits |
|------|----------------|---------------|
| Thinkst Canary | Human attackers on classic infra | Network / infra |
| Beelzebub MCP | General network deception | Network |
| SNARE / TANNER | Web scanners | Web tier |
| **Agent Canary** | AI agents (MCP, file reads, API probing) | App layer in your tree |

Agent-specific forensics (tool args, optional reasoning, fingerprints) plus a local dash and optional Nostr attestation. No separate honeypot host required.

---

## License

MIT

**Repo:** [github.com/SamsonCyber/agent-canary](https://github.com/SamsonCyber/agent-canary)
