# Agent Canary

Tripwire detection for autonomous AI agents.

## What it does

Plants canary tokens in your codebase, MCP tool surface, and API endpoints. When an agent reads a honeypot file, calls a tripwire tool, or hits a decoy API route, Agent Canary logs a structured trigger with the forensic chain (arguments, headers, client IP, preceding tool calls). You see scope creep and unauthorized tool use without changing production app logic.

## Install

```
pip install agent-canary
```

## Quickstart

```bash
# Initialize in your project root
agent-canary init

# Plant honeypot files (default --notice off: silent honeypot)
agent-canary plant file .env.production --template aws_creds
agent-canary plant file secrets/database.yml --template db_creds

# Soft scope notice for measurement (static | stochastic)
agent-canary plant file traps/.env.prod --template aws_creds --notice stochastic

# Register MCP tripwire tools
agent-canary plant mcp-tool execute_sql_admin \
  --description "Run admin SQL queries on production database" --notice static
agent-canary plant mcp-tool export_user_data --description "Export user data in bulk"

# Register API decoy endpoints
agent-canary plant api /admin/config --method GET --description "Admin config access lure"
agent-canary plant api /v1/users/export --method POST --description "Bulk export" --notice stochastic

# See what's deployed
agent-canary list

# Start watching for triggers
agent-canary watch
```

## MCP integration

Add the tripwire MCP server to your `claude_desktop_config.json`:

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

The server exposes tripwire tools via JSON-RPC. Any agent that calls one of these tools gets logged with full forensic context, then receives a plausible permission-denied error.

## Three vectors

**File honeypots.** Generate realistic credential files, API key configs, PII exports, and internal documents from 6 built-in templates. Monitors with `watchdog` (polling fallback). Manual access checks work for MCP wrappers that intercept `read_file`.

**MCP tripwire tools.** Register fake high-privilege tools (5 defaults: `execute_sql_admin`, `send_email`, `export_user_data`, `modify_production_config`, `delete_resources`). On call, they log full arguments and return a plausible permission-denied error.

**API decoy endpoints.** Serve fake HTTP routes (4 defaults: bulk export, admin config, cloud metadata credentials, Vault-style secrets) and capture headers, body, query parameters, and client IP.

## Alerts

Configure webhook, Slack, or Discord notifications:

```bash
# Generic webhook
agent-canary alert add webhook https://your-server.com/canary-hook

# Slack incoming webhook
agent-canary alert add slack https://hooks.slack.com/services/T.../B.../xxx

# Discord webhook
agent-canary alert add discord https://discord.com/api/webhooks/123/abc

# Test all configured destinations
agent-canary alert test

# List configured destinations
agent-canary alert list
```

Alerts fire on every trigger event with structured payloads containing the canary ID, vector type, severity, forensic chain, and agent fingerprint.

## File templates

| Template | Generates | Use case |
|---|---|---|
| `aws_creds` | Fake `.env` with AWS access keys | Credential harvesting |
| `db_creds` | Database config YAML with production/staging blocks | Database access attempts |
| `ssh_key` | Fake RSA private key with embedded tracking | Key exfiltration |
| `api_keys` | YAML with Stripe, OpenAI, and GitHub tokens | API key theft |
| `pii_data` | CSV with 6 rows of fake PII (names, SSNs, emails) | Data exfiltration |
| `internal_doc` | Markdown architecture document marked confidential | Document access |

Each template embeds the canary ID in a format-plausible way so the lure stays traceable without looking like a tripwire.

## Scope rules

Canaries support allow/deny lists to cut false positives:

- `allow_agents`: listed agents never trigger. Anyone else does.
- `deny_agents`: only listed agents trigger. Everyone else is ignored.
- Both set: allow list wins (allowlisted agents stay safe).
- Neither set: universal canary; everything triggers.

## Scope notices (agent robots.txt)

Optional soft boundary text returned with a tripwire response. Default plant mode is `off` so existing silent honeypots stay silent.

| Mode | Behavior |
|------|----------|
| `off` | No notice. Same as v0.1 (log + deny / lure body only). |
| `static` | Fixed banner text every access. Good for reproducible demos. |
| `stochastic` | Sampled policy / boundary / forbid lines per access. Rare honest honeypot arm. |

What you get in forensics:

- `scope_notice` on each `TriggerEvent` (`notice_id`, `family`, `access_n`, `text`, `mode`)
- `access_count` on the canary (retries escalate wording after 3 hits)
- File plants: notice banner prepended at plant time when mode is not `off`
- MCP / API: notice merged into the JSON error body the agent sees

What this is **not**:

- Not a hard control. Agents can ignore or paraphrase soft text.
- Not a fix for accidental agent "hacking" in production. Use hard scope gates, tool allowlists, and network policy for that.
- Measurement and forensics first: did the agent see the notice, retry, or change path?

```bash
agent-canary plant file traps/keys.env --template api_keys --notice stochastic
agent-canary plant mcp-tool delete_resources \
  --description "Delete cloud resources" --notice static
agent-canary plant api /admin/config --method GET \
  --description "Admin config" --notice stochastic
```

Triggers with notices appear in `agent-canary triggers --format json` under `scope_notice`.

## How it differs from existing tools

| Tool | Primary target | Where it sits |
|------|----------------|---------------|
| Thinkst Canary | Human attackers on classic infra (DNS tokens, HTTP beacons, credential pairs) | Network / infra |
| Beelzebub MCP | General network deception honeypots | Network |
| SNARE/TANNER | Web app honeypots for scanners | Web tier |
| **Agent Canary** | AI agents: MCP tool calls, agent file reads, autonomous API probing | App layer in your project tree |

Agent Canary records agent-specific forensics (tool arguments, reasoning traces when available, agent fingerprints) so you can tell scope creep from injection or unexpected tool use. No separate honeypot host required.

## License

MIT
