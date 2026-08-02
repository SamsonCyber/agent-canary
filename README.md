# Agent Canary

Tripwire detection for autonomous AI agents.

## What It Does

Agent Canary plants canary tokens across your codebase, MCP tool surface, and API endpoints. When an AI agent touches a honeypot file, calls a tripwire tool, or hits a decoy API route, the system captures the full forensic chain (arguments, headers, client IP, preceding tool calls) and logs a structured trigger event. You get immediate visibility into unauthorized agent behavior without modifying your production systems.

## Install

```
pip install agent-canary
```

## Quickstart

```bash
# Initialize in your project root
agent-canary init

# Plant honeypot files
agent-canary plant file .env.production --template aws_creds
agent-canary plant file secrets/database.yml --template db_creds

# Register MCP tripwire tools
agent-canary plant mcp-tool execute_sql_admin --description "Run admin SQL queries on production database"
agent-canary plant mcp-tool export_user_data --description "Export user data in bulk"

# Register API decoy endpoints
agent-canary plant api /admin/config --method GET --description "Admin config access lure"

# See what's deployed
agent-canary list

# Start watching for triggers
agent-canary watch
```

## MCP Integration

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

## Three Vectors

**File honeypots** -- Generate realistic-looking credential files, API key configs, PII exports, and internal documents from 6 built-in templates. Uses `watchdog` for filesystem monitoring with fallback polling. Manual access checking is available for MCP tool wrappers that intercept `read_file` calls.

**MCP tripwire tools** -- Register fake MCP tools (5 defaults: `execute_sql_admin`, `send_email`, `export_user_data`, `modify_production_config`, `delete_resources`) that look like high-privilege operations. When called, they capture the full tool invocation arguments and return a convincing error response.

**API decoy endpoints** -- Serve fake HTTP endpoints (4 defaults: bulk export, admin config, cloud metadata credentials, Vault-style secrets) that capture request forensics including headers, body, query parameters, and client IP.

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

## File Templates

| Template | Generates | Use Case |
|---|---|---|
| `aws_creds` | Fake `.env` with AWS access keys | Detect credential harvesting |
| `db_creds` | Database config YAML with production/staging blocks | Detect database access attempts |
| `ssh_key` | Fake RSA private key with embedded tracking | Detect key exfiltration |
| `api_keys` | YAML with Stripe, OpenAI, and GitHub tokens | Detect API key theft |
| `pii_data` | CSV with 6 rows of fake PII (names, SSNs, emails) | Detect data exfiltration |
| `internal_doc` | Markdown architecture document marked confidential | Detect document access |

Each template embeds the canary ID in a way that blends with the file format, making it traceable without being obvious.

## Scope Rules

Canaries support allow/deny lists to reduce false positives:

- `allow_agents` -- Listed agents never trigger the canary. Anyone else does.
- `deny_agents` -- Only listed agents trigger. Everyone else is ignored.
- Both set -- Allow list takes precedence (allowlisted agents are always safe).
- Neither set -- Universal canary, everything triggers.

## How It Differs From Existing Tools

Thinkst Canary targets network-level intrusion (DNS tokens, HTTP beacons, credential pairs) for human attackers on traditional infrastructure. Agent Canary targets the AI agent attack surface: MCP tool calls, file reads through agentic frameworks, and API probing by autonomous systems. Beelzebub MCP provides honeypot infrastructure for general network deception. Agent Canary operates at the application layer, embedding directly in your project directory with zero infrastructure requirements. SNARE/TANNER focus on web application honeypots for vulnerability scanners. Agent Canary captures forensic data specific to LLM agents: tool call arguments, reasoning traces, and agent fingerprints that let you classify whether a trigger was scope creep, prompt injection, or emergent behavior.

## License

MIT
