# FortiGate Troubleshooting MCP Server

A local [FastMCP](https://github.com/jlowin/fastmcp) (Python) server that exposes
FortiGate traffic-log and session troubleshooting over the **FortiOS REST API**.
Built for network engineers doing permit/deny and session debugging from Claude.

It connects to a **live FortiGate** — credentials come from the environment / a
`.env` file, and nothing is stored in code.

## Tools

| Tool | Answers | FortiOS endpoint |
|---|---|---|
| `search_traffic_logs` | *Was this flow permitted or denied, and by which policy?* | `GET /api/v2/log/memory/traffic/forward` |
| `list_firewall_sessions` | *Is there a live session for this flow, and what state is it in?* | `GET /api/v2/monitor/firewall/session` |
| `inspect_firewall_policy` | *What is policy N — its rule, action, and how much is it being hit?* | `GET /api/v2/cmdb/firewall/policy` + `GET /api/v2/monitor/firewall/policy` |

All three are **read-only**. `search_traffic_logs` and `list_firewall_sessions`
accept filters (source/dest IP, port, protocol, policy id). `inspect_firewall_policy`
takes a `policyid` (the `policy_id` you get from a log or session) and returns the
rule config merged with live counters — or the whole policy table if you omit it.

> **Why not a "policy lookup" (would-this-be-allowed) tool?** The
> `firewall/policy-lookup` REST endpoint returns `424 Failed Dependency` on FortiOS
> 7.4.x (FGT-60F confirmed) regardless of parameters — a known firmware limitation.
> `inspect_firewall_policy` covers the same troubleshooting need reliably: pull the
> `policy_id` from a traffic log / session, then inspect that rule.

## Setup

```bash
pip install -e .          # installs fastmcp + httpx + python-dotenv
cp .env.example .env      # then fill in host + token
```

Requires Python 3.10+.

### Configure the connection

1. On the FortiGate: **System → Administrators → Create New → REST API Admin**.
   Give it a read-only admin profile scoped to the VDOM(s) you need, set the
   trusted host to the machine running this server, and generate an **API token**.
2. Fill in `.env` (see `.env.example`):

   ```ini
   FORTIGATE_HOST=192.168.33.1     # or fw01.corp.local:8443
   FORTIGATE_API_TOKEN=xxxxxxxx    # FORTIGATE_TOKEN is also accepted
   FORTIGATE_VDOM=root
   FORTIGATE_VERIFY_SSL=false      # set true once you trust the cert
   ```

   The `.env` file is loaded automatically; real environment variables override it.

   > Traffic logs are read from the **memory** buffer (`/log/memory/...`), so the
   > FortiGate must have `set status enable` under `config log memory setting`.
   > Memory retention is small — for historical logs use disk or FortiAnalyzer.

### Verify connectivity

```bash
python check_connection.py
```

This calls each endpoint once and prints a short summary (or a clear error if the
token, VDOM, or REST permissions are wrong).

## Run it

```bash
python -m fortigate_mcp.server      # stdio transport
# or, after pip install -e .:
fortigate-mcp
```

## Connect to Claude

### Claude Code

```bash
claude mcp add fortigate -- python -m fortigate_mcp.server
```

Or add to `.mcp.json` / your Claude Code config:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "python",
      "args": ["-m", "fortigate_mcp.server"],
      "cwd": "C:\\Users\\lukbu\\OneDrive\\Dokumenty\\AI2\\fortigate_fastmcp_server",
      "env": {
        "FORTIGATE_HOST": "192.168.33.1",
        "FORTIGATE_API_TOKEN": "xxxxxxxx",
        "FORTIGATE_VDOM": "root"
      }
    }
  }
}
```

The `env` block here is optional if you keep a `.env` in `cwd`. On Claude Desktop,
add the same block under `mcpServers` in `claude_desktop_config.json`.

## Example prompts

- "Show me denied traffic from 192.168.33.115 in the recent logs."
- "List active firewall sessions to port 443."
- "That session matched policy 1 — inspect policy 1 and tell me its action and hit count."

## Project layout

```
fortigate_mcp/
  server.py     FastMCP server + the 3 tool definitions
  client.py     FortiOS REST client (requests, filtering, normalization)
  config.py     env/.env-driven settings, required-field validation
check_connection.py   one-shot live connectivity check against the FortiGate
```

## Notes on this firmware (FGT-60F, FortiOS 7.4.8)

- Sessions are returned under `results.details[]` with `proto` as a string; the
  client normalizes across firmware shapes.
- Session server-side filters are honored inconsistently, so all session filters
  except `policyid` are applied client-side after fetching the table.
- Traffic-log filters (`action`, `srcip`, `dstip`, `dstport`, `proto`) work
  server-side via the log `filter=` syntax.

## Extending

- Add disk logging: point `search_traffic_logs` at `/api/v2/log/disk/traffic/forward`.
- More log types (`utm`, `event`, `local`) follow the same `/log/<src>/<type>/<subtype>` shape.
- To wrap many more FortiOS endpoints, consider a search+execute tool pattern
  instead of one-tool-per-action.
