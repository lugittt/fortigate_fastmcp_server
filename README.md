# FortiGate Troubleshooting MCP Server

A local [FastMCP](https://github.com/jlowin/fastmcp) (Python) server that exposes
FortiGate traffic-log and session troubleshooting over the **FortiOS REST API**.
Built for network engineers doing permit/deny and session debugging from Claude.

It runs in **mock mode** out of the box (realistic sample data, no device needed),
and switches to **live mode** as soon as you point it at a real FortiGate.

## Tools

| Tool | Answers | FortiOS endpoint |
|---|---|---|
| `search_traffic_logs` | *Was this flow permitted or denied, and by which policy?* | `GET /api/v2/log/memory/traffic/forward` |
| `list_firewall_sessions` | *Is there a live session for this flow, and what state is it in?* | `GET /api/v2/monitor/firewall/session` |
| `firewall_policy_lookup` | *If I sent this traffic, would it be allowed — and via which policy?* | `GET /api/v2/monitor/firewall/policy-lookup` |

All three are **read-only**. Each accepts filters (source/dest IP, port, protocol,
policy id) and returns normalized JSON with the same field names in mock and live mode.

## Setup

```bash
pip install -e .          # installs fastmcp + httpx
cp .env.example .env      # optional: only needed for live mode
```

Requires Python 3.10+.

### Mock mode (default)

With no `FORTIGATE_HOST`/`FORTIGATE_API_TOKEN` set, the server serves sample data.
Verify everything works end-to-end:

```bash
python smoke_test.py
```

### Live mode

1. On the FortiGate: **System → Administrators → Create New → REST API Admin**.
   Give it a read-only admin profile scoped to the VDOM(s) you need, allow the
   trusted host of the machine running this server, and generate an **API token**.
2. Fill in `.env` (see `.env.example`):

   ```ini
   FORTIGATE_HOST=192.0.2.1        # or fw01.corp.local:8443
   FORTIGATE_API_TOKEN=xxxxxxxx
   FORTIGATE_VDOM=root
   FORTIGATE_VERIFY_SSL=false      # set true once you trust the cert
   ```

   > Traffic logs come from the **memory** buffer (`/log/memory/...`), so the
   > FortiGate must have `set status enable` under `config log memory setting`.
   > Memory retention is small — for historical logs use disk or FortiAnalyzer.

The server auto-detects the mode; set `FORTIGATE_MOCK=true` to force sample data
even with a host configured.

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
        "FORTIGATE_HOST": "192.0.2.1",
        "FORTIGATE_API_TOKEN": "xxxxxxxx",
        "FORTIGATE_VDOM": "root"
      }
    }
  }
}
```

Leave the `env` block out to run in mock mode. On Claude Desktop, add the same
block under `mcpServers` in `claude_desktop_config.json`.

## Example prompts

- "Show me denied traffic from 10.10.20.37 in the last logs."
- "List active firewall sessions to port 443."
- "If a host on port3 tries RDP to 10.10.20.10, would the firewall allow it?"

## Project layout

```
fortigate_mcp/
  server.py     FastMCP server + the 3 tool definitions
  client.py     FortiOS REST client + mock engine (same output shapes)
  config.py     env-driven settings, mock/live auto-detection
  mockdata.py   realistic offline sample logs, sessions, policies, routes
smoke_test.py   drives all 3 tools in mock mode via an in-memory MCP client
```

## Extending

- Add disk logging: point `search_traffic_logs` at `/api/v2/log/disk/traffic/forward`.
- More log types (`utm`, `event`, `local`) follow the same `/log/<src>/<type>/<subtype>` shape.
- To wrap many more FortiOS endpoints, consider the search+execute tool pattern
  instead of one-tool-per-action.
