"""Offline smoke test: drive the server in mock mode through an in-memory MCP client.

Run: python smoke_test.py
"""

import asyncio
import json

from fastmcp import Client

from fortigate_mcp.server import mcp


async def main() -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()
        print("Tools:", [t.name for t in tools])
        assert {t.name for t in tools} == {
            "search_traffic_logs",
            "list_firewall_sessions",
            "firewall_policy_lookup",
        }

        print("\n== denied traffic ==")
        r = await client.call_tool("search_traffic_logs", {"action": "deny"})
        print(json.dumps(r.data, indent=2))
        assert r.data and all(e["action"] == "deny" for e in r.data)

        print("\n== sessions to port 443 ==")
        r = await client.call_tool("list_firewall_sessions", {"dstport": 443})
        print(json.dumps(r.data, indent=2))
        assert r.data and all(e["dst"].endswith(":443") for e in r.data)

        print("\n== policy lookup: RDP from DMZ to LAN host ==")
        r = await client.call_tool(
            "firewall_policy_lookup",
            {"srcintf": "port3", "dstip": "10.10.20.10", "dstport": 3389, "proto": "tcp"},
        )
        print(json.dumps(r.data, indent=2))
        assert r.data["action"] == "deny" and r.data["would_be_allowed"] is False

        print("\n== policy lookup: HTTPS from LAN to Internet ==")
        r = await client.call_tool(
            "firewall_policy_lookup",
            {"srcintf": "port2", "dstip": "142.250.72.14", "dstport": 443},
        )
        print(json.dumps(r.data, indent=2))
        assert r.data["would_be_allowed"] is True

    print("\nAll assertions passed.")


if __name__ == "__main__":
    asyncio.run(main())
