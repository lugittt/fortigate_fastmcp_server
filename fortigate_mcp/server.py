"""FastMCP server exposing FortiGate traffic-log and session troubleshooting tools.

Run directly (``python -m fortigate_mcp.server``) or via the ``fortigate-mcp``
console script. Connection settings come from the environment / a ``.env`` file
(see ``.env.example``); FORTIGATE_HOST and FORTIGATE_API_TOKEN are required.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

from .client import FortiGateClient
from .config import load_settings

settings = load_settings()
_client = FortiGateClient(settings)

mcp = FastMCP(
    name="fortigate-tshoot",
    instructions=(
        "Tools for troubleshooting FortiGate traffic. Use search_traffic_logs to see "
        "whether flows were permitted or denied and by which policy; use "
        "list_firewall_sessions to inspect live sessions in the session table; use "
        "inspect_firewall_policy to resolve a policy id (from a log or session) into "
        "its rule, action, and live hit counters. "
        f"Connected to {settings.base_url} (vdom={settings.vdom})."
    ),
)

_READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}


@mcp.tool(annotations={"title": "Search traffic logs", **_READ_ONLY})
def search_traffic_logs(
    action: Annotated[
        Literal["accept", "deny", "all"],
        Field(description="Filter by policy action: 'accept' (permitted), 'deny' (blocked), or 'all'."),
    ] = "all",
    srcip: Annotated[str | None, Field(description="Exact source IP to match, e.g. '10.10.20.15'.")] = None,
    dstip: Annotated[str | None, Field(description="Exact destination IP to match.")] = None,
    dstport: Annotated[int | None, Field(description="Destination port to match, e.g. 443.")] = None,
    proto: Annotated[str | None, Field(description="Protocol name or number: 'tcp', 'udp', 'icmp', or 6/17/1.")] = None,
    limit: Annotated[int, Field(ge=1, le=200, description="Max number of log entries to return.")] = 20,
) -> list[dict]:
    """Search FortiGate forward *traffic* logs (memory buffer) for permit/deny events.

    Answers 'was this flow allowed or blocked, and by which policy?'. Returns the
    most recent matching entries with source/destination, protocol, action, the
    matching policy id/name, interfaces, and byte counts.
    """
    return _client.search_traffic_logs(
        action=action, srcip=srcip, dstip=dstip, dstport=dstport, proto=proto, limit=limit
    )


@mcp.tool(annotations={"title": "List firewall sessions", **_READ_ONLY})
def list_firewall_sessions(
    srcip: Annotated[str | None, Field(description="Exact source IP to match.")] = None,
    dstip: Annotated[str | None, Field(description="Exact destination IP to match.")] = None,
    dstport: Annotated[int | None, Field(description="Destination port to match, e.g. 3389.")] = None,
    proto: Annotated[str | None, Field(description="Protocol name or number: 'tcp', 'udp', 'icmp', or 6/17/1.")] = None,
    policyid: Annotated[int | None, Field(description="Only sessions matched by this firewall policy id.")] = None,
    limit: Annotated[int, Field(ge=1, le=200, description="Max number of sessions to return.")] = 20,
) -> list[dict]:
    """List entries from the FortiGate live *session* table with per-session details.

    Answers 'is there an active session for this flow right now, and what state is
    it in?'. Returns protocol, src/dst (ip:port), matching policy id, session state,
    ingress/egress interfaces, duration, expiry, and byte/packet counters.
    """
    return _client.list_firewall_sessions(
        srcip=srcip, dstip=dstip, dstport=dstport, proto=proto, policyid=policyid, limit=limit
    )


@mcp.tool(annotations={"title": "Inspect firewall policy", **_READ_ONLY})
def inspect_firewall_policy(
    policyid: Annotated[
        int | None,
        Field(description="The firewall policy id to inspect (the 'policy_id' from a traffic log or session). Omit to list all policies."),
    ] = None,
    limit: Annotated[int, Field(ge=1, le=500, description="Max number of policies to return when listing all.")] = 50,
) -> list[dict]:
    """Resolve a firewall policy id into the actual rule plus its live usage.

    Use this to explain a permit/deny: take the 'policy_id' from search_traffic_logs
    or list_firewall_sessions and inspect it here. Returns the rule's name, action
    (accept/deny), status, source/destination interfaces and addresses, service, NAT
    and logging settings, plus live counters (hit_count, active_sessions, bytes, and
    first/last used time). Omit policyid to review the whole policy table.
    """
    return _client.inspect_firewall_policy(policyid=policyid, limit=limit)


def main() -> None:
    try:
        mcp.run()  # stdio transport by default
    finally:
        _client.close()


if __name__ == "__main__":
    main()
