"""FastMCP server exposing FortiGate traffic-log and session troubleshooting tools.

Run directly (``python -m fortigate_mcp.server``) or via the ``fortigate-mcp``
console script. Connection settings come from the environment (see
``.env.example``); with no host/token configured it serves realistic mock data.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

from .client import FortiGateClient, FortiGateError
from .config import load_settings

settings = load_settings()
_client = FortiGateClient(settings)

_mode = "MOCK (sample data)" if settings.mock else f"LIVE ({settings.base_url}, vdom={settings.vdom})"

mcp = FastMCP(
    name="fortigate-tshoot",
    instructions=(
        "Tools for troubleshooting FortiGate traffic. Use search_traffic_logs to see "
        "whether flows were permitted or denied and by which policy; use "
        "list_firewall_sessions to inspect live sessions in the session table; use "
        "firewall_policy_lookup to predict which policy a hypothetical flow would match. "
        f"Data source: {_mode}."
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


@mcp.tool(annotations={"title": "Firewall policy lookup", **_READ_ONLY})
def firewall_policy_lookup(
    srcintf: Annotated[str, Field(description="Ingress interface the flow enters on, e.g. 'port2' or 'wan1'.")],
    dstip: Annotated[str, Field(description="Destination IP of the hypothetical flow.")],
    dstport: Annotated[int | None, Field(description="Destination port, e.g. 443. Omit for protocols without ports (ICMP).")] = None,
    proto: Annotated[str, Field(description="Protocol name or number: 'tcp', 'udp', 'icmp'. Default 'tcp'.")] = "tcp",
    srcip: Annotated[str | None, Field(description="Optional source IP for a more precise match.")] = None,
) -> dict:
    """Predict which firewall policy a hypothetical flow would match, and its action.

    Answers 'if I sent this traffic, would the firewall permit or deny it, and via
    which policy?' — without generating any real traffic. Returns the matched
    policy id/name, the action (accept/deny), and a would_be_allowed boolean. A
    policy_id of 0 means no policy matched (implicit deny).
    """
    return _client.policy_lookup(
        srcintf=srcintf, dstip=dstip, dstport=dstport, proto=proto, srcip=srcip
    )


def main() -> None:
    try:
        mcp.run()  # stdio transport by default
    finally:
        _client.close()


if __name__ == "__main__":
    main()
