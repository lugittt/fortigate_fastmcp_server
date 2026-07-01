"""Live connectivity check against the configured FortiGate.

Reads FORTIGATE_* from the environment, calls each tool once, and prints a short
summary. Use this to confirm credentials, VDOM, and REST permissions before
wiring the server into Claude.

Run: python check_connection.py
"""

import sys

from fortigate_mcp.client import FortiGateClient, FortiGateError
from fortigate_mcp.config import ConfigError, load_settings


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Config error: {exc}")
        return 2

    client = FortiGateClient(settings)
    print(f"Connecting to {settings.base_url} (vdom={settings.vdom}) ...")
    try:
        logs = client.search_traffic_logs(limit=3)
        print(f"  traffic logs   : {len(logs)} row(s) returned")

        sessions = client.list_firewall_sessions(limit=3)
        print(f"  firewall sessions: {len(sessions)} row(s) returned")

        if sessions:
            s = sessions[0]
            print(f"    sample session: {s['protocol']} {s['src']} -> {s['dst']} "
                  f"policy {s['policy_id']} state {s['state']}")
    except FortiGateError as exc:
        print(f"FAILED: {exc}")
        return 1
    finally:
        client.close()

    print("OK - FortiGate reachable and REST API responding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
