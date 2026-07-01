"""Realistic offline sample data used when the server runs in mock mode.

The shapes mirror the relevant FortiOS REST responses closely enough that the
same normalization code works against a real device and against this data.
"""

from __future__ import annotations

# --- Memory traffic logs: /api/v2/log/memory/traffic/forward -----------------
# Field names follow FortiOS traffic log keys.
TRAFFIC_LOGS: list[dict] = [
    {
        "date": "2026-07-01", "time": "10:14:52", "srcip": "10.10.20.15",
        "srcport": 51512, "dstip": "142.250.72.14", "dstport": 443, "proto": 6,
        "action": "accept", "policyid": 12, "policyname": "LAN-to-Internet",
        "srcintf": "port2", "dstintf": "wan1", "service": "HTTPS",
        "app": "HTTPS.BROWSER", "sentbyte": 8421, "rcvdbyte": 91233,
        "sessionid": 100241, "msg": "Traffic accepted",
    },
    {
        "date": "2026-07-01", "time": "10:14:49", "srcip": "10.10.20.37",
        "srcport": 44210, "dstip": "203.0.113.55", "dstport": 22, "proto": 6,
        "action": "deny", "policyid": 0, "policyname": "Implicit Deny",
        "srcintf": "port2", "dstintf": "wan1", "service": "SSH",
        "app": "SSH", "sentbyte": 74, "rcvdbyte": 0,
        "sessionid": 100242, "msg": "Traffic denied by policy",
    },
    {
        "date": "2026-07-01", "time": "10:14:41", "srcip": "10.10.30.8",
        "srcport": 39944, "dstip": "10.10.20.10", "dstport": 3389, "proto": 6,
        "action": "deny", "policyid": 27, "policyname": "DMZ-to-LAN",
        "srcintf": "port3", "dstintf": "port2", "service": "RDP",
        "app": "RDP", "sentbyte": 120, "rcvdbyte": 0,
        "sessionid": 100243, "msg": "Traffic denied by policy",
    },
    {
        "date": "2026-07-01", "time": "10:14:38", "srcip": "10.10.20.15",
        "srcport": 55010, "dstip": "1.1.1.1", "dstport": 53, "proto": 17,
        "action": "accept", "policyid": 12, "policyname": "LAN-to-Internet",
        "srcintf": "port2", "dstintf": "wan1", "service": "DNS",
        "app": "DNS", "sentbyte": 88, "rcvdbyte": 140,
        "sessionid": 100244, "msg": "Traffic accepted",
    },
    {
        "date": "2026-07-01", "time": "10:14:30", "srcip": "192.0.2.44",
        "srcport": 60122, "dstip": "10.10.10.20", "dstport": 443, "proto": 6,
        "action": "accept", "policyid": 5, "policyname": "Internet-to-DMZ",
        "srcintf": "wan1", "dstintf": "port3", "service": "HTTPS",
        "app": "SSL", "sentbyte": 5120, "rcvdbyte": 40233,
        "sessionid": 100245, "msg": "Traffic accepted",
    },
    {
        "date": "2026-07-01", "time": "10:14:22", "srcip": "185.199.108.153",
        "srcport": 41888, "dstip": "10.10.10.20", "dstport": 445, "proto": 6,
        "action": "deny", "policyid": 0, "policyname": "Implicit Deny",
        "srcintf": "wan1", "dstintf": "port3", "service": "SMB",
        "app": "SMB", "sentbyte": 60, "rcvdbyte": 0,
        "sessionid": 100246, "msg": "Traffic denied by policy",
    },
    {
        "date": "2026-07-01", "time": "10:14:10", "srcip": "10.10.20.61",
        "srcport": 49001, "dstip": "52.96.7.34", "dstport": 443, "proto": 6,
        "action": "accept", "policyid": 12, "policyname": "LAN-to-Internet",
        "srcintf": "port2", "dstintf": "wan1", "service": "HTTPS",
        "app": "Microsoft.Portal", "sentbyte": 15321, "rcvdbyte": 220145,
        "sessionid": 100247, "msg": "Traffic accepted",
    },
    {
        "date": "2026-07-01", "time": "10:13:58", "srcip": "10.10.30.8",
        "srcport": 39955, "dstip": "8.8.8.8", "dstport": 123, "proto": 17,
        "action": "accept", "policyid": 18, "policyname": "DMZ-to-Internet",
        "srcintf": "port3", "dstintf": "wan1", "service": "NTP",
        "app": "NTP", "sentbyte": 76, "rcvdbyte": 76,
        "sessionid": 100248, "msg": "Traffic accepted",
    },
]

# --- Firewall sessions: /api/v2/monitor/firewall/session --------------------
FIREWALL_SESSIONS: list[dict] = [
    {
        "proto": 6, "proto_state": "01", "source": "10.10.20.15",
        "source_port": 51512, "dest": "142.250.72.14", "dest_port": 443,
        "policyid": 12, "duration": 42, "expire": 3558, "state": "may_dirty",
        "shaper_state": "", "src_intf": "port2", "dst_intf": "wan1",
        "total_bytes": 99654, "total_packets": 214, "application": "HTTPS.BROWSER",
    },
    {
        "proto": 6, "proto_state": "01", "source": "10.10.20.61",
        "source_port": 49001, "dest": "52.96.7.34", "dest_port": 443,
        "policyid": 12, "duration": 128, "expire": 3472, "state": "may_dirty",
        "shaper_state": "", "src_intf": "port2", "dst_intf": "wan1",
        "total_bytes": 235466, "total_packets": 501, "application": "Microsoft.Portal",
    },
    {
        "proto": 17, "proto_state": "00", "source": "10.10.20.15",
        "source_port": 55010, "dest": "1.1.1.1", "dest_port": 53,
        "policyid": 12, "duration": 2, "expire": 178, "state": "log",
        "shaper_state": "", "src_intf": "port2", "dst_intf": "wan1",
        "total_bytes": 228, "total_packets": 2, "application": "DNS",
    },
    {
        "proto": 6, "proto_state": "05", "source": "192.0.2.44",
        "source_port": 60122, "dest": "10.10.10.20", "dest_port": 443,
        "policyid": 5, "duration": 310, "expire": 3290, "state": "may_dirty",
        "shaper_state": "", "src_intf": "wan1", "dst_intf": "port3",
        "total_bytes": 45353, "total_packets": 96, "application": "SSL",
    },
    {
        "proto": 6, "proto_state": "02", "source": "10.10.30.8",
        "source_port": 39944, "dest": "10.10.20.10", "dest_port": 3389,
        "policyid": 27, "duration": 1, "expire": 5, "state": "dirty",
        "shaper_state": "", "src_intf": "port3", "dst_intf": "port2",
        "total_bytes": 120, "total_packets": 1, "application": "RDP",
    },
    {
        "proto": 1, "proto_state": "00", "source": "10.10.20.37",
        "source_port": 0, "dest": "8.8.8.8", "dest_port": 0,
        "policyid": 12, "duration": 3, "expire": 57, "state": "log",
        "shaper_state": "", "src_intf": "port2", "dst_intf": "wan1",
        "total_bytes": 392, "total_packets": 4, "application": "PING",
    },
]

# --- Mock routing table: destination subnet -> egress interface --------------
# The lookup engine resolves the egress interface from the destination IP first
# (as FortiOS does via the routing table), then evaluates policies.
ROUTES: list[tuple[str, str]] = [
    ("10.10.10.0/24", "port3"),   # DMZ
    ("10.10.30.0/24", "port3"),   # DMZ
    ("10.10.20.0/24", "port2"),   # LAN
    ("0.0.0.0/0", "wan1"),        # default route
]

# --- Named firewall policies, used by the mock policy-lookup engine ----------
# ordered as they would be evaluated top-down; last entry is the implicit deny.
POLICIES: list[dict] = [
    {"policyid": 5, "name": "Internet-to-DMZ", "srcintf": "wan1",
     "dstintf": "port3", "dstport": 443, "protocol": 6, "action": "accept"},
    {"policyid": 12, "name": "LAN-to-Internet", "srcintf": "port2",
     "dstintf": "wan1", "dstport": None, "protocol": None, "action": "accept"},
    {"policyid": 18, "name": "DMZ-to-Internet", "srcintf": "port3",
     "dstintf": "wan1", "dstport": None, "protocol": None, "action": "accept"},
    {"policyid": 27, "name": "DMZ-to-LAN", "srcintf": "port3",
     "dstintf": "port2", "dstport": 3389, "protocol": 6, "action": "deny"},
]
