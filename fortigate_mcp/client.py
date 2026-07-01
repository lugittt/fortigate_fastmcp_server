"""FortiOS REST client with a built-in offline mock mode.

Both modes return the *same* normalized dict shapes, so tool code (and Claude)
sees a consistent structure whether it is talking to a real FortiGate or to the
bundled sample data.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from . import mockdata
from .config import Settings

PROTO_NUM_TO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
PROTO_NAME_TO_NUM = {v: k for k, v in PROTO_NUM_TO_NAME.items()}


class FortiGateError(RuntimeError):
    """Raised when a live request to the FortiGate fails."""


def proto_name(num: Any) -> str:
    try:
        return PROTO_NUM_TO_NAME.get(int(num), str(num))
    except (TypeError, ValueError):
        return str(num)


def _proto_to_num(proto: str | int | None) -> int | None:
    """Accept 'tcp' / 'TCP' / 6 / '6' and return the protocol number."""
    if proto is None or proto == "":
        return None
    if isinstance(proto, int):
        return proto
    s = str(proto).strip()
    if s.isdigit():
        return int(s)
    return PROTO_NAME_TO_NUM.get(s.upper())


def _addr(ip: Any, port: Any) -> str:
    if port in (None, 0, "0"):
        return str(ip)
    return f"{ip}:{port}"


class FortiGateClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._client: httpx.Client | None = None

    @property
    def mock(self) -> bool:
        return self.settings.mock

    # -- live HTTP plumbing --------------------------------------------------
    def _http(self) -> httpx.Client:
        if self._client is None:
            s = self.settings
            self._client = httpx.Client(
                base_url=s.base_url,
                headers={"Authorization": f"Bearer {s.api_token}"},
                verify=s.verify_ssl,
                timeout=s.timeout,
            )
        return self._client

    def _get(self, path: str, params: list[tuple[str, Any]]) -> dict:
        params = [("vdom", self.settings.vdom), *params]
        try:
            resp = self._http().get(path, params=params)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise FortiGateError(
                f"FortiGate returned HTTP {exc.response.status_code} for {path}. "
                "Check the API token, admin profile permissions, and VDOM."
            ) from exc
        except httpx.HTTPError as exc:
            raise FortiGateError(
                f"Could not reach FortiGate at {self.settings.base_url} ({exc})."
            ) from exc
        return resp.json()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # -- tool 1: traffic logs ------------------------------------------------
    def search_traffic_logs(
        self,
        action: str = "all",
        srcip: str | None = None,
        dstip: str | None = None,
        dstport: int | None = None,
        proto: str | int | None = None,
        limit: int = 20,
    ) -> list[dict]:
        proto_num = _proto_to_num(proto)
        if self.mock:
            rows = self._mock_traffic(action, srcip, dstip, dstport, proto_num)
        else:
            rows = self._live_traffic(action, srcip, dstip, dstport, proto_num, limit)
        return [_normalize_log(r) for r in rows[:limit]]

    def _live_traffic(self, action, srcip, dstip, dstport, proto_num, limit) -> list[dict]:
        filters: list[tuple[str, Any]] = []
        if action and action != "all":
            filters.append(("filter", f"action=={action}"))
        if srcip:
            filters.append(("filter", f"srcip=={srcip}"))
        if dstip:
            filters.append(("filter", f"dstip=={dstip}"))
        if dstport is not None:
            filters.append(("filter", f"dstport=={dstport}"))
        if proto_num is not None:
            filters.append(("filter", f"proto=={proto_num}"))
        params = [("rows", limit), *filters]
        data = self._get("/api/v2/log/memory/traffic/forward", params)
        return data.get("results", [])

    def _mock_traffic(self, action, srcip, dstip, dstport, proto_num) -> list[dict]:
        out = []
        for r in mockdata.TRAFFIC_LOGS:
            if action and action != "all" and r["action"] != action:
                continue
            if srcip and r["srcip"] != srcip:
                continue
            if dstip and r["dstip"] != dstip:
                continue
            if dstport is not None and r["dstport"] != dstport:
                continue
            if proto_num is not None and r["proto"] != proto_num:
                continue
            out.append(r)
        return out

    # -- tool 2: firewall sessions ------------------------------------------
    def list_firewall_sessions(
        self,
        srcip: str | None = None,
        dstip: str | None = None,
        dstport: int | None = None,
        proto: str | int | None = None,
        policyid: int | None = None,
        limit: int = 20,
    ) -> list[dict]:
        proto_num = _proto_to_num(proto)
        if self.mock:
            rows = self._mock_sessions(srcip, dstip, dstport, proto_num, policyid)
        else:
            rows = self._live_sessions(srcip, dstip, dstport, proto_num, policyid, limit)
        return [_normalize_session(r) for r in rows[:limit]]

    def _live_sessions(self, srcip, dstip, dstport, proto_num, policyid, limit) -> list[dict]:
        params: list[tuple[str, Any]] = [("count", limit)]
        if srcip:
            params.append(("filter.srcip", srcip))
        if dstip:
            params.append(("filter.dstip", dstip))
        if dstport is not None:
            params.append(("filter.dport", dstport))
        if proto_num is not None:
            params.append(("filter.proto", proto_num))
        if policyid is not None:
            params.append(("filter.policyid", policyid))
        data = self._get("/api/v2/monitor/firewall/session", params)
        return data.get("results", [])

    def _mock_sessions(self, srcip, dstip, dstport, proto_num, policyid) -> list[dict]:
        out = []
        for r in mockdata.FIREWALL_SESSIONS:
            if srcip and r["source"] != srcip:
                continue
            if dstip and r["dest"] != dstip:
                continue
            if dstport is not None and r["dest_port"] != dstport:
                continue
            if proto_num is not None and r["proto"] != proto_num:
                continue
            if policyid is not None and r["policyid"] != policyid:
                continue
            out.append(r)
        return out

    # -- tool 3: policy lookup ----------------------------------------------
    def policy_lookup(
        self,
        srcintf: str,
        dstip: str,
        dstport: int | None = None,
        proto: str | int = "tcp",
        srcip: str | None = None,
    ) -> dict:
        proto_num = _proto_to_num(proto) or 6
        query = {
            "src_intf": srcintf, "srcip": srcip, "dstip": dstip,
            "dstport": dstport, "protocol": proto_name(proto_num),
        }
        if self.mock:
            result = self._mock_policy_lookup(srcintf, dstip, proto_num, dstport)
        else:
            result = self._live_policy_lookup(srcintf, srcip, dstip, dstport, proto_num)
        result["query"] = query
        return result

    def _live_policy_lookup(self, srcintf, srcip, dstip, dstport, proto_num) -> dict:
        params: list[tuple[str, Any]] = [
            ("ipVersion", 4),
            ("srcIntf", srcintf),
            ("protocol", proto_num),
            ("dest", dstip),
        ]
        if srcip:
            params.append(("sourceip", srcip))
        if dstport is not None:
            params.append(("destport", dstport))
        data = self._get("/api/v2/monitor/firewall/policy-lookup", params)
        res = data.get("results", data)
        if isinstance(res, list):
            res = res[0] if res else {}
        pid = res.get("policyid", res.get("id", 0)) or 0
        action = str(res.get("action", "deny")).lower()
        return {
            "matched": pid != 0,
            "policy_id": pid,
            "policy_name": res.get("name", "Implicit Deny" if pid == 0 else ""),
            "action": action,
            "would_be_allowed": action in ("accept", "allow"),
        }

    def _mock_egress_intf(self, dstip: str) -> str:
        try:
            addr = ipaddress.ip_address(dstip)
        except ValueError:
            return "wan1"
        for cidr, intf in mockdata.ROUTES:
            if addr in ipaddress.ip_network(cidr):
                return intf
        return "wan1"

    def _mock_policy_lookup(self, srcintf, dstip, proto_num, dstport) -> dict:
        dstintf = self._mock_egress_intf(dstip)
        for p in mockdata.POLICIES:
            if p["srcintf"] not in (srcintf, "any"):
                continue
            if p["dstintf"] not in (dstintf, "any"):
                continue
            if p["protocol"] is not None and p["protocol"] != proto_num:
                continue
            if p["dstport"] is not None and p["dstport"] != dstport:
                continue
            return {
                "matched": True,
                "policy_id": p["policyid"],
                "policy_name": p["name"],
                "action": p["action"],
                "would_be_allowed": p["action"] == "accept",
                "egress_intf": dstintf,
            }
        return {
            "matched": False,
            "policy_id": 0,
            "policy_name": "Implicit Deny",
            "action": "deny",
            "would_be_allowed": False,
            "egress_intf": dstintf,
        }


# -- normalization helpers ---------------------------------------------------
def _normalize_log(r: dict) -> dict:
    return {
        "timestamp": f"{r.get('date', '')} {r.get('time', '')}".strip(),
        "action": r.get("action"),
        "src": _addr(r.get("srcip"), r.get("srcport")),
        "dst": _addr(r.get("dstip"), r.get("dstport")),
        "protocol": proto_name(r.get("proto")),
        "service": r.get("service"),
        "app": r.get("app"),
        "policy_id": r.get("policyid"),
        "policy_name": r.get("policyname"),
        "src_intf": r.get("srcintf"),
        "dst_intf": r.get("dstintf"),
        "sent_bytes": r.get("sentbyte"),
        "rcvd_bytes": r.get("rcvdbyte"),
        "message": r.get("msg"),
    }


def _normalize_session(r: dict) -> dict:
    return {
        "protocol": proto_name(r.get("proto")),
        "src": _addr(r.get("source"), r.get("source_port")),
        "dst": _addr(r.get("dest"), r.get("dest_port")),
        "policy_id": r.get("policyid"),
        "state": r.get("state"),
        "src_intf": r.get("src_intf"),
        "dst_intf": r.get("dst_intf"),
        "duration_sec": r.get("duration"),
        "expire_sec": r.get("expire"),
        "bytes": r.get("total_bytes"),
        "packets": r.get("total_packets"),
        "application": r.get("application"),
    }
