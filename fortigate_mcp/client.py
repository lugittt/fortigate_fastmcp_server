"""FortiOS REST client.

Talks to a live FortiGate over the FortiOS REST API and normalizes the raw
responses into the clean dict shapes the MCP tools return.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings

PROTO_NUM_TO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
PROTO_NAME_TO_NUM = {v: k for k, v in PROTO_NUM_TO_NAME.items()}

# When client-side filtering the session table, fetch up to this many rows first.
SESSION_FETCH_CAP = 2000


class FortiGateError(RuntimeError):
    """Raised when a request to the FortiGate fails."""


def proto_label(value: Any) -> str:
    """Canonical uppercase protocol label from a number (6) or name ('udp')."""
    num = _proto_to_num(value)
    if num is not None:
        return PROTO_NUM_TO_NAME.get(num, str(value).upper())
    return str(value).upper()


# Backwards-compatible alias used by the log normalizer.
proto_name = proto_label


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


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _names(value: Any) -> list[str]:
    """Flatten FortiOS ``[{"name": "x"}, ...]`` config lists to ``["x", ...]``."""
    if isinstance(value, list):
        return [v.get("name") if isinstance(v, dict) else v for v in value]
    if isinstance(value, dict):
        return [value.get("name")]
    if value in (None, ""):
        return []
    return [value]


def _epoch_iso(value: Any) -> str | None:
    ts = _as_int(value)
    if not ts:
        return None
    import datetime

    return datetime.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


def _extract_sessions(data: dict) -> list[dict]:
    """Return the session list across firmware shapes.

    Newer FortiOS returns ``results: {"details": [...]}``; older/other builds
    return ``results: [...]`` directly.
    """
    res = data.get("results", [])
    if isinstance(res, dict):
        return res.get("details", []) or []
    return res or []


class FortiGateClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._client: httpx.Client | None = None

    # -- HTTP plumbing -------------------------------------------------------
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
        return [_normalize_log(r) for r in data.get("results", [])[:limit]]

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
        client_filtered = any(v is not None for v in (srcip, dstip, dstport, proto_num))

        # policyid filters reliably server-side; the other fields are filtered
        # client-side because firmware honors them inconsistently.
        params: list[tuple[str, Any]] = [
            ("count", SESSION_FETCH_CAP if client_filtered else limit)
        ]
        if policyid is not None:
            params.append(("policyid", policyid))

        data = self._get("/api/v2/monitor/firewall/session", params)
        out: list[dict] = []
        for r in _extract_sessions(data):
            if srcip and r.get("saddr", r.get("source")) != srcip:
                continue
            if dstip and r.get("daddr", r.get("dest")) != dstip:
                continue
            if dstport is not None and _as_int(r.get("dport", r.get("dest_port"))) != dstport:
                continue
            if proto_num is not None and _proto_to_num(r.get("proto")) != proto_num:
                continue
            out.append(_normalize_session(r))
            if len(out) >= limit:
                break
        return out

    # -- tool 3: inspect firewall policy ------------------------------------
    def inspect_firewall_policy(
        self,
        policyid: int | None = None,
        limit: int = 50,
    ) -> list[dict]:
        # Configured rules (name, action, match criteria).
        path = "/api/v2/cmdb/firewall/policy"
        if policyid is not None:
            path = f"{path}/{policyid}"
        cfg = self._get(path, [])
        configs = cfg.get("results", [])
        if isinstance(configs, dict):  # single-policy fetch may return an object
            configs = [configs]

        # Live per-policy counters, keyed by policyid.
        stats_by_id: dict[int, dict] = {}
        try:
            stats = self._get("/api/v2/monitor/firewall/policy", [])
            for s in stats.get("results", []):
                pid = _as_int(s.get("policyid"))
                if pid is not None:
                    stats_by_id[pid] = s
        except FortiGateError:
            pass  # config still useful without live counters

        out = [_normalize_policy(c, stats_by_id) for c in configs[:limit]]
        return out


# -- normalization helpers ---------------------------------------------------
def _normalize_log(r: dict) -> dict:
    return {
        "timestamp": f"{r.get('date', '')} {r.get('time', '')}".strip(),
        "action": r.get("action"),
        "src": _addr(r.get("srcip"), r.get("srcport")),
        "dst": _addr(r.get("dstip"), r.get("dstport")),
        "protocol": proto_name(r.get("proto")),
        "service": r.get("service"),
        "app_category": r.get("app", r.get("appcat")),
        "policy_id": r.get("policyid"),
        "policy_name": r.get("policyname"),
        "src_intf": r.get("srcintf"),
        "dst_intf": r.get("dstintf"),
        "src_country": r.get("srccountry"),
        "dst_country": r.get("dstcountry"),
        "sent_bytes": r.get("sentbyte"),
        "rcvd_bytes": r.get("rcvdbyte"),
        "message": r.get("msg"),
    }


def _normalize_policy(cfg: dict, stats_by_id: dict[int, dict]) -> dict:
    pid = _as_int(cfg.get("policyid"))
    stats = stats_by_id.get(pid, {}) if pid is not None else {}
    return {
        "policy_id": pid,
        "name": cfg.get("name") or "(unnamed)",
        "action": cfg.get("action"),
        "status": cfg.get("status"),
        "src_intf": _names(cfg.get("srcintf")),
        "dst_intf": _names(cfg.get("dstintf")),
        "src_addr": _names(cfg.get("srcaddr")),
        "dst_addr": _names(cfg.get("dstaddr")),
        "service": _names(cfg.get("service")),
        "schedule": cfg.get("schedule"),
        "nat": cfg.get("nat"),
        "log_traffic": cfg.get("logtraffic"),
        "comments": cfg.get("comments") or None,
        # live counters
        "hit_count": stats.get("hit_count"),
        "active_sessions": stats.get("active_sessions"),
        "bytes": stats.get("bytes"),
        "packets": stats.get("packets"),
        "first_used": _epoch_iso(stats.get("first_used")),
        "last_used": _epoch_iso(stats.get("last_used")),
    }


def _normalize_session(r: dict) -> dict:
    # Field names differ across firmware; prefer the modern names, fall back.
    saddr = r.get("saddr", r.get("source"))
    sport = r.get("sport", r.get("source_port"))
    daddr = r.get("daddr", r.get("dest"))
    dport = r.get("dport", r.get("dest_port"))

    sent, rcvd = r.get("sentbyte"), r.get("rcvdbyte")
    total_bytes = r.get("total_bytes")
    if total_bytes is None and (sent is not None or rcvd is not None):
        total_bytes = (sent or 0) + (rcvd or 0)

    tx, rx = r.get("tx_packets"), r.get("rx_packets")
    total_pkts = r.get("total_packets")
    if total_pkts is None and (tx is not None or rx is not None):
        total_pkts = (tx or 0) + (rx or 0)

    application = r.get("application")
    apps = r.get("apps")
    if not application and isinstance(apps, list) and apps:
        application = apps[0].get("name")

    nat_src = None
    if r.get("snaddr"):
        nat_src = _addr(r.get("snaddr"), r.get("snport"))

    return {
        "protocol": proto_label(r.get("proto")),
        "src": _addr(saddr, sport),
        "dst": _addr(daddr, dport),
        "nat_src": nat_src,
        "policy_id": r.get("policyid"),
        "state": r.get("state"),
        "src_intf": r.get("srcintf", r.get("src_intf")),
        "dst_intf": r.get("dstintf", r.get("dst_intf")),
        "duration_sec": r.get("duration"),
        "expire_sec": _as_int(r.get("expiry", r.get("expire"))),
        "bytes": total_bytes,
        "packets": total_pkts,
        "application": application,
        "country": r.get("country"),
    }
