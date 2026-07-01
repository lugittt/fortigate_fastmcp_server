"""Runtime configuration loaded from environment variables.

The server reads its connection settings from the environment so that no
credentials ever live in code. See ``.env.example`` for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str | None
    api_token: str | None
    vdom: str
    verify_ssl: bool
    timeout: float
    mock: bool

    @property
    def base_url(self) -> str:
        """Return the https base URL for the FortiOS REST API."""
        host = (self.host or "").strip().rstrip("/")
        if host.startswith("http://") or host.startswith("https://"):
            return host
        return f"https://{host}"


def load_settings() -> Settings:
    host = os.environ.get("FORTIGATE_HOST") or None
    api_token = os.environ.get("FORTIGATE_API_TOKEN") or None

    forced_mock = os.environ.get("FORTIGATE_MOCK")
    if forced_mock is None or forced_mock == "":
        # Auto: fall back to mock whenever we lack the info to reach a device.
        mock = not (host and api_token)
    else:
        mock = _as_bool(forced_mock)

    timeout_raw = os.environ.get("FORTIGATE_TIMEOUT", "15")
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 15.0

    return Settings(
        host=host,
        api_token=api_token,
        vdom=os.environ.get("FORTIGATE_VDOM", "root") or "root",
        verify_ssl=_as_bool(os.environ.get("FORTIGATE_VERIFY_SSL"), default=False),
        timeout=timeout,
        mock=mock,
    )
