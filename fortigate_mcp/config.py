"""Runtime configuration loaded from environment variables.

The server reads its connection settings from the environment so that no
credentials ever live in code. See ``.env.example`` for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; env vars still work without it
    def load_dotenv(*_args, **_kwargs) -> bool:  # type: ignore[misc]
        return False


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(RuntimeError):
    """Raised when required connection settings are missing."""


@dataclass(frozen=True)
class Settings:
    host: str
    api_token: str
    vdom: str
    verify_ssl: bool
    timeout: float

    @property
    def base_url(self) -> str:
        """Return the https base URL for the FortiOS REST API."""
        host = self.host.strip().rstrip("/")
        if host.startswith("http://") or host.startswith("https://"):
            return host
        return f"https://{host}"


def load_settings() -> Settings:
    # Load .env from the current working directory / project root if present.
    # Real environment variables always take precedence over .env values.
    load_dotenv(override=False)

    host = (os.environ.get("FORTIGATE_HOST") or "").strip()
    # Accept FORTIGATE_TOKEN as an alias for FORTIGATE_API_TOKEN.
    api_token = (
        os.environ.get("FORTIGATE_API_TOKEN")
        or os.environ.get("FORTIGATE_TOKEN")
        or ""
    ).strip()

    missing = [
        name
        for name, value in (("FORTIGATE_HOST", host), ("FORTIGATE_API_TOKEN", api_token))
        if not value
    ]
    if missing:
        raise ConfigError(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + ". Set them (see .env.example) to connect to the FortiGate."
        )

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
    )
