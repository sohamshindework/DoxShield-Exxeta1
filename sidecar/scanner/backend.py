"""Scanner backend selection: real macOS scanners vs. synthetic fixtures.

Pick the backend with the environment variable ``DOXSHIELD_BACKEND``:

- ``macos``   : run the real system scanners (default; macOS only).
- ``fixture`` : serve synthetic, clearly-simulated data (CI, Linux, demos).

The two backends are fully separate classes. ``FixtureBackend`` contains no
system-scanning code at all, so selecting it cannot accidentally read the real
machine. ``MacOSBackend`` imports the platform scanners lazily, so the fixture
backend never needs them (and they are never imported on Linux/CI).
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"

VALID_BACKENDS = ("macos", "fixture")


class ScannerBackend(ABC):
    """Common interface over the four data sources DoxShield scans."""

    name: str = "abstract"

    @property
    def is_synthetic(self) -> bool:
        """True when results are simulated and must be labelled as such."""
        return False

    @abstractmethod
    def scan_apps(self) -> list: ...

    @abstractmethod
    def get_permissions(self) -> dict: ...

    @abstractmethod
    async def get_connections(self) -> list[dict]: ...

    @abstractmethod
    def scan_cookies(self) -> dict: ...

    @abstractmethod
    def check_fda(self) -> bool: ...

    @abstractmethod
    def find_browser_profiles(self) -> dict: ...

    @abstractmethod
    def connection_history(self) -> list[dict]: ...


class MacOSBackend(ScannerBackend):
    """Delegates to the existing macOS scanners, unchanged. Imports are lazy so
    this module stays importable on non-macOS hosts."""

    name = "macos"

    def scan_apps(self) -> list:
        from scanner.apps import scan_installed_apps
        return scan_installed_apps()

    def get_permissions(self) -> dict:
        from scanner.permissions import get_app_permissions
        return get_app_permissions()

    async def get_connections(self) -> list[dict]:
        from scanner.network import get_active_connections
        return await get_active_connections()

    def scan_cookies(self) -> dict:
        from scanner.cookies import scan_all_cookies
        return scan_all_cookies()

    def check_fda(self) -> bool:
        from scanner.cookies import check_fda
        return check_fda()

    def find_browser_profiles(self) -> dict:
        from scanner.cookies import find_browser_profiles
        return find_browser_profiles()

    def connection_history(self) -> list[dict]:
        from scanner.network import connection_history
        return list(connection_history)


class FixtureBackend(ScannerBackend):
    """Serves synthetic data from JSON fixtures. Does no system access."""

    name = "fixture"

    def __init__(self, fixture_dir: Path = FIXTURE_DIR) -> None:
        self._dir = Path(fixture_dir)

    @property
    def is_synthetic(self) -> bool:
        return True

    def _load(self, filename: str) -> Any:
        with open(self._dir / filename) as f:
            return json.load(f)

    def scan_apps(self) -> list:
        from scanner.apps import AppInfo
        return [AppInfo(**a) for a in self._load("apps.json")]

    def get_permissions(self) -> dict:
        return self._load("permissions.json")

    async def get_connections(self) -> list[dict]:
        return self._load("connections.json")

    def scan_cookies(self) -> dict:
        return self._load("cookies.json")

    def check_fda(self) -> bool:
        return bool(self.scan_cookies().get("fda_granted", True))

    def find_browser_profiles(self) -> dict:
        return {name: [] for name in self.scan_cookies().get("browsers_found", [])}

    def connection_history(self) -> list[dict]:
        return self._load("connections.json")


_BACKENDS = {"macos": MacOSBackend, "fixture": FixtureBackend}
_instance: ScannerBackend | None = None


def get_backend() -> ScannerBackend:
    """Return the configured backend (cached). Reads ``DOXSHIELD_BACKEND`` once."""
    global _instance
    if _instance is None:
        choice = os.getenv("DOXSHIELD_BACKEND", "macos").strip().lower()
        if choice not in _BACKENDS:
            raise ValueError(
                f"DOXSHIELD_BACKEND must be one of {list(VALID_BACKENDS)}, got {choice!r}"
            )
        _instance = _BACKENDS[choice]()
    return _instance


def reset_backend() -> None:
    """Testing helper: clear the cached backend so the env var is re-read."""
    global _instance
    _instance = None
