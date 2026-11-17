"""IP geolocation is offline-only: no observed IP address leaves the machine."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

from scanner import ip_geo  # noqa: E402


def geo(ip: str) -> dict:
    return asyncio.run(ip_geo.geolocate_ip(ip))


def test_no_http_client_imported():
    # Removing the online lookup must also drop the HTTP client dependency.
    assert not hasattr(ip_geo, "httpx")


def test_private_ip_is_local():
    result = geo("192.168.1.5")
    assert result["jurisdiction"] == "LOCAL"
    assert result["source"] == "local"


def test_loopback_is_local():
    assert geo("127.0.0.1")["country_code"] == "LOCAL"


def test_known_range_resolves_offline():
    result = geo("54.1.2.3")  # AWS 54.0.0.0/8 (US) in data/ip_ranges.json
    assert result["source"] == "known_ranges"
    assert result["jurisdiction"] == "US"


def test_unknown_public_ip_stays_unknown():
    result = geo("8.8.8.8")  # public, not in the bundled known ranges
    assert result["source"] == "offline-unknown"
    assert result["jurisdiction"] == "Unknown"


def test_source_is_never_an_online_service():
    for ip in ["8.8.8.8", "1.1.1.1", "203.0.113.9", "198.51.100.9"]:
        assert geo(ip)["source"] in {"local", "known_ranges", "offline-unknown"}
