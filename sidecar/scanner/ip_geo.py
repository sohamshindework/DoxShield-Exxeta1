"""Offline IP geolocation.

Privacy rule: no observed IP address ever leaves the machine. Lookups use only
local data — private/loopback detection and the bundled known-provider ranges
(``data/ip_ranges.json``). Addresses not covered are reported as Unknown rather
than sent to any third-party geolocation service.
"""
import fnmatch
import ipaddress
import json
import time
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

_ip_ranges: dict = {}
_tracker_domains: list = []


def _load_ip_ranges():
    global _ip_ranges
    try:
        with open(DATA_DIR / "ip_ranges.json") as f:
            _ip_ranges = json.load(f)
    except Exception:
        _ip_ranges = {}


def _load_trackers():
    global _tracker_domains
    try:
        with open(DATA_DIR / "known_trackers.json") as f:
            _tracker_domains = json.load(f)
    except Exception:
        _tracker_domains = []


_load_ip_ranges()
_load_trackers()

# Memory cache: {ip: (result_dict, timestamp)}
_cache: dict[str, tuple[dict, float]] = {}
CACHE_TTL = 3600  # 1 hour


def check_known_ranges(ip: str) -> dict | None:
    """Check if IP falls within known cloud provider ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for jurisdiction, providers in _ip_ranges.items():
        if not isinstance(providers, dict):
            continue
        for provider, cidrs in providers.items():
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        return {
                            "country": jurisdiction,
                            "country_code": jurisdiction,
                            "org": provider,
                            "jurisdiction": jurisdiction,
                            "source": "known_ranges",
                        }
                except ValueError:
                    continue
    return None


async def geolocate_ip(ip: str) -> dict:
    """Geolocate an IP. Returns country, country_code, org, jurisdiction."""
    if ip in _cache:
        result, ts = _cache[ip]
        if time.time() - ts < CACHE_TTL:
            return result

    # Private / loopback
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            result = {
                "country": "Local",
                "country_code": "LOCAL",
                "org": "Local Network",
                "jurisdiction": "LOCAL",
                "source": "local",
            }
            _cache[ip] = (result, time.time())
            return result
    except ValueError:
        pass

    # Known ranges (no network call)
    known = check_known_ranges(ip)
    if known:
        _cache[ip] = (known, time.time())
        return known

    # No online lookup: an address we cannot resolve offline stays Unknown.
    # This is deliberate — sending the IP to a remote service would leak the
    # very network flow DoxShield is here to protect.
    result = {
        "country": "Unknown",
        "country_code": "XX",
        "org": "Unknown",
        "jurisdiction": "Unknown",
        "source": "offline-unknown",
    }
    _cache[ip] = (result, time.time())
    return result


def _map_jurisdiction(country_code: str) -> str:
    eu_countries = {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "RO", "SK", "SI", "ES", "SE", "NO", "IS", "LI", "CH",
    }
    if country_code in eu_countries:
        return "EU"
    elif country_code == "US":
        return "US"
    elif country_code == "CN":
        return "CN"
    elif country_code == "RU":
        return "RU"
    elif country_code == "GB":
        return "UK"
    elif country_code in ("CA", "AU", "NZ"):
        return "FVEY"
    return "Other"


def check_domain_tracker(domain: str) -> dict | None:
    """Check if a domain matches a known tracker pattern."""
    domain = domain.lstrip(".")
    for tracker in _tracker_domains:
        pattern = tracker.get("pattern", "")
        clean_pattern = pattern.lstrip("*.")
        if fnmatch.fnmatch(domain, pattern) or domain == clean_pattern or domain.endswith("." + clean_pattern):
            return tracker
    return None
