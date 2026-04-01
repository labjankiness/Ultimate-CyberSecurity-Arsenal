"""
Offline IP geolocation lookup for the SSH Honeypot.

Uses a hardcoded mapping of common IP ranges for demo purposes.
For production use, download a free GeoIP CSV database (see README).

Usage:
    from geo_lookup import lookup_ip
    info = lookup_ip("203.0.113.5")
    # {"country": "United States", "city": "Unknown", "lat": 37.751, "lon": -97.822}
"""

import os
import csv
from typing import Optional


# Hardcoded IP-to-country mapping for common ranges and demo data.
# Uses IANA-assigned documentation ranges (RFC 5737) and common attacker ranges.
_IP_RANGES: list[tuple[str, str, str]] = [
    # (prefix, country, city)
    # RFC 5737 documentation ranges
    ("203.0.113.", "United States", "Los Angeles"),
    ("198.51.100.", "United States", "New York"),
    ("192.0.2.", "United States", "Chicago"),
    # Common attacker source ranges (demo)
    ("185.220.", "Russia", "Moscow"),
    ("185.234.", "Russia", "St. Petersburg"),
    ("103.224.", "China", "Beijing"),
    ("103.136.", "China", "Shanghai"),
    ("91.215.", "Ukraine", "Kyiv"),
    ("45.33.", "Germany", "Frankfurt"),
    ("45.55.", "Netherlands", "Amsterdam"),
    ("46.101.", "United Kingdom", "London"),
    ("104.248.", "Singapore", "Singapore"),
    ("139.59.", "India", "Mumbai"),
    ("178.128.", "United States", "San Francisco"),
    ("167.99.", "United States", "Dallas"),
    ("68.183.", "Canada", "Toronto"),
    ("157.245.", "Brazil", "Sao Paulo"),
    ("206.189.", "Australia", "Sydney"),
    ("165.22.", "Japan", "Tokyo"),
    ("116.203.", "South Korea", "Seoul"),
    ("5.189.", "Iran", "Tehran"),
    ("41.215.", "Nigeria", "Lagos"),
    ("196.216.", "South Africa", "Cape Town"),
    ("77.247.", "Romania", "Bucharest"),
    ("185.100.", "France", "Paris"),
    # Private/internal
    ("192.168.", "Local Network", "Internal"),
    ("10.", "Local Network", "Internal"),
    ("172.16.", "Local Network", "Internal"),
    ("127.", "Localhost", "Loopback"),
]

# Country coordinates for map display
_COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "United States": (37.751, -97.822),
    "Russia": (55.751, 37.618),
    "China": (39.904, 116.407),
    "Ukraine": (50.450, 30.523),
    "Germany": (52.520, 13.405),
    "Netherlands": (52.367, 4.904),
    "United Kingdom": (51.507, -0.128),
    "Singapore": (1.352, 103.820),
    "India": (19.076, 72.878),
    "Canada": (43.651, -79.347),
    "Brazil": (-23.550, -46.633),
    "Australia": (-33.868, 151.209),
    "Japan": (35.682, 139.759),
    "South Korea": (37.567, 126.978),
    "Iran": (35.689, 51.389),
    "Nigeria": (6.525, 3.379),
    "South Africa": (-33.926, 18.424),
    "Romania": (44.426, 26.103),
    "France": (48.857, 2.352),
    "Local Network": (0.0, 0.0),
    "Localhost": (0.0, 0.0),
}


def lookup_ip(ip: str) -> dict:
    """Look up geographic location for an IP address.

    Uses the local hardcoded database. Falls back to "Unknown" if
    no match is found.

    Args:
        ip: IPv4 address string.

    Returns:
        Dict with: country, city, lat, lon.
    """
    for prefix, country, city in _IP_RANGES:
        if ip.startswith(prefix):
            lat, lon = _COUNTRY_COORDS.get(country, (0.0, 0.0))
            return {
                "country": country,
                "city": city,
                "lat": lat,
                "lon": lon,
            }

    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
    }


if __name__ == "__main__":
    test_ips = [
        "203.0.113.5",
        "185.220.101.33",
        "103.224.182.5",
        "192.168.1.10",
        "8.8.8.8",
    ]
    print("=== Geo Lookup Test ===\n")
    for ip in test_ips:
        info = lookup_ip(ip)
        print(f"  {ip:<20} → {info['country']}, {info['city']} ({info['lat']}, {info['lon']})")
