"""Look up the country of public IPs using a GeoLite2-format (.mmdb) database."""

import os
from functools import lru_cache

import geoip2.database
import geoip2.errors


@lru_cache(maxsize=4)
def _reader(path: str) -> geoip2.database.Reader | None:
    if not path or not os.path.exists(path):
        return None
    return geoip2.database.Reader(path)


def country_for_ip(ip: str, db_path: str | None = None) -> str | None:
    reader = _reader(db_path or os.environ.get("GEOIP_DB_PATH", ""))
    if reader is None:
        return None
    try:
        return reader.country(ip).country.name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None


def countries_for_ips(ips: list[str], db_path: str | None = None) -> str:
    """Return e.g. 'United States (45.33.32.156)'; empty string if nothing found."""
    parts = []
    for ip in ips:
        country = country_for_ip(ip, db_path)
        if country:
            parts.append(f"{country} ({ip})")
    return ", ".join(parts)
