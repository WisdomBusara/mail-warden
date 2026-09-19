"""DNS blocklist (RBL) lookups, e.g. Spamhaus ZEN. Requires dnspython."""
from __future__ import annotations

import ipaddress

try:
    import dns.resolver
    _HAVE_DNS = True
except ImportError:
    _HAVE_DNS = False

_CACHE: dict[tuple[str, str], bool] = {}

# Private/reserved ranges are never worth querying and would false-positive
# against most public DNSBLs if they somehow matched.
_SKIP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in _SKIP_NETWORKS)


def is_listed(ip: str, zone: str = "zen.spamhaus.org", timeout: float = 2.0) -> bool:
    """Returns True if `ip` is listed on the given DNSBL zone. Fails open (False) on any error."""
    if not _HAVE_DNS or not _is_public(ip):
        return False

    cache_key = (ip, zone)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    try:
        octets = ip.split(".")
        query = ".".join(reversed(octets)) + "." + zone
        dns.resolver.resolve(query, "A", lifetime=timeout)
        _CACHE[cache_key] = True
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        _CACHE[cache_key] = False
        return False
    except Exception:
        # Timeout, no resolver, network unreachable, etc: don't let DNSBL
        # unavailability affect scoring.
        return False
