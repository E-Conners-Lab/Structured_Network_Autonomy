"""SSRF protection — validates outbound webhook URLs against RFC-1918, loopback, and link-local.

Called at startup/config time (not per-request). Uses synchronous DNS resolution
because it only runs during initialization.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Networks that must never be targets of outbound HTTP calls
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def validate_webhook_url(url: str) -> None:
    """Validate that a webhook URL is safe for outbound requests.

    Checks:
    1. Must use https:// scheme (http:// rejected)
    2. Resolved IP must not be in private, loopback, or link-local ranges
    3. Must not point to cloud metadata endpoints (169.254.169.254)

    Args:
        url: The URL to validate.

    Raises:
        ValueError: If the URL fails any safety check.
    """
    parsed = urlparse(str(url))

    if parsed.scheme != "https":
        raise ValueError(f"Webhook URL must use HTTPS, got {parsed.scheme}://")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has no hostname")

    # Resolve hostname to IP addresses
    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(
                    f"Webhook URL resolves to blocked address {ip} (in {network})"
                )
