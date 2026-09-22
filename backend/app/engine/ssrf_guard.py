"""CyberAge SSRF (Server-Side Request Forgery) Defense Engine."""

import ipaddress
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

AUTHORIZED_LOCAL_LABS = {
    "localhost",
    "127.0.0.1",
    "localhost:3000",
    "127.0.0.1:3000",
    "localhost:8080",
    "127.0.0.1:8080",
    "localhost:8000",
    "127.0.0.1:8000",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class SSRFGuard:
    @classmethod
    def is_safe_target(cls, url: str) -> Tuple[bool, Optional[str], Optional[str]]:
        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = f"http://{clean_url}"

        parsed = urlparse(clean_url)
        hostname = parsed.hostname
        netloc = (parsed.netloc or "").lower()

        if not hostname:
            return False, None, "Target URL lacks a valid domain name or hostname."

        if netloc in AUTHORIZED_LOCAL_LABS or hostname.lower() in ("localhost", "127.0.0.1"):
            return True, "127.0.0.1", None

        if hostname.lower() in ("metadata.google.internal", "169.254.169.254"):
            return False, None, "Access denied: Cloud metadata endpoints are prohibited."

        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ip_str = addr_info[0][4][0]
            target_ip = ipaddress.ip_address(ip_str)
        except socket.gaierror as e:
            return False, None, f"DNS resolution failed for '{hostname}': {e.strerror}"
        except Exception as e:
            return False, None, f"Network inspection error: {str(e)}"

        for blocked_net in BLOCKED_IP_NETWORKS:
            if target_ip in blocked_net:
                return (
                    False,
                    ip_str,
                    f"Access restricted: Target resolves to internal IP space ({ip_str}) to prevent SSRF.",
                )

        return True, ip_str, None