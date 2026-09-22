"""CyberAge Passive Subdomain Discovery Engine (Certificate Transparency Logs)."""

from typing import List
import requests

from app.config import config


class SubdomainDiscoveryEngine:
    @staticmethod
    def discover(base_domain: str) -> List[str]:
        """
        Queries public Certificate Transparency (CT) logs to enumerate
        registered subdomains for the target apex domain.
        """
        if not base_domain or "." not in base_domain or base_domain in ("localhost", "127.0.0.1"):
            return []

        subdomains = set()
        url = f"https://crt.sh/?q=%25.{base_domain}&output=json"

        try:
            resp = requests.get(url, timeout=5.0, headers={"User-Agent": config.USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(base_domain):
                            subdomains.add(sub)
        except Exception:
            pass

        return sorted(list(subdomains))[:25]