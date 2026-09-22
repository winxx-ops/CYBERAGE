"""CyberAge Content & Directory Discovery Engine (Gobuster-Style Path Enumeration)."""

import concurrent.futures
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin
import requests

from app.config import config
from app.engine.models import Confidence, Finding, Severity

TARGET_PATHS = [
    ("robots.txt", "Crawling Policy File"),
    ("sitemap.xml", "SEO / Architecture Sitemap"),
    (".env", "Exposed Environment Configuration"),
    (".git/HEAD", "Exposed Git Version Control Repository"),
    (".gitignore", "Exposed Git Configuration"),
    ("admin/", "Administrative Control Portal"),
    ("admin/login", "Admin Authentication Endpoint"),
    ("administrator/", "Administrative Portal Variant"),
    ("login", "Authentication Gateway"),
    ("dashboard", "User/Admin Dashboard"),
    ("api/", "API Gateway Root"),
    ("api/v1/", "API v1 Endpoint Directory"),
    ("swagger.json", "OpenAPI / Swagger Definition"),
    ("docs", "Interactive API Documentation"),
    ("backup.zip", "Database / Source Backup Archive"),
    ("backup.sql", "Raw SQL Dump Archive"),
    ("config.php", "PHP Configuration File"),
    ("config.json", "JSON Configuration File"),
    ("test/", "Staging / Test Environment Directory"),
    ("debug", "Debug Interface / Endpoint"),
]


@dataclass
class DiscoveredPath:
    path: str
    url: str
    status_code: int
    content_length: int
    redirect_location: Optional[str] = None
    description: str = ""
    is_sensitive: bool = False


class ContentDiscoveryEngine:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def run_discovery(self) -> Tuple[List[DiscoveredPath], List[Finding]]:
        discovered: List[DiscoveredPath] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            future_to_path = {
                executor.submit(self._probe_path, path, desc): (path, desc)
                for path, desc in TARGET_PATHS
            }
            for future in concurrent.futures.as_completed(future_to_path):
                result = future.result()
                if result:
                    discovered.append(result)

        discovered.sort(key=lambda x: (x.status_code != 200, x.status_code))
        findings = self._audit_exposed_paths(discovered)
        return discovered, findings

    def _probe_path(self, path: str, desc: str) -> Optional[DiscoveredPath]:
        target_url = urljoin(self.base_url, path)
        try:
            resp = self.session.head(target_url, timeout=3.0, allow_redirects=False, verify=False)
            if resp.status_code in (400, 405):
                resp = self.session.get(target_url, timeout=3.0, allow_redirects=False, verify=False, stream=True)

            code = resp.status_code
            if code in (200, 204, 301, 302, 307, 308, 401, 403):
                content_len = int(resp.headers.get("Content-Length", 0))
                redirect_target = resp.headers.get("Location")

                is_sensitive = any(
                    sig in path.lower()
                    for sig in (".env", ".git", "backup", "config", "swagger", "debug")
                )

                return DiscoveredPath(
                    path="/" + path,
                    url=target_url,
                    status_code=code,
                    content_length=content_len,
                    redirect_location=redirect_target,
                    description=desc,
                    is_sensitive=is_sensitive,
                )
        except Exception:
            pass
        return None

    def _audit_exposed_paths(self, discovered: List[DiscoveredPath]) -> List[Finding]:
        findings: List[Finding] = []

        for item in discovered:
            if item.status_code == 200:
                if ".git" in item.path:
                    findings.append(Finding(
                        title="Critical Git Repository Disclosure",
                        severity=Severity.CRITICAL,
                        category="Information Disclosure",
                        owasp_id="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-538",
                        evidence=f"Exposed Git repository accessible at: {item.url} (Status: 200 OK)",
                        recommendation="Block web access to the '.git' directory immediately in your web server configuration.",
                        confidence=Confidence.HIGH,
                    ))
                elif ".env" in item.path:
                    findings.append(Finding(
                        title="Sensitive Environment File (.env) Publicly Exposed",
                        severity=Severity.CRITICAL,
                        category="Security Misconfiguration",
                        owasp_id="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-552",
                        evidence=f"Environment configuration file accessible at: {item.url} (Status: 200 OK)",
                        recommendation="Remove '.env' files from the web root and configure server rewrite rules to deny dotfiles.",
                        confidence=Confidence.HIGH,
                    ))
                elif "backup" in item.path:
                    findings.append(Finding(
                        title="Backup File or Database Archive Publicly Accessible",
                        severity=Severity.HIGH,
                        category="Information Disclosure",
                        owasp_id="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-530",
                        evidence=f"Backup artifact found at: {item.url} (Status: 200 OK)",
                        recommendation="Store backup archives outside the public web root directory.",
                        confidence=Confidence.HIGH,
                    ))
                elif "swagger" in item.path or "docs" in item.path:
                    findings.append(Finding(
                        title="API Documentation / Schema Publicly Exposed",
                        severity=Severity.LOW,
                        category="Information Disclosure",
                        owasp_id="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-200",
                        evidence=f"API definitions exposed at: {item.url}",
                        recommendation="Ensure internal APIs and schema definitions require authentication in production.",
                        confidence=Confidence.HIGH,
                    ))

        return findings