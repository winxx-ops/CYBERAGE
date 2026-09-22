"""Cookie Security Analyzer for CyberAge."""

from typing import List
from urllib.parse import urlparse
from app.engine.models import Confidence, Finding, Severity

class CookieSecurityAnalyzer:
    SESSIONS = {"session", "sess", "phpsessid", "jsessionid", "token", "auth", "jwt"}

    def analyze(self, url: str, raw_response) -> List[Finding]:
        findings: List[Finding] = []
        if not raw_response:
            return findings

        raw_cookies = []
        if hasattr(raw_response, "raw") and hasattr(raw_response.raw, "headers"):
            raw_cookies = raw_response.raw.headers.getlist("Set-Cookie")
        if not raw_cookies and "set-cookie" in raw_response.headers:
            raw_cookies = [raw_response.headers["set-cookie"]]

        scheme = urlparse(url).scheme.lower()
        for raw in raw_cookies:
            tokens = [t.strip() for t in raw.split(";") if t.strip()]
            if not tokens:
                continue
            name = tokens[0].split("=")[0].strip() if "=" in tokens[0] else tokens[0]
            clean = name.lower().replace("-", "").replace("_", "")
            is_session = any(s in clean for s in self.SESSIONS)
            elevated = Severity.HIGH if is_session else Severity.MEDIUM

            attrs = {t.split("=")[0].strip().lower(): (t.split("=")[1].strip() if "=" in t else True) for t in tokens[1:]}

            if "secure" not in attrs:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing 'Secure' Attribute",
                    severity=elevated if scheme == "https" else Severity.MEDIUM,
                    category="Insecure State Management", owasp_id="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-614", evidence=f"Directive: {raw}",
                    recommendation="Append '; Secure' to ensure transport solely over encrypted channels."
                ))

            if "httponly" not in attrs:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing 'HttpOnly' Attribute",
                    severity=elevated, category="Insecure State Management",
                    owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-1004",
                    evidence=f"Directive: {raw}",
                    recommendation="Append '; HttpOnly' to prevent script accessibility."
                ))

            if "samesite" not in attrs:
                findings.append(Finding(
                    title=f"Cookie '{name}' Missing 'SameSite' Attribute",
                    severity=Severity.LOW if not is_session else Severity.MEDIUM,
                    category="Broken Access Control", owasp_id="A01:2021-Broken Access Control",
                    cwe_id="CWE-1275", evidence=f"Directive: {raw}",
                    recommendation="Set '; SameSite=Lax' or 'Strict' to mitigate CSRF."
                ))

        return findings
