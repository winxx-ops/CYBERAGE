"""Security Header Analyzer for CyberAge."""

import re
from typing import List
from app.engine.models import Confidence, Finding, Severity

class HeaderAnalyzer:
    def analyze(self, url: str, headers: dict) -> List[Finding]:
        findings: List[Finding] = []
        h = {k.lower(): v for k, v in headers.items()}

        # CSP
        csp = h.get("content-security-policy")
        if not csp:
            findings.append(Finding(
                title="Missing Content-Security-Policy",
                severity=Severity.MEDIUM, category="Security Misconfiguration",
                owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-693",
                evidence="Content-Security-Policy header is absent.",
                recommendation="Define an authorized CSP restricting script and object sources."
            ))
        elif "'unsafe-inline'" in csp:
            findings.append(Finding(
                title="Weak CSP: 'unsafe-inline' Detected",
                severity=Severity.MEDIUM, category="Security Misconfiguration",
                owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-1021",
                evidence=f"CSP contains unsafe-inline: {csp}",
                recommendation="Utilize script nonces or hashes instead of 'unsafe-inline'."
            ))

        # HSTS
        if url.startswith("https://"):
            hsts = h.get("strict-transport-security")
            if not hsts:
                findings.append(Finding(
                    title="Missing Strict-Transport-Security (HSTS)",
                    severity=Severity.MEDIUM, category="Cryptographic Failures",
                    owasp_id="A02:2021-Cryptographic Failures", cwe_id="CWE-319",
                    evidence="No Strict-Transport-Security header on HTTPS endpoint.",
                    recommendation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
                ))

        # Clickjacking & Sniffing
        if not h.get("x-frame-options") and "frame-ancestors" not in h.get("content-security-policy", ""):
            findings.append(Finding(
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                severity=Severity.LOW, category="Security Misconfiguration",
                owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-1021",
                evidence="X-Frame-Options and frame-ancestors are absent.",
                recommendation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
            ))

        if "nosniff" not in h.get("x-content-type-options", "").lower():
            findings.append(Finding(
                title="Missing or Incomplete X-Content-Type-Options",
                severity=Severity.LOW, category="Security Misconfiguration",
                owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-693",
                evidence="X-Content-Type-Options header absent or lacks 'nosniff'.",
                recommendation="Configure 'X-Content-Type-Options: nosniff'."
            ))

        # Leaks
        for banner, title in [("server", "Web Server Banner"), ("x-powered-by", "Technology Fingerprint")]:
            if h.get(banner):
                findings.append(Finding(
                    title=f"Information Disclosure via {title}",
                    severity=Severity.INFORMATIONAL, category="Information Disclosure",
                    owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-200",
                    evidence=f"Exposed via '{banner}': {h[banner]}",
                    recommendation=f"Suppress the '{banner}' header in production."
                ))

        return findings
