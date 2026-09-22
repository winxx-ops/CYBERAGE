"""Form & Security Controls Analyzer for CyberAge."""

from typing import List
from urllib.parse import urlparse
from app.engine.models import Confidence, Finding, Severity

class FormSecurityAnalyzer:
    def analyze(self, forms: list, scope) -> List[Finding]:
        findings: List[Finding] = []
        for idx, form in enumerate(forms, start=1):
            method = form.method.upper()
            action_scheme = urlparse(form.action).scheme.lower() or scope.scheme

            if form.has_password_field and (action_scheme != "https" or scope.scheme != "https"):
                findings.append(Finding(
                    title=f"Cleartext Password Transmission in Form #{idx}",
                    severity=Severity.HIGH, category="Cryptographic Failures",
                    owasp_id="A02:2021-Cryptographic Failures", cwe_id="CWE-319",
                    evidence=f"Form on '{form.page_url}' submits password unencrypted.",
                    recommendation="Enforce HTTPS on the action destination and origin page."
                ))

            if method == "GET" and form.has_password_field:
                findings.append(Finding(
                    title=f"Sensitive Credentials Transmitted via HTTP GET in Form #{idx}",
                    severity=Severity.HIGH, category="Information Disclosure",
                    owasp_id="A05:2021-Security Misconfiguration", cwe_id="CWE-598",
                    evidence=f"Form on '{form.page_url}' uses GET with sensitive fields.",
                    recommendation="Change form submission method from GET to POST."
                ))

            if method in ("POST", "PUT", "DELETE") and not form.has_csrf_token:
                findings.append(Finding(
                    title=f"Potential CSRF Vulnerability in Form #{idx}",
                    severity=Severity.MEDIUM, category="Broken Access Control",
                    owasp_id="A01:2021-Broken Access Control", cwe_id="CWE-352",
                    evidence=f"State-changing {method} form submitting to '{form.action}' lacks an anti-CSRF token.",
                    recommendation="Implement unpredictable synchronizer tokens or validate Origin/Referer headers."
                ))

        return findings
