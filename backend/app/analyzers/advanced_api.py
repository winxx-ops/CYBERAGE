"""CyberAge Advanced API & CORS Security Analyzer."""

from typing import List
from urllib.parse import urljoin
import requests

from app.config import config
from app.engine.models import Confidence, Finding, Severity


class AdvancedAPIAnalyzer:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def audit_all(self) -> List[Finding]:
        findings = []
        findings.extend(self._audit_cors())
        findings.extend(self._audit_graphql())
        return findings

    def _audit_cors(self) -> List[Finding]:
        findings = []
        evil_origin = "https://evil-attacker-cyberage.com"

        try:
            resp = self.session.get(
                self.base_url,
                headers={"Origin": evil_origin},
                timeout=config.DEFAULT_TIMEOUT_SEC,
                verify=False,
            )
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower().strip()

            # 1. Arbitrary Origin Reflection with Credentials (Critical)
            if allow_origin == evil_origin and allow_creds == "true":
                findings.append(Finding(
                    title="Critical CORS Misconfiguration: Arbitrary Origin & Credentials Allowed",
                    severity=Severity.CRITICAL,
                    category="Broken Access Control",
                    owasp_id="A01:2021-Broken Access Control",
                    cwe_id="CWE-942",
                    evidence=f"Reflected '{allow_origin}' with Access-Control-Allow-Credentials: true",
                    recommendation="Never reflect untrusted Origins dynamically when credentials are supported. Maintain an explicit whitelist.",
                    confidence=Confidence.HIGH,
                ))
            # 2. Wildcard with Credentials
            elif allow_origin == "*" and allow_creds == "true":
                findings.append(Finding(
                    title="Insecure CORS Policy: Wildcard Origin with Credentials Enabled",
                    severity=Severity.HIGH,
                    category="Broken Access Control",
                    owasp_id="A01:2021-Broken Access Control",
                    cwe_id="CWE-942",
                    evidence="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                    recommendation="Revoke wildcard allowances when transmitting authenticated sessions.",
                    confidence=Confidence.HIGH,
                ))
            # 3. Excessive Wildcard Sharing
            elif allow_origin == "*":
                findings.append(Finding(
                    title="Permissive CORS Policy (Wildcard Origin Allowed)",
                    severity=Severity.LOW,
                    category="Security Misconfiguration",
                    owasp_id="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-942",
                    evidence="Access-Control-Allow-Origin header is set to wildcard (*).",
                    recommendation="Restrict CORS origins if this endpoint serves non-public or sensitive resources.",
                    confidence=Confidence.MEDIUM,
                ))
        except Exception:
            pass

        return findings

    def _audit_graphql(self) -> List[Finding]:
        findings = []
        graphql_routes = ["graphql", "api/graphql", "v1/graphql"]
        introspection_query = {"query": "{__schema{types{name}}}"}

        for route in graphql_routes:
            target = urljoin(self.base_url, route)
            try:
                resp = self.session.post(
                    target,
                    json=introspection_query,
                    timeout=3.5,
                    verify=False,
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings.append(Finding(
                        title="GraphQL Schema Introspection Enabled in Production",
                        severity=Severity.MEDIUM,
                        category="Information Disclosure",
                        owasp_id="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-200",
                        evidence=f"Introspection query succeeded at: {target}",
                        recommendation="Disable GraphQL schema introspection in production environments to prevent automated object mapping.",
                        confidence=Confidence.HIGH,
                    ))
                    break
            except Exception:
                continue

        return findings