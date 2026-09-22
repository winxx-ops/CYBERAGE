"""TLS/SSL Analyzer for CyberAge."""

import socket
import ssl
from datetime import datetime, timezone
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.engine.models import Confidence, Finding, Severity

class TLSSecurityAnalyzer:
    LEGACY = {"TLSv1.0": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}

    def analyze(self, scope) -> List[Finding]:
        findings: List[Finding] = []
        if scope.scheme != "https":
            findings.append(Finding(
                title="Unencrypted Transport Protocol (HTTP In Use)",
                severity=Severity.HIGH, category="Cryptographic Failures",
                owasp_id="A02:2021-Cryptographic Failures", cwe_id="CWE-319",
                evidence="Application endpoints transmit in cleartext.",
                recommendation="Enforce HTTPS across all application routes."
            ))
            return findings

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((scope.hostname, scope.port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=scope.hostname) as ssock:
                    raw_cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(raw_cert, default_backend())
                    now = datetime.now(timezone.utc)
                    if now > x509_cert.not_valid_after_utc:
                        findings.append(Finding(
                            title="Expired TLS Certificate", severity=Severity.CRITICAL,
                            category="Cryptographic Failures", owasp_id="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-298", evidence=f"Expired on {x509_cert.not_valid_after_utc.isoformat()}.",
                            recommendation="Renew the certificate immediately."
                        ))
                    elif (x509_cert.not_valid_after_utc - now).days <= 15:
                        findings.append(Finding(
                            title="TLS Certificate Nearing Expiration", severity=Severity.MEDIUM,
                            category="Cryptographic Failures", owasp_id="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-298", evidence="Expires in <= 15 days.",
                            recommendation="Renew certificate before service disruption."
                        ))
        except ssl.SSLCertVerificationError as err:
            findings.append(Finding(
                title="TLS Certificate Validation Failure", severity=Severity.CRITICAL,
                category="Cryptographic Failures", owasp_id="A02:2021-Cryptographic Failures",
                cwe_id="CWE-295", evidence=f"Verification failure: {err.verify_message}",
                recommendation="Deploy a certificate issued by a public Certificate Authority."
            ))
        except Exception:
            pass

        # Protocol probe
        for name, ver in self.LEGACY.items():
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
            c.minimum_version, c.maximum_version = ver, ver
            try:
                with socket.create_connection((scope.hostname, scope.port), timeout=3) as sock:
                    with c.wrap_socket(sock, server_hostname=scope.hostname) as ssock:
                        if ssock.version():
                            findings.append(Finding(
                                title=f"Deprecated Protocol Supported: {name}",
                                severity=Severity.HIGH, category="Cryptographic Failures",
                                owasp_id="A02:2021-Cryptographic Failures", cwe_id="CWE-326",
                                evidence=f"Negotiated connection via {name}.",
                                recommendation=f"Disable {name} and require TLSv1.2 or TLSv1.3."
                            ))
            except Exception:
                pass

        return findings
