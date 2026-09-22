# setup_cyberage.py
import os

files = {
    "backend/requirements.txt": """requests>=2.31.0
beautifulsoup4>=4.12.0
cryptography>=42.0.0
pydantic>=2.5.0
fastapi>=0.110.0
uvicorn>=0.28.0
python-jose>=3.3.0
passlib>=1.7.4
pytest>=8.0.0
""",

    "backend/app/__init__.py": "",
    "backend/app/engine/__init__.py": "",
    "backend/app/analyzers/__init__.py": "",

    "backend/app/config.py": """\"\"\"CyberAge Global Configuration & Author Attribution.\"\"\"

from dataclasses import dataclass

@dataclass(frozen=True)
class CyberAgeConfig:
    PROJECT_NAME: str = "CyberAge"
    VERSION: str = "2.0.0-PROD"
    AUTHOR_NAME: str = "Amit Kumar Mahato"
    GITHUB_URL: str = "https://github.com/winxx-ops"
    LINKEDIN_URL: str = "https://www.linkedin.com/in/amit-kumar-mahato-859206226"

    USER_AGENT: str = "CyberAge-Security-Engine/2.0 (+https://github.com/winxx-ops)"
    DEFAULT_TIMEOUT_SEC: float = 10.0
    MAX_CRAWL_PAGES: int = 15
    MAX_CRAWL_DEPTH: int = 2
    CRAWL_DELAY_SEC: float = 0.2

    JWT_SECRET: str = "cyberage-auth-secret-key-amit-kumar-mahato-2026"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

config = CyberAgeConfig()
""",

    "backend/app/engine/models.py": """\"\"\"Finding models and taxonomy classifications.\"\"\"

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    title: str
    severity: Severity
    category: str
    owasp_id: str
    cwe_id: str
    evidence: str
    recommendation: str
    confidence: Confidence = Confidence.HIGH
    details: Dict[str, Any] = field(default_factory=dict)
    cvss_score: Optional[float] = None
""",

    "backend/app/engine/validator.py": """\"\"\"CyberAge Scope Boundary & Target Validation Engine.\"\"\"

import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
import requests
from app.config import config

@dataclass
class RedirectHop:
    url: str
    status_code: int
    headers: dict

@dataclass
class TargetScope:
    raw_input: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    ip_address: Optional[str]
    base_domain: str
    path: str
    is_reachable: bool
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    final_destination: Optional[str] = None
    cross_domain_redirect: bool = False
    validation_error: Optional[str] = None

class TargetValidator:
    @classmethod
    def validate(cls, input_url: str) -> TargetScope:
        clean_input = input_url.strip()
        if not clean_input.startswith(("http://", "https://")):
            clean_input = f"https://{clean_input}"

        parsed = urlparse(clean_input)
        if not parsed.hostname:
            return TargetScope(
                raw_input=input_url, normalized_url=clean_input, scheme="", hostname="",
                port=0, ip_address=None, base_domain="", path="/", is_reachable=False,
                validation_error="Malformed URL: Missing valid hostname."
            )

        hostname = parsed.hostname.lower()
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        base_domain = cls._extract_base(hostname)

        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror as err:
            return TargetScope(
                raw_input=input_url, normalized_url=clean_input, scheme=scheme, hostname=hostname,
                port=port, ip_address=None, base_domain=base_domain, path=path, is_reachable=False,
                validation_error=f"DNS resolution failed: {err.strerror}"
            )

        normalized_url = urlunparse((scheme, f"{hostname}:{parsed.port}" if parsed.port else hostname, path, "", "", ""))
        scope = TargetScope(
            raw_input=input_url, normalized_url=normalized_url, scheme=scheme,
            hostname=hostname, port=port, ip_address=ip_address, base_domain=base_domain,
            path=path, is_reachable=False
        )
        cls._probe(scope)
        return scope

    @staticmethod
    def _extract_base(hostname: str) -> str:
        p = hostname.split(".")
        return ".".join(p[-2:]) if len(p) >= 2 else hostname

    @classmethod
    def _probe(cls, scope: TargetScope) -> None:
        session = requests.Session()
        session.headers.update({"User-Agent": config.USER_AGENT})
        t0 = time.perf_counter()
        try:
            resp = session.get(scope.normalized_url, timeout=config.DEFAULT_TIMEOUT_SEC, allow_redirects=True, verify=True)
            scope.is_reachable = True
            scope.status_code = resp.status_code
            scope.response_time_ms = round((time.perf_counter() - t0) * 1000, 2)
            scope.final_destination = resp.url
            for r in resp.history:
                scope.redirect_chain.append(RedirectHop(r.url, r.status_code, dict(r.headers)))
            if (urlparse(resp.url).hostname or "").lower() != scope.hostname:
                scope.cross_domain_redirect = True
        except requests.exceptions.SSLError:
            try:
                resp = session.get(scope.normalized_url, timeout=config.DEFAULT_TIMEOUT_SEC, allow_redirects=False, verify=False)
                scope.is_reachable = True
                scope.status_code = resp.status_code
                scope.validation_error = "TLS Certificate Untrusted or Self-Signed."
            except Exception as e:
                scope.is_reachable = False
                scope.validation_error = str(e)
        except Exception as e:
            scope.is_reachable = False
            scope.validation_error = str(e)
""",

    "backend/app/engine/spider.py": """\"\"\"CyberAge Polite Scoped Crawler.\"\"\"

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urldefrag, urljoin, urlparse
from bs4 import BeautifulSoup
import requests
from app.config import config
from app.engine.validator import TargetScope

@dataclass
class FormField:
    name: str
    field_type: str

@dataclass
class DiscoveredForm:
    page_url: str
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    has_password_field: bool = False
    has_csrf_token: bool = False

@dataclass
class CrawledPage:
    url: str
    status_code: int
    content_type: str
    response_headers: Dict[str, str]
    body: str

@dataclass
class CrawlResult:
    target: TargetScope
    visited_urls: Set[str] = field(default_factory=set)
    pages: List[CrawledPage] = field(default_factory=list)
    all_forms: List[DiscoveredForm] = field(default_factory=list)
    duration_sec: float = 0.0

class CyberSpider:
    IGNORED = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".tar", ".css"}
    CSRF_NAMES = {"csrf", "xsrf", "_csrf", "csrf_token", "authenticity_token", "nonce"}

    def __init__(self, scope: TargetScope):
        self.scope = scope
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def crawl(self) -> CrawlResult:
        t0 = time.perf_counter()
        visited: Set[str] = set()
        pages: List[CrawledPage] = []
        forms: List[DiscoveredForm] = []
        queue = deque([(self.scope.normalized_url, 0)])

        while queue and len(visited) < config.MAX_CRAWL_PAGES:
            url, depth = queue.popleft()
            clean = self._clean_url(url)
            if not clean or clean in visited or not self._in_scope(clean):
                continue

            visited.add(clean)
            time.sleep(config.CRAWL_DELAY_SEC)
            try:
                r = self.session.get(clean, timeout=config.DEFAULT_TIMEOUT_SEC, verify=False)
            except Exception:
                continue

            if not r.headers.get("Content-Type", "").lower().startswith("text/html"):
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            pages.append(CrawledPage(clean, r.status_code, r.headers.get("Content-Type", ""), dict(r.headers), r.text))

            for f in soup.find_all("form"):
                action = f.get("action", "")
                resolved = urljoin(clean, action) if action else clean
                method = f.get("method", "GET").upper()
                fields = []
                has_pwd, has_csrf = False, False

                for inp in f.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    ftype = inp.get("type", "text").lower()
                    if ftype == "password":
                        has_pwd = True
                    cname = name.lower().replace("-", "").replace("_", "")
                    if any(t in cname for t in self.CSRF_NAMES):
                        has_csrf = True
                    fields.append(FormField(name=name, field_type=ftype))

                forms.append(DiscoveredForm(clean, resolved, method, fields, has_pwd, has_csrf))

            if depth < config.MAX_CRAWL_DEPTH:
                for a in soup.find_all("a", href=True):
                    tgt = self._clean_url(urljoin(clean, a["href"]))
                    if tgt and self._in_scope(tgt) and tgt not in visited:
                        queue.append((tgt, depth + 1))

        return CrawlResult(self.scope, visited, pages, forms, round(time.perf_counter() - t0, 2))

    def _clean_url(self, raw: str) -> Optional[str]:
        d, _ = urldefrag(raw)
        p = urlparse(d)
        if p.scheme not in ("http", "https") or any(p.path.lower().endswith(e) for e in self.IGNORED):
            return None
        return f"{p.scheme}://{p.netloc}{p.path.rstrip('/') or '/'}"

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname
        return bool(host and host.lower() == self.scope.hostname)
""",

    "backend/app/engine/risk_scorer.py": """\"\"\"CyberAge Risk Engine.\"\"\"

from typing import Dict, List
from app.engine.models import Finding, Severity

class CyberRiskEngine:
    WEIGHTS = {
        Severity.CRITICAL: 4.0,
        Severity.HIGH: 2.5,
        Severity.MEDIUM: 1.5,
        Severity.LOW: 0.5,
        Severity.INFORMATIONAL: 0.1
    }

    CVSS_MAP = {
        Severity.CRITICAL: 9.3,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.3,
        Severity.LOW: 3.1,
        Severity.INFORMATIONAL: 0.0
    }

    @classmethod
    def compute(cls, findings: List[Finding]) -> Dict[str, any]:
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1
            if f.cvss_score is None:
                f.cvss_score = cls.CVSS_MAP[f.severity]

        raw = sum(cls.WEIGHTS[f.severity] for f in findings)
        return {
            "overall_score": round(min(10.0, raw), 2),
            "counts": {s.value: counts[s] for s in Severity},
            "total_findings": len(findings)
        }
""",

    "backend/app/engine/reporter.py": """\"\"\"CyberAge Report Artifact Generator.\"\"\"

import json

class CyberReporter:
    @staticmethod
    def save_json(filepath: str, data: dict) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
""",

    "backend/app/analyzers/headers_analyzer.py": """\"\"\"Security Header Analyzer for CyberAge.\"\"\"

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
""",

    "backend/app/analyzers/cookie_analyzer.py": """\"\"\"Cookie Security Analyzer for CyberAge.\"\"\"

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
""",

    "backend/app/analyzers/tls_analyzer.py": """\"\"\"TLS/SSL Analyzer for CyberAge.\"\"\"

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
""",

    "backend/app/analyzers/form_analyzer.py": """\"\"\"Form & Security Controls Analyzer for CyberAge.\"\"\"

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
""",

    "backend/app/analyzers/tech_detector.py": """\"\"\"Technology Stack Identification for CyberAge.\"\"\"

from dataclasses import dataclass
from typing import Dict, List, Set
from bs4 import BeautifulSoup

@dataclass
class DetectedTechnology:
    name: str
    category: str
    evidence: str

class CyberTechDetector:
    SERVERS = {
        "nginx": "Nginx", "apache": "Apache HTTP Server",
        "cloudflare": "Cloudflare CDN/Edge", "microsoft-iis": "Microsoft IIS"
    }

    FRAMEWORKS = {
        "express": "Express.js", "php": "PHP Runtime",
        "asp.net": "ASP.NET", "next.js": "Next.js"
    }

    def analyze(self, headers: dict, body: str) -> List[DetectedTechnology]:
        detected, seen = [], set()
        h = {k.lower(): v for k, v in headers.items()}

        s = h.get("server", "").lower()
        for k, v in self.SERVERS.items():
            if k in s and v not in seen:
                detected.append(DetectedTechnology(v, "Web Server / CDN", f"Server Header: {h.get('server')}"))
                seen.add(v)

        p = h.get("x-powered-by", "").lower()
        for k, v in self.FRAMEWORKS.items():
            if k in p and v not in seen:
                detected.append(DetectedTechnology(v, "Backend Runtime", f"X-Powered-By: {h.get('x-powered-by')}"))
                seen.add(v)

        if body:
            b_lower = body.lower()
            soup = BeautifulSoup(body, "html.parser")
            if "wp-content" in b_lower and "WordPress" not in seen:
                detected.append(DetectedTechnology("WordPress", "CMS", "wp-content assets"))
                seen.add("WordPress")
            if ("react" in b_lower or soup.find(id="__next")) and "React" not in seen:
                detected.append(DetectedTechnology("React", "Frontend Library", "React DOM signatures"))
                seen.add("React")

        return detected
""",

    "backend/app/api.py": """\"\"\"CyberAge Primary FastAPI Application.\"\"\"

import os
import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Dict
import requests

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from app.config import config
from app.engine.validator import TargetValidator
from app.engine.spider import CyberSpider
from app.engine.risk_scorer import CyberRiskEngine
from app.engine.reporter import CyberReporter

from app.analyzers.headers_analyzer import HeaderAnalyzer
from app.analyzers.cookie_analyzer import CookieSecurityAnalyzer
from app.analyzers.tls_analyzer import TLSSecurityAnalyzer
from app.analyzers.form_analyzer import FormSecurityAnalyzer
from app.analyzers.tech_detector import CyberTechDetector

app = FastAPI(
    title=config.PROJECT_NAME,
    description=f"Developed by {config.AUTHOR_NAME}",
    version=config.VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_bearer = HTTPBearer()

def create_access_token(email: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=config.JWT_EXPIRATION_HOURS)
    return jwt.encode({"sub": email, "exp": exp}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security_bearer)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token.")
        return email
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired.")

class LoginRequest(BaseModel):
    email: str

class ScanRequest(BaseModel):
    target_url: str

@app.get("/api/meta")
def get_meta():
    return {
        "project": config.PROJECT_NAME,
        "version": config.VERSION,
        "author": config.AUTHOR_NAME,
        "github": config.GITHUB_URL,
        "linkedin": config.LINKEDIN_URL
    }

@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$", email):
        raise HTTPException(status_code=400, detail="Invalid email format.")
    return {
        "access_token": create_access_token(email),
        "token_type": "bearer",
        "email": email,
        "author": config.AUTHOR_NAME,
        "framework": config.PROJECT_NAME
    }

@app.post("/api/scan")
def scan(req: ScanRequest, user: str = Depends(get_current_user)):
    target = req.target_url.strip()
    scope = TargetValidator.validate(target)
    if not scope.is_reachable:
        raise HTTPException(status_code=400, detail=scope.validation_error or "Target unreachable.")

    # Primary probe
    try:
        res = requests.get(scope.normalized_url, timeout=config.DEFAULT_TIMEOUT_SEC, verify=False,
                           headers={"User-Agent": config.USER_AGENT})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Target probe failed: {str(e)}")

    spider = CyberSpider(scope)
    crawl = spider.crawl()

    findings = []
    findings.extend(HeaderAnalyzer().analyze(scope.normalized_url, dict(res.headers)))
    findings.extend(TLSSecurityAnalyzer().analyze(scope))
    findings.extend(CookieSecurityAnalyzer().analyze(scope.normalized_url, res))
    tech = CyberTechDetector().analyze(dict(res.headers), res.text)
    findings.extend(FormSecurityAnalyzer().analyze(crawl.all_forms, scope))

    risk = CyberRiskEngine.compute(findings)

    payload = {
        "project": config.PROJECT_NAME,
        "target": asdict(scope),
        "auditor": user,
        "author": config.AUTHOR_NAME,
        "risk_summary": risk,
        "findings": [asdict(f) for f in findings],
        "technologies": [asdict(t) for t in tech],
        "metrics": {
            "pages_crawled": len(crawl.pages),
            "forms_found": len(crawl.all_forms),
            "duration_sec": crawl.duration_sec
        }
    }

    os.makedirs("reports", exist_ok=True)
    CyberReporter.save_json("reports/latest_scan.json", payload)
    return payload
"""
}

for filepath, content in files.items():
    folder = os.path.dirname(filepath)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated: {filepath}")

print("\n[+] CyberAge standalone architecture initialized successfully!")