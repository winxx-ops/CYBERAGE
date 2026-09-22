"""CyberAge Scope Boundary & Target Validation Engine."""

import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.config import config
from app.engine.ssrf_guard import SSRFGuard


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
            clean_input = f"http://{clean_input}"

        parsed = urlparse(clean_input)
        if not parsed.hostname:
            return TargetScope(
                raw_input=input_url,
                normalized_url=clean_input,
                scheme="",
                hostname="",
                port=0,
                ip_address=None,
                base_domain="",
                path="/",
                is_reachable=False,
                validation_error="Malformed URL: Missing valid hostname.",
            )

        hostname = parsed.hostname.lower()
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        base_domain = cls._extract_base(hostname)

        is_safe, resolved_ip, ssrf_err = SSRFGuard.is_safe_target(clean_input)
        if not is_safe:
            return TargetScope(
                raw_input=input_url,
                normalized_url=clean_input,
                scheme=scheme,
                hostname=hostname,
                port=port,
                ip_address=resolved_ip,
                base_domain=base_domain,
                path=path,
                is_reachable=False,
                validation_error=ssrf_err,
            )

        normalized_url = urlunparse((
            scheme,
            f"{hostname}:{parsed.port}" if parsed.port else hostname,
            path,
            "",
            "",
            "",
        ))

        scope = TargetScope(
            raw_input=input_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            ip_address=resolved_ip,
            base_domain=base_domain,
            path=path,
            is_reachable=False,
        )

        cls._probe(scope)
        return scope

    @staticmethod
    def _extract_base(hostname: str) -> str:
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @classmethod
    def _probe(cls, scope: TargetScope) -> None:
        session = requests.Session()
        session.headers.update({"User-Agent": config.USER_AGENT})
        t0 = time.perf_counter()

        def try_connect(target_url: str) -> Optional[requests.Response]:
            try:
                return session.get(target_url, timeout=7.0, allow_redirects=True, verify=False)
            except Exception:
                return None

        resp = try_connect(scope.normalized_url)

        if resp is None and scope.scheme == "https":
            fallback_url = scope.normalized_url.replace("https://", "http://", 1)
            resp = try_connect(fallback_url)
            if resp:
                scope.normalized_url = fallback_url
                scope.scheme = "http"
                scope.port = 80

        if resp is None and scope.scheme == "http":
            upgrade_url = scope.normalized_url.replace("http://", "https://", 1)
            resp = try_connect(upgrade_url)
            if resp:
                scope.normalized_url = upgrade_url
                scope.scheme = "https"
                scope.port = 443

        if resp is None:
            scope.is_reachable = False
            scope.validation_error = (
                f"Target connection timed out. Neither HTTP nor HTTPS responded on {scope.hostname}."
            )
            return

        scope.is_reachable = True
        scope.status_code = resp.status_code
        scope.response_time_ms = round((time.perf_counter() - t0) * 1000, 2)
        scope.final_destination = resp.url

        for r in resp.history:
            scope.redirect_chain.append(RedirectHop(r.url, r.status_code, dict(r.headers)))

        final_host = (urlparse(resp.url).hostname or "").lower()
        if final_host and final_host != scope.hostname:
            scope.cross_domain_redirect = True