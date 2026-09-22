"""CyberAge Polite Scoped Crawler."""

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
