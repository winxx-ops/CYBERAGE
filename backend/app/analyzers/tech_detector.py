"""Technology Stack Identification for CyberAge."""

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
