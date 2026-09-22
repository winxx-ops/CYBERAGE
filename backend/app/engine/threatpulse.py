"""CyberAge ThreatPulse: Native Threat Reputation & Domain Heuristics Engine."""

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Tuple

from app.engine.models import Confidence, Finding, Severity

SUSPICIOUS_TLDS = {
    "top", "xyz", "buzz", "click", "rest", "tk", "ml", "ga", "cf", "gq", 
    "work", "loan", "support", "shop", "icu", "bar", "lat"
}

DNSBL_PROVIDERS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
]

TARGET_KEYWORDS = [
    "paypal", "apple", "google", "bank", "login", "account", 
    "secure", "update", "verify", "signin", "support", "billing"
]


@dataclass
class ThreatFactor:
    name: str
    weight: int
    triggered: bool
    details: str


@dataclass
class ThreatPulseReport:
    target_domain: str
    target_ip: str
    threat_score: int
    verdict: str
    blacklists_checked: int = 0
    blacklists_flagged: int = 0
    flagged_blacklists: List[str] = field(default_factory=list)
    factors: List[ThreatFactor] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)


class ThreatPulseEngine:
    def __init__(self, domain: str, ip_address: str):
        self.domain = domain.lower().strip()
        self.ip_address = ip_address.strip()

    def evaluate(self) -> Tuple[ThreatPulseReport, List[Finding]]:
        factors: List[ThreatFactor] = []
        score = 0
        categories: List[str] = []
        findings: List[Finding] = []

        # 1. Suspicious / Abuse-Prone TLD Analysis
        tld = self.domain.split(".")[-1] if "." in self.domain else ""
        if tld in SUSPICIOUS_TLDS:
            score += 25
            categories.append("Abuse-Prone TLD")
            factors.append(ThreatFactor(
                name="Suspicious Top-Level Domain",
                weight=25,
                triggered=True,
                details=f"The domain uses '{tld}', a TLD with higher statistical abuse rates.",
            ))
        else:
            factors.append(ThreatFactor(
                name="Top-Level Domain Reputation",
                weight=0,
                triggered=False,
                details="Standard domain suffix (.com, .org, .edu, .net, etc.).",
            ))

        # 2. Brand Impersonation / Typosquatting Patterns
        keyword_hits = [k for k in TARGET_KEYWORDS if k in self.domain and not self.domain.endswith(f"{k}.com")]
        if keyword_hits:
            score += 30
            categories.append("Phishing Indicator")
            factors.append(ThreatFactor(
                name="Brand Impersonation / Deceptive Keywords",
                weight=30,
                triggered=True,
                details=f"Contains high-value target keywords: {', '.join(keyword_hits)}",
            ))
            findings.append(Finding(
                title=f"Potential Deceptive Domain Naming Pattern ({keyword_hits[0]})",
                severity=Severity.HIGH,
                category="Threat Intelligence / Brand Protection",
                owasp_id="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1385",
                evidence=f"Target domain matches pattern '{keyword_hits}' outside apex namespace.",
                recommendation="Ensure this domain is not unintentionally spoofing recognized brands or authentication services.",
                confidence=Confidence.HIGH,
            ))

        # 3. Structural Complexity / High-Entropy Names
        hyphen_count = self.domain.count("-")
        dot_count = self.domain.count(".")
        if hyphen_count >= 3 or dot_count >= 4:
            score += 20
            categories.append("Obfuscated Structure")
            factors.append(ThreatFactor(
                name="Suspicious Subdomain/Hyphen Density",
                weight=20,
                triggered=True,
                details=f"Excessive hyphenation ({hyphen_count}) or nested subdomains ({dot_count}).",
            ))

        # 4. Multi-DNSBL Threat Feed Interrogation
        bl_flagged, flagged_list = self._check_dnsbl()
        if bl_flagged > 0:
            score += min(45, bl_flagged * 20)
            categories.append("Blacklisted Host")
            factors.append(ThreatFactor(
                name="Public Threat Feeds / DNSBL",
                weight=min(45, bl_flagged * 20),
                triggered=True,
                details=f"Flagged by {bl_flagged} independent security blacklists: {', '.join(flagged_list)}",
            ))
            findings.append(Finding(
                title=f"Target Host IP Listed on {bl_flagged} Security Blocklists",
                severity=Severity.HIGH,
                category="Threat Intelligence",
                owasp_id="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1385",
                evidence=f"IP {self.ip_address} is actively listed on: {', '.join(flagged_list)}",
                recommendation="Investigate server for outbound spam, brute-force behavior, or open relays and request delisting.",
                confidence=Confidence.HIGH,
            ))
        else:
            factors.append(ThreatFactor(
                name="Public Threat Feeds / DNSBL",
                weight=0,
                triggered=False,
                details="IP address is clean across all checked threat blocklists.",
            ))

        final_score = min(100, score)
        if final_score >= 60:
            verdict = "MALICIOUS"
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        report = ThreatPulseReport(
            target_domain=self.domain,
            target_ip=self.ip_address,
            threat_score=final_score,
            verdict=verdict,
            blacklists_checked=len(DNSBL_PROVIDERS),
            blacklists_flagged=bl_flagged,
            flagged_blacklists=flagged_list,
            factors=factors,
            categories=categories if categories else ["Safe Web Asset"],
        )

        return report, findings

    def _check_dnsbl(self) -> Tuple[int, List[str]]:
        flagged_sources = []
        try:
            ip_obj = ipaddress.ip_address(self.ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return 0, []

            reversed_ip = ".".join(reversed(self.ip_address.split(".")))
            for dnsbl in DNSBL_PROVIDERS:
                query = f"{reversed_ip}.{dnsbl}"
                try:
                    socket.setdefaulttimeout(1.2)
                    res = socket.gethostbyname(query)
                    if res and res.startswith("127.0.0."):
                        flagged_sources.append(dnsbl)
                except Exception:
                    continue
        except Exception:
            pass

        return len(flagged_sources), flagged_sources