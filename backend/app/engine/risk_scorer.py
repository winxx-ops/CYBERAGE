"""CyberAge Risk Engine."""

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
