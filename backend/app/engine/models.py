"""Finding models and taxonomy classifications."""

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
