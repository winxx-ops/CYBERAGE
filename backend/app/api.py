"""CyberAge Master FastAPI Application: Static UI Hosting, Recon, OSINT, ThreatPulse & VAPT."""

import os
import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import bcrypt
import requests

from fastapi import Depends, FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import config
from app.engine.validator import TargetValidator
from app.engine.spider import CyberSpider
from app.engine.risk_scorer import CyberRiskEngine
from app.engine.reporter import CyberReporter
from app.engine.recon import NetworkReconEngine
from app.engine.content_discovery import ContentDiscoveryEngine
from app.engine.subdomains import SubdomainDiscoveryEngine
from app.engine.threatpulse import ThreatPulseEngine

from app.analyzers.headers_analyzer import HeaderAnalyzer
from app.analyzers.cookie_analyzer import CookieSecurityAnalyzer
from app.analyzers.tls_analyzer import TLSSecurityAnalyzer
from app.analyzers.form_analyzer import FormSecurityAnalyzer
from app.analyzers.tech_detector import CyberTechDetector
from app.analyzers.advanced_api import AdvancedAPIAnalyzer

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=config.PROJECT_NAME,
    description=f"Developed by {config.AUTHOR_NAME}",
    version=config.VERSION,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Pre-hash operator master key for zero plain-text storage
ADMIN_HASHED_PASSWORD = bcrypt.hashpw(
    config.ADMIN_PASSWORD.encode("utf-8"),
    bcrypt.gensalt(rounds=12)
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


security_bearer = HTTPBearer(auto_error=False)


def create_access_token(username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=config.JWT_EXPIRATION_HOURS)
    return jwt.encode({"sub": username, "exp": exp}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security_bearer)) -> str:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session Expired or Clearance Token Missing. Please authenticate."
        )
    try:
        payload = jwt.decode(credentials.credentials, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token identity.")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Clearance expired or invalid signature.")


class LoginCredentials(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)


class ScanRequest(BaseModel):
    target_url: str = Field(..., max_length=255)


FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


@app.get("/", include_in_schema=False)
def serve_dashboard():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"error": "Dashboard not found in frontend directory."}


@app.get("/api/meta")
def get_meta():
    return {
        "project": config.PROJECT_NAME,
        "version": config.VERSION,
        "author": config.AUTHOR_NAME,
        "github": config.GITHUB_URL,
        "linkedin": config.LINKEDIN_URL,
    }


@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request, creds: LoginCredentials):
    clean_user = creds.username.strip()
    is_valid_user = (clean_user.lower() == config.ADMIN_USERNAME.lower())
    
    # Secure constant-time hash verification via bcrypt
    try:
        is_valid_pass = bcrypt.checkpw(
            creds.password.encode("utf-8"),
            ADMIN_HASHED_PASSWORD
        )
    except Exception:
        is_valid_pass = False

    if not (is_valid_user and is_valid_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access Denied: Invalid Operator Identity or Clearance Key."
        )

    return {
        "access_token": create_access_token(clean_user),
        "token_type": "bearer",
        "operator": clean_user,
        "role": "SECURITY_LEAD",
        "author": config.AUTHOR_NAME,
    }


@app.post("/api/scan")
@limiter.limit("10/minute")
def scan(request: Request, req: ScanRequest, user: str = Depends(get_current_user)):
    target = req.target_url.strip()

    # 1. Target Scope & SSRF Verification
    scope = TargetValidator.validate(target)
    if not scope.is_reachable:
        raise HTTPException(
            status_code=400,
            detail=scope.validation_error or "Target unreachable or blocked by security policy.",
        )

    # 2. Network Recon, Port Probing & DNS
    recon_engine = NetworkReconEngine(scope.hostname, scope.ip_address)
    recon_profile = recon_engine.execute_recon()

    # 3. Native ThreatPulse Reputation & DNSBL Engine
    threat_engine = ThreatPulseEngine(scope.hostname, scope.ip_address)
    threat_report, threat_findings = threat_engine.evaluate()

    # 4. Passive Subdomain OSINT (Certificate Transparency logs)
    subdomains = SubdomainDiscoveryEngine.discover(scope.base_domain)

    # 5. Safe HTTP Probe
    try:
        res = requests.get(
            scope.normalized_url,
            timeout=config.DEFAULT_TIMEOUT_SEC,
            verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Target probe failed: {str(e)}")

    # 6. Web Crawler & Form Discovery
    spider = CyberSpider(scope)
    crawl = spider.crawl()

    # 7. Gobuster-Style Sensitive Path Discovery
    discovery_engine = ContentDiscoveryEngine(scope.normalized_url)
    discovered_paths, discovery_findings = discovery_engine.run_discovery()

    # 8. Advanced API & CORS Misconfiguration Prober
    api_analyzer = AdvancedAPIAnalyzer(scope.normalized_url)
    api_findings = api_analyzer.audit_all()

    # 9. Aggregate All Security Findings
    findings = []
    findings.extend(HeaderAnalyzer().analyze(scope.normalized_url, dict(res.headers)))
    findings.extend(TLSSecurityAnalyzer().analyze(scope))
    findings.extend(CookieSecurityAnalyzer().analyze(scope.normalized_url, res))
    tech = CyberTechDetector().analyze(dict(res.headers), res.text)
    findings.extend(FormSecurityAnalyzer().analyze(crawl.all_forms, scope))
    findings.extend(discovery_findings)
    findings.extend(api_findings)
    findings.extend(threat_findings)

    # 10. Compute Normalized Risk Score
    risk = CyberRiskEngine.compute(findings)

    payload = {
        "project": config.PROJECT_NAME,
        "target": asdict(scope),
        "recon": asdict(recon_profile),
        "threatpulse": asdict(threat_report),
        "subdomains": {
            "base_domain": scope.base_domain,
            "count": len(subdomains),
            "records": subdomains,
        },
        "directory_scan": {
            "paths": [asdict(p) for p in discovered_paths],
            "total_tested": len(discovered_paths),
            "total_discovered": len(discovered_paths),
        },
        "auditor": user,
        "author": config.AUTHOR_NAME,
        "risk_summary": risk,
        "findings": [asdict(f) for f in findings],
        "technologies": [asdict(t) for t in tech],
        "metrics": {
            "pages_crawled": len(crawl.pages),
            "forms_found": len(crawl.all_forms),
            "duration_sec": crawl.duration_sec,
        },
    }

    # 11. Save Machine-Readable Audit Report
    os.makedirs("reports", exist_ok=True)
    CyberReporter.save_json("reports/latest_scan.json", payload)
    return payload