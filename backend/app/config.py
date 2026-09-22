"""CyberAge Global Configuration, Authentication & Author Attribution."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class CyberAgeConfig:
    PROJECT_NAME: str = "CyberAge"
    VERSION: str = "2.1.0-PROD"
    AUTHOR_NAME: str = "Amit Kumar Mahato"
    GITHUB_URL: str = "https://github.com/winxx-ops"
    LINKEDIN_URL: str = "https://www.linkedin.com/in/amit-kumar-mahato-859206226"

    # Restricted Operator Credentials
    ADMIN_USERNAME: str = os.getenv("CYBERAGE_ADMIN_USER", "admin")
    ADMIN_PASSWORD: str = os.getenv("CYBERAGE_ADMIN_PASS", "CyberAge@2026#Secure")

    # Threat Intelligence & Scanner Settings
    VIRUSTOTAL_API_KEY: str = os.getenv("VT_API_KEY", "")
    USER_AGENT: str = "CyberAge-Security-Engine/2.1 (+https://github.com/winxx-ops)"
    DEFAULT_TIMEOUT_SEC: float = 10.0
    MAX_CRAWL_PAGES: int = 15
    MAX_CRAWL_DEPTH: int = 2
    CRAWL_DELAY_SEC: float = 0.2

    # JWT Session Security
    JWT_SECRET: str = os.getenv("CYBERAGE_JWT_SECRET", "super-secret-key-amit-kumar-mahato-cyberage-v2")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 12


config = CyberAgeConfig()