# ⚡ CyberAge — Automated 3D Web VAPT & Threat Recon Suite

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Three.js](https://img.shields.io/badge/Frontend-Three.js%20%2F%20TailwindCSS-06B6D4.svg)](https://threejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**CyberAge** is an automated Web Vulnerability Assessment and Penetration Testing (VAPT) suite. It pairs a high-performance Python FastAPI backend with an interactive, Three.js-powered 3D neon HUD dashboard.

---

## 🚀 Key Modules & Capabilities

- **ThreatPulse Reputation Engine:** Native domain & IP reputation evaluator using DNSBL feeds, domain age heuristics, and brand-impersonation indicators.
- **Active Network Recon:** Multi-threaded TCP port prober with raw socket banner grabbing across common services.
- **DNS & Geolocation Matrix:** Deep DNS record mapping (A, AAAA, MX, NS, TXT, CNAME, PTR) and server geolocation with ASN identification.
- **Passive Subdomain OSINT:** Zero-noise attack surface mapping via public Certificate Transparency logs (`crt.sh`).
- **Gobuster Path Discovery:** Concurrent directory and sensitive artifact enumeration (`.env`, `.git`, backups, admin portals).
- **Modern API Security:** Active CORS misconfiguration auditing and GraphQL schema introspection checks.
- **Operator Security Gateway:** Role-based access control protected with JWT tokens and bcrypt cryptographic hashing.
- **Executive Audit Export:** One-click generation of printable and PDF-formatted penetration testing deliverables.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/winxx-ops/CYBERAGE.git](https://github.com/winxx-ops/CYBERAGE.git)
cd CYBERAGE
