# CyberAge — Enterprise 3D Web VAPT & Threat Recon Suite

CyberAge is a dual-use Web Vulnerability Assessment and Penetration Testing (VAPT) framework built with a FastAPI backend and a 3D Three.js neon HUD interface.

## Features
- **ThreatPulse Reputation Engine**: Native domain and IP reputation analysis with DNSBL checks.
- **Network Recon & Fingerprinting**: Multi-threaded TCP port scanning and raw banner grabbing.
- **DNS & Geolocation Profiler**: Resolves A, AAAA, MX, NS, TXT, and CNAME records with IP geolocation.
- **Passive Subdomain OSINT**: Discovers subdomains via Certificate Transparency (`crt.sh`).
- **Gobuster Path Discovery**: Concurrent directory and sensitive file enumeration.
- **Modern API Security**: Active CORS misconfiguration probing and GraphQL introspection auditing.

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/winxx-ops/CYBERAGE.git](https://github.com/winxx-ops/CYBERAGE.git)
   cd CYBERAGE