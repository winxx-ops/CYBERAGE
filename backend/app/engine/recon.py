"""CyberAge Network Reconnaissance: DNS, Geolocation, Port Scanning & Banner Grabbing."""

import concurrent.futures
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import List, Optional
import requests

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


@dataclass
class GeoLocationData:
    country: str = "Unknown"
    country_code: str = ""
    region: str = "Unknown"
    city: str = "Unknown"
    postal: str = "N/A"
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "UTC"
    isp: str = "Unknown"
    asn: str = "Unknown"
    org: str = "Unknown"
    flag_emoji: str = "🌐"


@dataclass
class OpenService:
    port: int
    service: str
    state: str = "open"
    banner: str = "Unknown"
    response_time_ms: float = 0.0


@dataclass
class DNSRecords:
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    reverse_ptr: Optional[str] = None


@dataclass
class ReconProfile:
    hostname: str
    ip_address: str
    reverse_ptr: str
    geo: GeoLocationData
    dns: DNSRecords
    open_ports: List[OpenService]
    total_ports_scanned: int
    scan_duration_sec: float


class NetworkReconEngine:
    def __init__(self, hostname: str, ip_address: str):
        self.hostname = hostname
        self.ip_address = ip_address

    def execute_recon(self) -> ReconProfile:
        start_time = time.perf_counter()

        reverse_ptr = self._get_reverse_ptr()
        geo_data = self._resolve_geolocation()
        dns_data = self._resolve_dns_records(reverse_ptr)
        open_services = self._scan_ports_concurrently()

        duration = round(time.perf_counter() - start_time, 2)
        return ReconProfile(
            hostname=self.hostname,
            ip_address=self.ip_address,
            reverse_ptr=reverse_ptr,
            geo=geo_data,
            dns=dns_data,
            open_ports=open_services,
            total_ports_scanned=len(COMMON_PORTS),
            scan_duration_sec=duration,
        )

    def _resolve_geolocation(self) -> GeoLocationData:
        if self.ip_address in ("127.0.0.1", "::1") or self.ip_address.startswith(("192.168.", "10.")):
            return GeoLocationData(
                country="Localhost / Private",
                country_code="LOCAL",
                region="Internal Loopback",
                city="Local Lab",
                isp="Loopback Interface",
                asn="Private AS",
                org="Self-Hosted Lab",
                flag_emoji="💻",
            )

        try:
            resp = requests.get(f"https://ipwho.is/{self.ip_address}", timeout=3.5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success", True):
                    conn = data.get("connection", {})
                    tz = data.get("timezone", {})
                    return GeoLocationData(
                        country=data.get("country", "Unknown"),
                        country_code=data.get("country_code", ""),
                        region=data.get("region", "Unknown"),
                        city=data.get("city", "Unknown"),
                        postal=data.get("postal", "N/A"),
                        latitude=data.get("latitude", 0.0),
                        longitude=data.get("longitude", 0.0),
                        timezone=tz.get("id", "UTC"),
                        isp=conn.get("isp", "Unknown"),
                        asn=f"AS{conn.get('asn', '')}" if conn.get("asn") else "Unknown",
                        org=conn.get("org", data.get("org", "Unknown")),
                        flag_emoji=data.get("flag", {}).get("emoji", "🌐"),
                    )
        except Exception:
            pass
        return GeoLocationData()

    def _get_reverse_ptr(self) -> str:
        try:
            return socket.gethostbyaddr(self.ip_address)[0]
        except Exception:
            return "N/A (No PTR Record)"

    def _resolve_dns_records(self, reverse_ptr: str) -> DNSRecords:
        records = DNSRecords(reverse_ptr=reverse_ptr)

        try:
            records.a_records = list({
                info[4][0] for info in socket.getaddrinfo(self.hostname, None, socket.AF_INET)
            })
        except Exception:
            records.a_records = [self.ip_address]

        headers = {"Accept": "application/dns-json"}
        type_mapping = {"AAAA": 28, "MX": 15, "TXT": 16, "NS": 2, "CNAME": 5}

        for record_name, record_type in type_mapping.items():
            try:
                url = f"https://cloudflare-dns.com/dns-query?name={self.hostname}&type={record_type}"
                resp = requests.get(url, headers=headers, timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    values = [ans.get("data", "").strip('"') for ans in answers if ans.get("data")]

                    if record_name == "AAAA":
                        records.aaaa_records = values
                    elif record_name == "MX":
                        records.mx_records = values
                    elif record_name == "TXT":
                        records.txt_records = values
                    elif record_name == "NS":
                        records.ns_records = values
                    elif record_name == "CNAME" and values:
                        records.cname = values[0]
            except Exception:
                continue

        return records

    def _probe_port(self, port: int, service_name: str) -> Optional[OpenService]:
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)

        try:
            result = sock.connect_ex((self.ip_address, port))
            if result == 0:
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                banner = self._grab_banner(sock, port)
                sock.close()
                return OpenService(
                    port=port,
                    service=service_name,
                    state="open",
                    banner=banner,
                    response_time_ms=elapsed_ms,
                )
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(1.2)
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.hostname.encode() + b"\r\n\r\n")
            elif port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.hostname.encode() + b"\r\n\r\n")
                    raw = ssock.recv(256).decode("utf-8", errors="ignore")
                    lines = [line.strip() for line in raw.split("\r\n") if line.strip()]
                    return lines[0] if lines else "TLS Service (Encrypted)"
            else:
                sock.sendall(b"\r\n")

            raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
            if raw:
                return raw.split("\r\n")[0].split("\n")[0][:80]
        except Exception:
            pass
        return f"{COMMON_PORTS.get(port, 'TCP')} Service Active"

    def _scan_ports_concurrently(self) -> List[OpenService]:
        open_services: List[OpenService] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            future_to_port = {
                executor.submit(self._probe_port, port, sname): port
                for port, sname in COMMON_PORTS.items()
            }
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    open_services.append(res)

        open_services.sort(key=lambda s: s.port)
        return open_services