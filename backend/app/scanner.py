import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt"
}

def _probe(host: str, port: int, timeout: float):
    row = {"port": port, "service": SERVICES.get(port, "unknown"), "state": "closed_or_filtered"}
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            row["state"] = "open"
    except OSError:
        row["state"] = "unreachable"
    finally:
        sock.close()
    return row

def scan_ports(host: str, ports: list[int], timeout: float = 0.5):
    results = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_probe, host, port, timeout) for port in ports]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["port"])
