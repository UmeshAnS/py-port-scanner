import socket
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

RISKY_SERVICES = {
    21: "FTP (Cleartext credentials / Anonymous login risk)",
    23: "Telnet (Unencrypted remote shell - high risk)",
    25: "SMTP (Check for open relay)",
    139: "NetBIOS (SMB enumeration risk)",
    445: "SMB (Check for EternalBlue / null sessions)",
    3389: "RDP (Brute-force / BlueKeep target)",
    6379: "Redis (Often exposed without authentication)",
}


def grab_banner(sock: socket.socket, ip: str, port: int) -> str:
    try:
        if port in (80, 8080, 8000, 8888):
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            for line in response.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()
            return response.splitlines()[0].strip() if response else "HTTP Service"

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner.splitlines()[0] if banner else "No banner returned"
    except Exception:
        return "No banner returned"


def scan_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

                banner = grab_banner(sock, ip, port)
                warning = RISKY_SERVICES.get(port, "")
                return {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "banner": banner,
                    "security_note": warning,
                }
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Threaded TCP Port Scanner & Service Banner Grabber"
    )
    parser.add_argument("target", help="Target IP address or hostname (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("-o", "--output", help="Optional JSON file path to save results")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        return

    try:
        start_port, end_port = map(int, args.ports.split("-"))
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError
    except ValueError:
        print("[!] Invalid port range. Use format START-END (e.g., 1-1024).")
        return

    ports = range(start_port, end_port + 1)
    start_time = datetime.now()

    print("=" * 65)
    print(f"Target:      {args.target} ({target_ip})")
    print(f"Port Range:  {start_port}-{end_port} | Threads: {args.threads}")
    print(f"Started At:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    duration = (datetime.now() - start_time).total_seconds()

    if not open_ports:
        print("No open TCP ports found in the specified range.")
    else:
        print(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<14} {'BANNER'}")
        print("-" * 65)
        for item in open_ports:
            print(f"{item['port']:<10} {item['state']:<8} {item['service']:<14} {item['banner']}")
            if item["security_note"]:
                print(f"   [!] Security Note: {item['security_note']}")

    print("=" * 65)
    print(f"Scan complete in {duration:.2f}s | Open ports found: {len(open_ports)}")

    if args.output:
        report = {
            "target": args.target,
            "resolved_ip": target_ip,
            "scan_time": start_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "open_ports": open_ports,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
