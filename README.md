# Multi-Threaded TCP Port Scanner & Banner Grabber

A fast, multi-threaded network reconnaissance CLI tool built in Python using `socket` and `concurrent.futures`. Designed to enumerate open TCP ports, grab live service banners (including HTTP `HEAD` header probing), flag high-risk cleartext protocols, and export structured JSON scan reports.

## Features
- **High-Speed Concurrency:** Scans 9,000+ TCP ports in ~3 seconds using `ThreadPoolExecutor`.
- **Active Service Banner Grabbing:** Captures initial service greeting banners (SSH, FTP, SMTP) and sends HTTP `HEAD` probes to identify web server versions.
- **Security Posture Flagging:** Automatically highlights high-risk or unencrypted services (Telnet, FTP, SMB, RDP, Redis) for follow-up enumeration.
- **JSON Reporting:** Exports structured scan metadata and open port findings via `-o`.

## Usage
```bash
# Scan default ports (1-1024) on a target
python3 scanner.py 127.0.0.1

# Scan custom port range with 100 threads and export to JSON
python3 scanner.py 127.0.0.1 -p 1-9000 -t 100 -o sample_scan.json
