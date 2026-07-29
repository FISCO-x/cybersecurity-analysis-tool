#!/usr/bin/env python3
"""
Vulnerability Assessment Tool
Purpose: Audits local network ports and flags insecure services.
Freshworks Ticket Reference: SCT-1
"""

import socket

TARGET_HOST = "127.0.0.1"
CRITICAL_PORTS = {
    21: "FTP (Plaintext Credentials)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure Protocol)",
    80: "HTTP (Unencrypted Web)",
    443: "HTTPS (Encrypted Web)"
}

def scan_vulnerabilities():
    print(f"[*] Starting Vulnerability Assessment on: {TARGET_HOST}\n")
    findings = []

    for port, service in CRITICAL_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((TARGET_HOST, port))
        
        if result == 0:
            severity = "HIGH" if port in [21, 23, 80] else "INFO"
            findings.append({"port": port, "service": service, "severity": severity})
            print(f"[!] Port {port} ({service}): OPEN | Severity: {severity}")
        else:
            print(f"[+] Port {port} ({service}): CLOSED")
        sock.close()

    return findings

if __name__ == "__main__":
    scan_vulnerabilities()
