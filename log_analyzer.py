#!/usr/bin/env python3
"""
Cybersecurity Log Analysis Script
Purpose: Parses system log files to identify failed logins and brute-force patterns.
Freshworks Ticket Reference: SCT-2
"""

import re
from collections import Counter
import json

SAMPLE_LOG_DATA = """
2026-07-28 10:14:02 192.168.1.50 LOGIN_SUCCESS user=admin
2026-07-28 10:15:11 203.0.113.45 LOGIN_FAILED user=root
2026-07-28 10:15:14 203.0.113.45 LOGIN_FAILED user=root
2026-07-28 10:15:18 203.0.113.45 LOGIN_FAILED user=root
2026-07-28 10:15:22 203.0.113.45 LOGIN_FAILED user=root
2026-07-28 10:15:26 203.0.113.45 LOGIN_FAILED user=root
2026-07-28 10:18:00 198.51.100.12 LOGIN_FAILED user=jsmith
2026-07-28 10:20:45 192.168.1.52 LOGIN_SUCCESS user=mwilson
"""

FAILED_THRESHOLD = 3

def analyze_logs(log_text):
    print("[*] Starting Cybersecurity Log Analysis...")
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(LOGIN_SUCCESS|LOGIN_FAILED)')
    failed_attempts = Counter()
    total_events = 0

    for line in log_text.strip().split('\n'):
        if not line:
            continue
        total_events += 1
        match = log_pattern.search(line)
        if match:
            ip, status = match.groups()
            if status == 'LOGIN_FAILED':
                failed_attempts[ip] += 1

    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= FAILED_THRESHOLD}

    summary = {
        "total_logs_processed": total_events,
        "flagged_suspicious_ips": suspicious_ips,
        "action_required": len(suspicious_ips) > 0
    }

    print(f"Total Logs Processed: {total_events}")
    if suspicious_ips:
        print("[!] Brute-Force Attacks Detected from:")
        for ip, count in suspicious_ips.items():
            print(f"    - IP: {ip} | Failed Attempts: {count}")

    return summary

if __name__ == "__main__":
    results = analyze_logs(SAMPLE_LOG_DATA)
