#!/usr/bin/env python3
"""
Automated Web Security Scanner
Audits a website for secure headers, CORS misconfiguration, HTTPS and cookie flags.

Usage:
    python RohiniWaghade_WebSecurityScanner.py https://example.com
    python RohiniWaghade_WebSecurityScanner.py https://example.com --json report.json

Only scan websites you own or have written permission to test.
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template

import requests

TIMEOUT = 10
app = Flask(__name__)
EVIL_ORIGIN = "https://evil.example"

# header name -> (why it matters, weight)
SECURITY_HEADERS = {
    "Content-Security-Policy": ("Prevents XSS and data injection", 20),
    "Strict-Transport-Security": ("Forces HTTPS (HSTS)", 20),
    "X-Frame-Options": ("Prevents clickjacking", 10),
    "X-Content-Type-Options": ("Stops MIME-type sniffing", 10),
    "Referrer-Policy": ("Controls referrer information leakage", 5),
    "Permissions-Policy": ("Restricts browser features", 5),
}

@app.route('/')
def home():
    return render_template('index.html')


def fetch(url, headers=None):
    return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)


def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return {"check": "HTTPS", "status": "PASS", "detail": "Site uses HTTPS", "points": 20}
    return {"check": "HTTPS", "status": "FAIL", "detail": "Site uses plain HTTP", "points": 0}


def check_headers(response):
    results = []
    for name, (why, weight) in SECURITY_HEADERS.items():
        if name in response.headers:
            results.append({"check": name, "status": "PASS",
                            "detail": f"Present: {response.headers[name][:80]}", "points": weight})
        else:
            results.append({"check": name, "status": "FAIL",
                            "detail": f"Missing. {why}", "points": 0})
    return results


def check_cors(url):
    try:
        r = fetch(url, headers={"Origin": EVIL_ORIGIN})
    except requests.RequestException as e:
        return {"check": "CORS", "status": "ERROR", "detail": str(e), "points": 0}

    acao = r.headers.get("Access-Control-Allow-Origin")
    creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao is None:
        return {"check": "CORS", "status": "PASS",
                "detail": "No CORS headers returned for foreign origin", "points": 10}
    if acao == EVIL_ORIGIN and creds:
        return {"check": "CORS", "status": "FAIL",
                "detail": "CRITICAL: reflects any origin WITH credentials allowed", "points": 0}
    if acao == EVIL_ORIGIN:
        return {"check": "CORS", "status": "FAIL",
                "detail": "Reflects arbitrary Origin header", "points": 0}
    if acao == "*":
        return {"check": "CORS", "status": "WARN",
                "detail": "Wildcard (*) allows any origin to read responses", "points": 5}
    return {"check": "CORS", "status": "PASS",
            "detail": f"Restricted to: {acao}", "points": 10}


def check_cookies(response):
    cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not cookies:
        return {"check": "Cookie flags", "status": "PASS",
                "detail": "No cookies set", "points": 10}
    problems = []
    for c in cookies:
        low = c.lower()
        name = c.split("=")[0]
        if "secure" not in low:
            problems.append(f"{name}: missing Secure")
        if "httponly" not in low:
            problems.append(f"{name}: missing HttpOnly")
        if "samesite" not in low:
            problems.append(f"{name}: missing SameSite")
    if problems:
        return {"check": "Cookie flags", "status": "FAIL",
                "detail": "; ".join(problems), "points": 0}
    return {"check": "Cookie flags", "status": "PASS",
            "detail": "All cookies have Secure, HttpOnly, SameSite", "points": 10}


def grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def scan(url):
    try:
        response = fetch(url)
    except requests.RequestException as e:
        print(f"[!] Could not reach {url}: {e}")
        sys.exit(1)

    results = [check_https(response.url)]
    results += check_headers(response)
    results.append(check_cors(url))
    results.append(check_cookies(response))

    max_points = 20 + sum(w for _, w in SECURITY_HEADERS.values()) + 10 + 10
    earned = sum(r["points"] for r in results)
    score = round(earned / max_points * 100)

    return {
        "target": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "score": score,
        "grade": grade(score),
        "results": results,
    }


def print_report(report):
    icons = {"PASS": "[+]", "FAIL": "[-]", "WARN": "[~]", "ERROR": "[!]"}
    print("=" * 64)
    print(" WEB SECURITY SCAN REPORT")
    print("=" * 64)
    print(f" Target : {report['target']}")
    print(f" Time   : {report['scanned_at']}")
    print("-" * 64)
    for r in report["results"]:
        print(f" {icons[r['status']]} {r['check']:<28} {r['status']}")
        print(f"     {r['detail']}")
    print("-" * 64)
    print(f" SCORE: {report['score']}/100    GRADE: {report['grade']}")
    print("=" * 64)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple web security scanner")
    parser.add_argument("url", nargs="?", help="Target URL, e.g. https://example.com")
    parser.add_argument("--json", metavar="FILE", help="Save report as JSON")
    args = parser.parse_args()

    if args.url or len(sys.argv) > 1:
        target = args.url or input("Enter website URL to scan (e.g. https://example.com): ").strip()
        if not target:
            print("No URL given.")
            sys.exit(1)
        url = target if target.startswith("http") else "https://" + target
        report = scan(url)
        print_report(report)

        if args.json:
            with open(args.json, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to {args.json}")
    else:
        app.run(debug=True)
