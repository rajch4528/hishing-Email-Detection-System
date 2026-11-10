#!/usr/bin/env python3
"""Rule-based phishing email checker. Runs locally; makes no network requests."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

RULES = [
    ("urgent_language", 2, [
        "act immediately", "urgent action", "within 24 hours",
        "account will be suspended", "immediate action required",
        "last warning", "verify now"
    ]),
    ("credential_request", 3, [
        "enter your password", "confirm your password", "share your password",
        "verify your account", "login to restore", "send your otp",
        "share the otp", "provide your otp"
    ]),
    ("payment_pressure", 2, [
        "payment failed", "invoice overdue", "wire transfer",
        "gift card", "payment required"
    ]),
    ("unexpected_attachment", 2, [
        ".exe", ".scr", ".js", ".vbs", ".bat", ".iso", ".img"
    ]),
    ("generic_greeting", 1, [
        "dear customer", "dear user", "valued customer", "dear account holder"
    ]),
    ("threat_or_reward", 2, [
        "you have won", "claim your prize", "legal action will be taken",
        "your account is blocked", "unusual activity detected"
    ]),
]

@dataclass
class Finding:
    rule: str
    points: int
    explanation: str

def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,);]") for u in URL_RE.findall(text)]

def analyze_email(text: str) -> dict:
    lowered = text.lower()
    findings: list[Finding] = []

    for rule, points, phrases in RULES:
        matched = [phrase for phrase in phrases if phrase in lowered]
        if matched:
            findings.append(Finding(
                rule, points,
                f"Matched indicator(s): {', '.join(matched)}"
            ))

    urls = extract_urls(text)
    if len(urls) >= 3:
        findings.append(Finding(
            "many_links", 1,
            f"Message contains {len(urls)} links; check each destination carefully."
        ))

    for url in urls:
        normalized = url if "://" in url else "http://" + url
        host = urlparse(normalized).hostname or ""
        if IP_HOST_RE.match(host):
            findings.append(Finding(
                "ip_address_link", 3,
                f"A link uses an IP address instead of a recognizable domain: {url}"
            ))

    score = min(sum(item.points for item in findings), 10)
    if score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "risk": level,
        "findings": findings,
        "urls": urls,
        "disclaimer": (
            "This is a simple heuristic checker, not a definitive verdict. "
            "A low score does not prove an email is safe."
        ),
    }

def print_report(result: dict) -> None:
    print("\n=== PHISHING EMAIL CHECK REPORT ===")
    print(f"Risk level : {result['risk']}")
    print(f"Risk score : {result['score']}/10")
    print("\nIndicators:")
    if not result["findings"]:
        print("- No configured warning indicators were found.")
    else:
        for item in result["findings"]:
            print(f"- [{item.rule}] (+{item.points}) {item.explanation}")
    print("\nLinks found:")
    if result["urls"]:
        for url in result["urls"]:
            print(f"- {url}")
    else:
        print("- None")
    print(f"\nNote: {result['disclaimer']}")
    print("Safety: Do not click suspicious links or open unexpected attachments.")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check a saved email text file for common phishing indicators."
    )
    parser.add_argument("email_file", help="Path to a .txt email file")
    args = parser.parse_args()

    path = Path(args.email_file)
    if not path.is_file():
        parser.error(f"File not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    print_report(analyze_email(text))

if __name__ == "__main__":
    main()
