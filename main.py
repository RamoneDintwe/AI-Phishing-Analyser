"""
AI Phishing Analyser - MVP (Regex/Header Parser)
MotseNova - Ramone Dintwe
Usage: python main.py path/to/email.eml
"""

import email
import logging
import re
import sys
from email import policy
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

URL_RE = re.compile(r'https?://[^\s<>"\')]+')
IP_URL_RE = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
URGENCY_WORDS = [
    "urgent", "verify your account", "suspended", "immediately",
    "click here", "confirm your identity", "unusual activity",
    "act now", "limited time", "your account will be closed",
    # South Africa-specific urgency phrases
    "sars refund", "sars efiling", "sassa grant", "sassa payment",
    "load shedding rebate", "e-toll fine", "e-toll account",
    "home affairs", "grant suspended", "verify your sassa",
    "outstanding tax", "banking app update", "fica verification"
]


def load_email(path):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def get_body(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:        
                    parts.append(part.get_content())
                except Exception as e: # noqa: BLE001 
                    logger.warning(f"Failed to decode email part: {e}")
        return "\n".join(parts)
    try:
        return msg.get_content()
    except Exception as e: # noqa: BLE001
        logger.warning(f"Failed to get email content: {e}")
        return ""


def check_auth_results(msg):
    findings = []
    auth = msg.get("Authentication-Results", "")
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth, re.IGNORECASE)
        result = m.group(1).lower() if m else "missing"
        if result in ("fail", "missing", "softfail"):
            findings.append((f"{mech.upper()} check: {result}", 20))
    return findings


def check_from_replyto_mismatch(msg):
    findings = []
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    reply_addr = email.utils.parseaddr(msg.get("Reply-To", ""))[1]
    if reply_addr and from_addr:
        from_domain = from_addr.split("@")[-1].lower()
        reply_domain = reply_addr.split("@")[-1].lower()
        if from_domain != reply_domain:
            findings.append(
                (f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})", 25)
            )
    return findings


def check_display_name(msg):
    findings = []
    name, addr = email.utils.parseaddr(msg.get("From", ""))
    if name and addr:
        domain = addr.split("@")[-1].lower()
        common_brands = [
            "paypal", "microsoft", "google", "amazon", "bank",
            # SA banks
            "fnb", "absa", "sars", "nedbank", "standard bank",
            "capitec", "tymebank", "african bank", "discovery bank",
            # SA gov / telco / grants
            "sassa", "home affairs", "vodacom", "mtn", "telkom",
        ]
        for brand in common_brands:
            if brand in name.lower() and brand not in domain:
                findings.append((f"Display name mentions '{brand}' but domain is '{domain}'", 30))
    return findings


def check_urls(body):
    findings = []
    urls = URL_RE.findall(body)
    for url in urls:
        if IP_URL_RE.match(url):
            findings.append((f"URL uses raw IP address: {url}", 25))
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if host in SHORTENERS:
            findings.append((f"URL shortener detected: {url}", 15))
        if "xn--" in host:
            findings.append((f"Punycode domain (possible homograph attack): {url}", 30))
    return findings


def check_urgency_language(subject, body):
    findings = []
    text = f"{subject} {body}".lower()
    hits = [w for w in URGENCY_WORDS if w in text]
    if hits:
        findings.append((f"Urgency/pressure language found: {', '.join(hits[:3])}", 10 * len(hits[:3])))
    return findings


def analyse(path):
    msg = load_email(path)
    subject = msg.get("Subject", "")
    body = get_body(msg)

    findings = []
    findings += check_auth_results(msg)
    findings += check_from_replyto_mismatch(msg)
    findings += check_display_name(msg)
    findings += check_urls(body)
    findings += check_urgency_language(subject, body)

    score = min(sum(w for _, w in findings), 100)

    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    print(f"\nSubject: {subject}")
    print(f"From: {msg.get('From', 'unknown')}")
    print(f"\nRisk Score: {score}/100  ->  {verdict}\n")
    print("Findings:")
    if findings:
        for desc, weight in findings:
            print(f"  [+{weight}] {desc}")
    else:
        print("  No red flags detected.")
    print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/email.eml")
        sys.exit(1)
    analyse(sys.argv[1])