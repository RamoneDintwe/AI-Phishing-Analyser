"""
AI Phishing Analyser - MVP (Regex/Header Parser)
MotseNova - Ramone Dintwe
Usage: python main.py path/to/email.eml
"""

import difflib
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
CATEGORY_CAP = 50  # Maximum score per category to prevent over-weighting
AMBIGUOUS_BRAND_KEYS = {"rain", "gems", "visa", "apple"}
BRAND_DOMAINS = {
    "nedbank": "nedbank.co.za",
    "fnb": "fnb.co.za",
    "absa": "absa.co.za",
    "standard bank": "standardbank.co.za",
    "capitec": "capitecbank.co.za",
    "african bank": "africanbank.co.za",
    "discovery bank": "discovery.co.za",
    "tymebank": "tymebank.co.za",
    "gotyme": "gotyme.co.za",
    "investec": "investec.com",
    "old mutual": "oldmutual.co.za",
    "sanlam": "sanlam.co.za",
    "easyequities": "easyequities.co.za",
    "sars": "sars.gov.za",
    "sassa": "sassa.gov.za",
    "home affairs": "dha.gov.za",
    "uif": "labour.gov.za",
    "saps": "saps.gov.za",
    "nsfas": "nsfas.org.za",
    "vodacom": "vodacom.co.za",
    "mtn": "mtn.co.za",
    "telkom": "telkom.co.za",
    "cell c": "cellc.co.za",
    "rain": "rain.co.za",
    "afrihost": "afrihost.com",
    "takealot": "takealot.com",
    "woolworths": "woolworths.co.za",
    "shoprite": "shoprite.co.za",
    "checkers": "checkers.co.za",
    "pick n pay": "pnp.co.za",
    "dischem": "dischem.co.za",
    "clicks": "clicks.co.za",
    "payfast": "payfast.co.za",
    "ozow": "ozow.com",
    "snapscan": "snapscan.co.za",
    "yoco": "yoco.com",
    "paypal": "paypal.com",
    "visa": "visa.com",
    "mastercard": "mastercard.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "whatsapp": "whatsapp.com",
    "facebook": "facebook.com",
    "linkedin": "linkedin.com",
    "dhl": "dhl.com",
    "the courier guy": "thecourierguy.co.za",
    "postnet": "postnet.co.za",
    "sa post office": "postoffice.co.za",
    "flysafair": "flysafair.co.za",
    "south african airways": "flysaa.com",
    "momentum": "momentum.co.za",
    "hollard": "hollard.co.za",
    "outsurance": "outsurance.co.za",
    "bonitas": "bonitas.co.za",
    "gems": "gems.gov.za",
    "fsca": "fsca.org.za",
    "transunion": "transunion.com"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
    ".docm", ".xlsm", ".pptm", ".ps1",
}

URGENCY_WORDS = [
    "urgent", "verify your account", "suspended", "immediately",
    "click here", "confirm your identity", "unusual activity",
    "act now", "limited time", "your account will be closed",
    # South Africa-specific urgency phrases
    "sars refund", "sars efiling", "sassa grant", "sassa payment",
    "load shedding rebate", "e-toll fine", "e-toll account",
    "home affairs", "grant suspended", "verify your sassa",
    "outstanding tax", "banking app update", "fica verification",
    "refund", "claim your", "reward points", "account blocked",
    "update your details", "otp expired", "sim swap", "delivery failed",
]


def _sender_domain(msg):
    """Return the lower-case domain from the From header, or '' if absent."""
    address = email.utils.parseaddr(msg.get("From", ""))[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def load_email(path):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def get_body(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(part.get_content())
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Failed to decode email part: {e}")
        return "\n".join(parts)
    try:
        return msg.get_content()
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to get email content: {e}")
        return ""


def check_auth_results(msg):
    findings = []
    auth = msg.get("Authentication-Results", "")
    if not auth:
        findings.append(("Authentication-Results header missing entirely", 5))
        return findings
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth, re.IGNORECASE)
        result = m.group(1).lower() if m else ""
        if result in ("fail", "softfail"):
            findings.append((f"{mech.upper()} check: {result}", 20))
    return findings


def check_from_replyto_mismatch(msg):
    findings = []
    from_domain = _sender_domain(msg)
    reply_addr = email.utils.parseaddr(msg.get("Reply-To", ""))[1]
    reply_domain = reply_addr.rsplit("@", 1)[-1].lower() if "@" in reply_addr else ""
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(
            (f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})", 25)
        )
    return findings


def check_display_name(msg):
    findings = []
    name = email.utils.parseaddr(msg.get("From", ""))[0]
    domain = _sender_domain(msg)
    if not (name and domain):
        return findings
    for brand in BRAND_DOMAINS:
        if brand in name.lower() and brand.replace(" ", "") not in domain:
            findings.append((f"Display name mentions '{brand}' but domain is '{domain}'", 30))
            break
    return findings


def check_typosquat_domain(msg):
    findings = []
    domain = _sender_domain(msg)
    if not domain:
        return findings
    if domain in BRAND_DOMAINS.values() or any(
        domain.endswith("." + real_domain) for real_domain in BRAND_DOMAINS.values()
    ):
        return findings
    for brand, real_domain in BRAND_DOMAINS.items():
        similarity = difflib.SequenceMatcher(None, domain, real_domain).ratio()
        if similarity > 0.80:
            findings.append(
                (f"Sender domain '{domain}' closely resembles '{real_domain}' ({brand}) — possible typosquat", 30)
            )
    return findings


def check_subdomain_abuse(msg):
    findings = []
    domain = _sender_domain(msg)
    if not domain:
        return findings
    tokens = re.split(r"[.\-]", domain)
    for brand, real_domain in BRAND_DOMAINS.items():
        if domain == real_domain or domain.endswith("." + real_domain):
            continue
        brand_key = brand.replace(" ","")
        if any(
            token == brand_key
            or (
                brand_key not in AMBIGUOUS_BRAND_KEYS
                and (token.startswith(brand_key) or token.endswith(brand_key))
            )
            for token in tokens
        ):
            findings.append(
                (f"Domain '{domain}' contains brand '{brand}' but isn't the real domain - possible subdomain abuse", 30)
            )
    return findings


def check_urls(body):
    findings = []
    urls = URL_RE.findall(body)
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if IP_URL_RE.match(url):
            findings.append((f"URL uses raw IP address: {url}", 25))
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


def check_attachments(msg):
    findings = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            lower_name = filename.lower()
            for ext in DANGEROUS_EXTENSIONS:
                if lower_name.endswith(ext):
                    findings.append((f"Suspicious attachment: {filename}", 25))
                    break
    return findings


def analyse(path):
    msg = load_email(path)
    subject = msg.get("Subject", "")
    body = get_body(msg)

    categories = [
        check_auth_results(msg),
        check_from_replyto_mismatch(msg),
        check_display_name(msg),
        check_typosquat_domain(msg),
        check_subdomain_abuse(msg),
        check_urls(body),
        check_urgency_language(subject, body),
        check_attachments(msg),
    ]

    findings = []
    score = 0
    for cat_findings in categories:
        findings += cat_findings
        score += min(sum(w for _, w in cat_findings), CATEGORY_CAP)
    score = min(score, 100)

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
    try:
        analyse(sys.argv[1])
    except FileNotFoundError:
        print(f"File not found: {sys.argv[1]}")
        sys.exit(1)