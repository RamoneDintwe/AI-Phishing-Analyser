# AI Phishing Analyser

A lightweight, rules-based phishing detection tool for `.eml` email files, built for the South African context — it recognises local banks, government services (SARS, SASSA, SAPS, Home Affairs), telecoms, and retailers by name, not just generic phishing patterns.

**MVP status:** this is a regex/header-parsing heuristic tool, not a machine-learning classifier. It does not perform live DNS lookups, attachment content scanning, or URL reputation checks — it flags red flags based on message structure and known-brand comparison.

---

## Requirements

- Python 3.10+ (developed and tested on 3.14.7)
- No external dependencies — uses only the Python standard library (`email`, `difflib`, `re`, `urllib.parse`)

## Usage

```bash
python main.py path/to/email.eml
```

The tool prints the subject, sender, a risk score out of 100, a verdict (LOW / MEDIUM / HIGH RISK), and a breakdown of every flag raised with its point weight.

---

## How scoring works

Each detection check belongs to a category. Findings within a single category are summed and capped at **50 points** (`CATEGORY_CAP`) so that one noisy category (e.g. a message with several suspicious URLs) can't single-handedly dominate the score. Category totals are then summed and capped at **100 points** overall.

| Score | Verdict |
|---|---|
| 60–100 | HIGH RISK |
| 30–59 | MEDIUM RISK |
| 0–29 | LOW RISK |

---

## What it checks

**Authentication-Results header**
Flags SPF, DKIM, or DMARC results of `fail` or `softfail` (+20 each). A completely missing `Authentication-Results` header carries a small flat penalty (+5) — this is a light heuristic, not a substitute for real DMARC alignment checking, since the tool doesn't perform its own DNS-based verification.

**Reply-To mismatch**
Flags when the `Reply-To` address domain differs from the `From` address domain (+25) — a common tell in phishing that wants replies routed away from the spoofed sender.

**Display name spoofing**
Flags when the visible display name references a known brand (e.g. "FNB Online Banking") but the actual sending domain doesn't match that brand (+30).

**Typosquat domain detection**
Compares the sender's domain against ~55 known South African and international brand domains using string similarity. A domain that closely resembles a real brand domain without being an exact match or legitimate subdomain of it is flagged (+30). Genuine brand domains and their subdomains (e.g. `secure.fnb.co.za`) are excluded from this check.

**Subdomain abuse**
Flags domains that stuff a brand name into an unrelated domain (e.g. `fnb-security-alert.co.za`) without being a real subdomain of that brand (+30). Brand names that are also common English words (e.g. "rain", "gems", "visa", "apple") are matched more conservatively to avoid false positives on unrelated domains.

**Suspicious URLs**
- Raw IP address instead of a domain name (+25)
- Known URL shorteners — bit.ly, tinyurl.com, etc. (+15)
- Punycode domains, a common homograph/lookalike-character technique (+30)

**Urgency/pressure language**
Flags common phishing pressure tactics, including South Africa–specific phrasing ("SARS refund", "SASSA grant suspended", "e-toll fine", "load shedding rebate", etc.). Up to 3 distinct phrases are scored per message (+10 each).

**Dangerous attachments**
Flags attachments with executable or macro-enabled extensions (`.exe`, `.scr`, `.js`, `.docm`, `.ps1`, etc.) (+25). This checks the filename extension only, not the file contents.

---

## Known limitations

- No live DNS/SPF/DKIM/DMARC verification — relies entirely on the `Authentication-Results` header already present in the `.eml` file, as set by the receiving mail server.
- No attachment content scanning — only the filename extension is checked.
- No live URL reputation or sandboxing — shortener and punycode detection are pattern-based only.
- The 55-brand list is not exhaustive; domains outside it won't trigger typosquat or subdomain-abuse checks.

---

## Testing

```bash
python -m pytest -v
```

The test suite covers all detection functions individually plus end-to-end scenarios against real-world-style phishing examples (FNB, SARS, SASSA, Nedbank, Absa, PayPal) and legitimate mail, to confirm the tool doesn't flag genuine correspondence.

---

## License

See [LICENSE](LICENSE).

---

*MotseNova — Ramone Dintwe*
