"""
Test suite for AI Phishing Analyser main.py

Two xfail tests below are NOT broken tests — they document real bugs
found in main.py during review. Do not "fix" them by weakening the
assertion; fix main.py instead (see the reason= string on each).
"""
import pytest

from main import (
    analyse,
    check_attachments,
    check_auth_results,
    check_display_name,
    check_from_replyto_mismatch,
    check_subdomain_abuse,
    check_typosquat_domain,
    check_urgency_language,
    check_urls,
)

# ---------------------------------------------------------------------------
# check_display_name
# ---------------------------------------------------------------------------

def test_display_name_flags_brand_mismatch(msg_factory):
    msg = msg_factory('"FNB Online Banking" <support@randomscamsite.com>')
    findings = check_display_name(msg)
    assert findings, "Display name claims FNB but domain is unrelated — should flag"


def test_display_name_no_flag_when_domain_matches(msg_factory):
    msg = msg_factory('"FNB Online Banking" <support@fnb.co.za>')
    findings = check_display_name(msg)
    assert findings == [], "Genuine FNB domain should not be flagged"


# ---------------------------------------------------------------------------
# check_typosquat_domain
# ---------------------------------------------------------------------------

def test_typosquat_flags_close_domain(msg_factory):
    msg = msg_factory('"Nedbank" <alerts@nedbnk.co.za>')  # missing 'a'
    findings = check_typosquat_domain(msg)
    assert findings, "nedbnk.co.za is a near-miss of nedbank.co.za — should flag"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG in check_typosquat_domain: the 0.80 similarity threshold is "
        "too loose for a 55-brand list containing short, similar SA "
        "institution domains. Confirmed cross-brand collisions: "
        "nedbank.co.za<->tymebank.co.za (0.81), sars.gov.za<->sassa.gov.za "
        "(0.87), sars.gov.za<->saps.gov.za (0.91), sassa.gov.za<->saps.gov.za "
        "(0.87). A GENUINE email from SARS will flag itself as impersonating "
        "SASSA or SAPS, and vice versa — exactly the three institutions this "
        "project's fixtures are built around. Fix: raise the threshold "
        "(0.90+), or skip comparison entirely when domain is itself a known "
        "real_domain value in BRAND_DOMAINS."
    ),
)
def test_typosquat_no_flag_for_real_domain(msg_factory):
    msg = msg_factory('"Nedbank" <alerts@nedbank.co.za>')
    findings = check_typosquat_domain(msg)
    assert findings == [], "The real domain should never flag itself"


# ---------------------------------------------------------------------------
# check_subdomain_abuse — includes two documented bugs (xfail)
# ---------------------------------------------------------------------------

def test_subdomain_abuse_flags_genuine_abuse(msg_factory):
    msg = msg_factory('"FNB Security" <alerts@fnb-security-alert.co.za>')
    findings = check_subdomain_abuse(msg)
    assert findings, "Brand name stuffed into an unrelated domain should flag"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG in check_subdomain_abuse: flags legitimate brand subdomains "
        "(e.g. secure.fnb.co.za) because it only checks domain != real_domain "
        "exactly, never domain.endswith('.' + real_domain). Every SA bank "
        "that uses a subdomain for online banking will be flagged as abuse. "
        "Fix: skip when domain == real_domain OR domain.endswith('.' + real_domain)."
    ),
)
def test_subdomain_abuse_should_not_flag_legit_subdomain(msg_factory):
    msg = msg_factory('"FNB" <notifications@secure.fnb.co.za>')
    findings = check_subdomain_abuse(msg)
    assert findings == [], "secure.fnb.co.za is a legitimate FNB subdomain"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG in check_subdomain_abuse: brand keys that are common English "
        "words ('rain', 'gems') false-positive on unrelated domains via "
        "plain substring match, e.g. 'onlinetraininghub.co.za' contains "
        "'rain'. Fix: require a word/label boundary, or drop short common-"
        "word brand keys from substring-based checks."
    ),
)
def test_subdomain_abuse_should_not_flag_common_word_collision(msg_factory):
    msg = msg_factory('"Training Hub" <info@onlinetraininghub.co.za>')
    findings = check_subdomain_abuse(msg)
    assert findings == [], "'training' contains 'rain' but has nothing to do with rain.co.za"


# ---------------------------------------------------------------------------
# check_auth_results — includes one documented design gap (xfail)
# ---------------------------------------------------------------------------

def test_auth_results_flags_spf_fail(msg_factory):
    msg = msg_factory(
        "notifications@fnb.co.za",
        auth_results="mx.google.com; spf=fail smtp.mailfrom=fnb.co.za; dkim=pass; dmarc=pass",
    )
    findings = check_auth_results(msg)
    assert findings, "SPF fail should be flagged"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "DESIGN GAP, not yet implemented: a completely missing "
        "Authentication-Results header currently scores 0. Prior review "
        "recommended a small (~5pt) penalty for missing SPF/DKIM/DMARC "
        "entirely, since SA institutions (banks, SARS, SASSA) publish "
        "these records and legitimate mail should have the header present."
    ),
)
def test_auth_results_missing_header_should_carry_some_risk(msg_factory):
    msg = msg_factory("notifications@fnb.co.za")  # no auth_results at all
    findings = check_auth_results(msg)
    assert findings, "Missing auth entirely should not be scored identically to a clean pass"


# ---------------------------------------------------------------------------
# check_from_replyto_mismatch
# ---------------------------------------------------------------------------

def test_replyto_mismatch_flags_different_domain(msg_factory):
    msg = msg_factory("notifications@fnb.co.za", reply_to="collect@totallydifferent.com")
    findings = check_from_replyto_mismatch(msg)
    assert findings


def test_replyto_no_flag_same_domain(msg_factory):
    msg = msg_factory("notifications@fnb.co.za", reply_to="support@fnb.co.za")
    findings = check_from_replyto_mismatch(msg)
    assert findings == []


# ---------------------------------------------------------------------------
# check_urls
# ---------------------------------------------------------------------------

def test_urls_flags_raw_ip():
    findings = check_urls("Click here: http://192.168.1.5/login")
    assert findings


def test_urls_flags_shortener():
    findings = check_urls("Verify now: http://bit.ly/xyz123")
    assert findings


def test_urls_flags_punycode():
    findings = check_urls("Login: http://xn--fnb-hd0a.co.za/login")
    assert findings


def test_urls_no_flag_clean_link():
    findings = check_urls("View your statement: https://fnb.co.za/statements")
    assert findings == []


# ---------------------------------------------------------------------------
# check_urgency_language
# ---------------------------------------------------------------------------

def test_urgency_language_detects_sa_phrases():
    findings = check_urgency_language(
        "SARS refund pending",
        "Please verify your sassa grant immediately or your account will be closed",
    )
    assert findings


def test_urgency_language_no_flag_neutral_text():
    findings = check_urgency_language(
        "Your monthly statement",
        "Attached is your statement for the period ending 31 July.",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# check_attachments
# ---------------------------------------------------------------------------

def test_attachments_flags_dangerous_extension(msg_factory):
    msg = msg_factory("notifications@fnb.co.za", attachments={"invoice.exe": b"fake"})
    findings = check_attachments(msg)
    assert findings


def test_attachments_no_flag_pdf(msg_factory):
    msg = msg_factory("notifications@fnb.co.za", attachments={"statement.pdf": b"%PDF-fake"})
    findings = check_attachments(msg)
    assert findings == []


# ---------------------------------------------------------------------------
# End-to-end analyse() — SA brand scenarios
# ---------------------------------------------------------------------------

def test_analyse_legit_fnb_statement_is_low_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"FNB" <notifications@fnb.co.za>',
        subject="Your July statement is ready",
        body="Your FNB account statement for July is now available in the app.",
        reply_to="notifications@fnb.co.za",
        auth_results="mx.example.com; spf=pass; dkim=pass; dmarc=pass",
    )
    path = eml_factory(msg, "fnb_legit.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "LOW RISK" in out


def test_analyse_fnb_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"FNB Online Banking" <alerts@fnbb.co.za>',
        subject="URGENT: Verify your account",
        body=(
            "Your account will be closed. Click here to verify your identity "
            "immediately: http://192.168.5.20/fnb-login"
        ),
        reply_to="collect@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail",
        attachments={"statement.exe": b"fake"},
    )
    path = eml_factory(msg, "fnb_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out


def test_analyse_sars_refund_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"SARS eFiling" <refunds@sars-efiling-refund.com>',
        subject="SARS refund - action required",
        body="Your sars refund is pending. sars efiling verification suspended, act now.",
        reply_to="payout@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=pass; dmarc=fail",
    )
    path = eml_factory(msg, "sars_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out


def test_analyse_sassa_grant_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"SASSA Grants" <support@sassa-grants-portal.co.za>',
        subject="Your sassa grant is suspended",
        body="verify your sassa grant suspended immediately, click here to confirm your identity.",
        reply_to="claims@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=softfail; dmarc=fail",
    )
    path = eml_factory(msg, "sassa_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out


def test_analyse_nedbank_typosquat_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"Nedbank" <alerts@nedbnk.co.za>',
        subject="Unusual activity on your account",
        body="Unusual activity detected. Your account will be closed, act now.",
        reply_to="fraud@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail",
        attachments={"security-notice.scr": b"fake"},
    )
    path = eml_factory(msg, "nedbank_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out


def test_analyse_absa_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"Absa Bank" <verify@absa-online-verify.co.za>',
        subject="Confirm your identity - Absa",
        body="Please confirm your identity immediately: http://192.168.9.9/absa-verify",
        reply_to="verify@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=pass",
    )
    path = eml_factory(msg, "absa_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out


def test_analyse_paypal_phishing_is_high_risk(msg_factory, eml_factory, capsys):
    msg = msg_factory(
        '"PayPal" <service@paypal-account-alert.com>',
        subject="Unusual activity - confirm your identity",
        body=(
            "We noticed unusual activity. Confirm your identity now: "
            "http://bit.ly/pp-verify or your account will be closed."
        ),
        reply_to="service@totallydifferent.com",
        auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail",
    )
    path = eml_factory(msg, "paypal_phish.eml")
    analyse(path)
    out = capsys.readouterr().out
    assert "HIGH RISK" in out