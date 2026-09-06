"""
Shared fixtures for the AI Phishing Analyser test suite.
"""
import email.message
import email.policy

import pytest


def build_msg(
    from_header,
    subject="Test subject",
    body="Hello, this is a test email body.",
    reply_to=None,
    auth_results=None,
    attachments=None,
):
    """Build an in-memory EmailMessage for unit-testing check_* functions
    that take an already-parsed msg object."""
    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = from_header
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth_results:
        msg["Authentication-Results"] = auth_results
    msg.set_content(body)

    for filename, data in (attachments or {}).items():
        msg.add_attachment(
            data, maintype="application", subtype="octet-stream", filename=filename
        )
    return msg


def write_eml(tmp_path, msg, name="test.eml"):
    """Serialise an EmailMessage to a real .eml file on disk, since
    load_email()/analyse() operate on file paths, not msg objects."""
    path = tmp_path / name
    path.write_bytes(bytes(msg))
    return str(path)


@pytest.fixture
def msg_factory():
    return build_msg


@pytest.fixture
def eml_factory(tmp_path):
    def _make(msg, name="test.eml"):
        return write_eml(tmp_path, msg, name)
    return _make