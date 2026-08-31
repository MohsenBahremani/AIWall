# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
import secrets
import string

import pytest

from app.scanners.secrets import SecretScanner, scan_request_body

AWS_DOC_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


def _random_aws_key() -> str:
    suffix = "".join(secrets.choice(string.digits + string.ascii_uppercase) for _ in range(16))
    return "AKIA" + suffix


def _fake_slack_token() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    return "slack " + "-".join(["xoxb", "1" * 11, "2" * 12, body])


def _fake_stripe_secret_key() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    return "stripe sk_live_" + body


def _fake_stripe_restricted_key() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    return "stripe rk_live_" + body


def _fake_google_api_key() -> str:
    # Alphanumeric suffix only: a trailing '-' breaks the regex word boundary (\b).
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(35))
    return "google AIza" + body


def _fake_azure_storage_key() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits + "+/=") for _ in range(44))
    return "azure AccountKey=" + body


def _fake_gcp_service_account() -> str:
    return 'gcp {"type": "service_account", "project_id": "demo"}'


def _fake_database_url() -> str:
    password = secrets.token_urlsafe(12)
    return f"db postgres://dbuser:{password}@127.0.0.1:5432/app"


def _fake_pkcs8_private_key() -> str:
    return "key -----BEGIN PRIVATE KEY-----\nabc"


def _fake_encrypted_private_key() -> str:
    return "key -----BEGIN ENCRYPTED PRIVATE KEY-----\nabc"


_RULE_SAMPLES = {
    "slack-token": _fake_slack_token,
    "stripe-secret-key": _fake_stripe_secret_key,
    "stripe-restricted-key": _fake_stripe_restricted_key,
    "google-api-key": _fake_google_api_key,
    "azure-storage-key": _fake_azure_storage_key,
    "gcp-service-account": _fake_gcp_service_account,
    "database-url": _fake_database_url,
    "pkcs8-private-key": _fake_pkcs8_private_key,
    "encrypted-private-key": _fake_encrypted_private_key,
}


def test_secret_scanner_detects_aws_key() -> None:
    scanner = SecretScanner()
    result = scanner.scan(f"my key is {_random_aws_key()}")

    assert result.contains_secret is True
    assert any(match.rule_id == "aws-access-key" for match in result.matches)


def test_secret_scanner_ignores_aws_documentation_example() -> None:
    scanner = SecretScanner()
    result = scanner.scan(f"from the AWS docs: {AWS_DOC_EXAMPLE}")

    assert result.contains_secret is False


def test_secret_scanner_detects_github_token() -> None:
    scanner = SecretScanner()
    body = "ghp_" + secrets.token_hex(18)
    result = scanner.scan("token " + body)

    assert result.contains_secret is True
    assert any(match.rule_id == "github-token" for match in result.matches)


def test_secret_scanner_detects_ssh_private_key() -> None:
    scanner = SecretScanner()
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"
    result = scanner.scan(text)

    assert result.contains_secret is True
    assert any(match.rule_id == "ssh-private-key" for match in result.matches)


def test_secret_scanner_ignores_clean_text() -> None:
    scanner = SecretScanner()
    result = scanner.scan("hello from a normal prompt")

    assert result.contains_secret is False
    assert result.matches == ()


def test_scan_request_body_from_chat_payload() -> None:
    body = (
        b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"key '
        + _random_aws_key().encode()
        + b'"}]}'
    )
    result = scan_request_body(body)

    assert result.contains_secret is True


@pytest.mark.parametrize("rule_id", list(_RULE_SAMPLES))
def test_secret_scanner_detects_expanded_rule_pack(rule_id: str) -> None:
    text = _RULE_SAMPLES[rule_id]()
    result = SecretScanner().scan(text)

    assert result.contains_secret is True
    assert any(match.rule_id == rule_id for match in result.matches)
    assert all(match.rule_id for match in result.matches)
