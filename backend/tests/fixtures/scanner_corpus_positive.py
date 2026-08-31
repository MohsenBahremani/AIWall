# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Positive secret-scanner corpus.

Samples are built at runtime so source files do not contain push-protection
false positives. Every supported rule_id must have a generator here.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Callable


def _rand_alnum(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _rand_aws_key() -> str:
    suffix = "".join(secrets.choice(string.digits + string.ascii_uppercase) for _ in range(16))
    return "AKIA" + suffix


def sample_aws_access_key() -> str:
    return f"my aws key is {_rand_aws_key()}"


def sample_github_token() -> str:
    return "token ghp_" + secrets.token_hex(18)


def sample_github_fine_grained_token() -> str:
    return "token github_pat_" + _rand_alnum(22)


def sample_slack_token() -> str:
    body = _rand_alnum(24)
    return "slack " + "-".join(["xoxb", "1" * 11, "2" * 12, body])


def sample_stripe_secret_key() -> str:
    return "stripe sk_live_" + _rand_alnum(24)


def sample_stripe_restricted_key() -> str:
    return "stripe rk_live_" + _rand_alnum(24)


def sample_google_api_key() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(35))
    return "google AIza" + body


def sample_azure_storage_key() -> str:
    alphabet = string.ascii_letters + string.digits + "+/="
    body = "".join(secrets.choice(alphabet) for _ in range(44))
    return "azure AccountKey=" + body


def sample_gcp_service_account() -> str:
    return 'gcp {"type": "service_account", "project_id": "demo"}'


def sample_database_url() -> str:
    password = secrets.token_urlsafe(12)
    return f"db postgres://dbuser:{password}@127.0.0.1:5432/app"


def sample_ssh_private_key() -> str:
    return "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"


def sample_pkcs8_private_key() -> str:
    return "-----BEGIN PRIVATE KEY-----\nabc"


def sample_encrypted_private_key() -> str:
    return "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc"


def sample_jwt() -> str:
    return (
        "bearer eyJ"
        + _rand_alnum(20)
        + "."
        + _rand_alnum(20)
        + "."
        + _rand_alnum(20)
    )


def sample_generic_api_key() -> str:
    return "api_key=" + _rand_alnum(20)


def sample_dotenv_secret() -> str:
    return "\n".join(
        [
            f"DATABASE_URL=postgres://dbuser:{secrets.token_urlsafe(10)}@127.0.0.1:5432/app",
            f"REDIS_URL=redis://cache:{secrets.token_urlsafe(10)}@127.0.0.1:6379/0",
            f"OPENAI_API_KEY=sk-proj-{_rand_alnum(28)}",
        ]
    )


def sample_high_entropy() -> str:
    alphabet = string.ascii_letters + string.digits + "+/="
    token = "".join(secrets.choice(alphabet) for _ in range(40))
    return f"token {token}"


POSITIVE_SAMPLES: dict[str, Callable[[], str]] = {
    "aws-access-key": sample_aws_access_key,
    "github-token": sample_github_token,
    "github-fine-grained-token": sample_github_fine_grained_token,
    "slack-token": sample_slack_token,
    "stripe-secret-key": sample_stripe_secret_key,
    "stripe-restricted-key": sample_stripe_restricted_key,
    "google-api-key": sample_google_api_key,
    "azure-storage-key": sample_azure_storage_key,
    "gcp-service-account": sample_gcp_service_account,
    "database-url": sample_database_url,
    "ssh-private-key": sample_ssh_private_key,
    "pkcs8-private-key": sample_pkcs8_private_key,
    "encrypted-private-key": sample_encrypted_private_key,
    "jwt": sample_jwt,
    "generic-api-key": sample_generic_api_key,
    "dotenv-secret": sample_dotenv_secret,
    "high-entropy": sample_high_entropy,
}
