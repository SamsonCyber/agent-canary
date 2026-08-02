"""Honeypot content templates for Agent Canary.

Each template function takes a canary_id and returns file content as a string.
The canary_id is embedded in each output so triggered files can be traced back
to their registered canary.
"""
from __future__ import annotations

import hashlib
import textwrap
from typing import Callable


def aws_creds(canary_id: str) -> str:
    """Generate a fake .env file with AWS credentials."""
    h = hashlib.sha256(canary_id.encode()).hexdigest()
    access_key = f"AKIACANARY{h[:10].upper()}"
    secret_key = h[:40]
    return textwrap.dedent(f"""\
        # Auto-generated config — do not commit
        # tracking: {canary_id}
        AWS_ACCESS_KEY_ID={access_key}
        AWS_SECRET_ACCESS_KEY={secret_key}
        AWS_REGION=us-east-1
        AWS_DEFAULT_OUTPUT=json
    """)


def db_creds(canary_id: str) -> str:
    """Generate a fake database.yml with production/staging blocks."""
    h = hashlib.sha256(canary_id.encode()).hexdigest()
    host_hash = h[:12]
    password_prod = h[:20]
    password_staging = h[20:40]
    return textwrap.dedent(f"""\
        # Database configuration
        # canary_ref: {canary_id}

        production:
          adapter: postgresql
          host: canary-db-{host_hash}.internal
          port: 5432
          database: app_production
          username: deploy_user
          password: {password_prod}
          pool: 25
          timeout: 5000

        staging:
          adapter: postgresql
          host: canary-db-{host_hash}-stg.internal
          port: 5432
          database: app_staging
          username: deploy_user
          password: {password_staging}
          pool: 10
          timeout: 5000
    """)


def ssh_key(canary_id: str) -> str:
    """Generate a fake RSA private key with canary_id in the base64 block."""
    h = hashlib.sha256(canary_id.encode()).hexdigest()
    # Build fake base64 lines from the hash, repeating to look plausible
    chunk = h + h  # 128 hex chars
    lines = []
    for i in range(0, len(chunk), 64):
        lines.append(chunk[i : i + 64])
    # Embed the canary_id as a comment-safe b64 line
    encoded_id = canary_id.replace(":", "")[:60].ljust(64, "=")
    lines.insert(1, encoded_id)
    body = "\n".join(lines)
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{body}\n"
        "-----END RSA PRIVATE KEY-----\n"
    )


def api_keys(canary_id: str) -> str:
    """Generate YAML with fake third-party API keys."""
    h = hashlib.sha256(canary_id.encode()).hexdigest()
    return textwrap.dedent(f"""\
        # Service API keys — CONFIDENTIAL
        # ref: {canary_id}

        stripe:
          secret_key: sk_live_canary{h[:24]}
          publishable_key: pk_live_canary{h[24:48]}

        openai:
          api_key: sk-canary{h[:32]}

        github:
          personal_access_token: ghp_canary{h[:30]}
    """)


def pii_data(canary_id: str) -> str:
    """Generate a CSV with 5 rows of fake PII data."""
    h = hashlib.sha256(canary_id.encode()).hexdigest()
    rows = [
        "name,email,ssn,phone",
        f"Jane Doe,jane.doe@fakecorp-{h[:6]}.test,078-05-1120,(555) 100-0001",
        f"John Smith,john.smith@fakecorp-{h[:6]}.test,219-09-9999,(555) 100-0002",
        f"Alice Canary,alice@fakecorp-{h[:6]}.test,987-65-4320,(555) 100-0003",
        f"Bob Tripwire,bob.t@fakecorp-{h[:6]}.test,111-22-3333,(555) 100-0004",
        f"Carol Beacon,carol.b@fakecorp-{h[:6]}.test,000-12-3456,(555) 100-0005",
    ]
    # Embed canary_id inside a plausible data row (not a comment that breaks CSV parsers)
    rows.append(f"System Canary,canary-{h[:8]}@fakecorp-{h[:6]}.test,000-00-{h[:4]},(555) 100-{h[4:8]}")
    return "\n".join(rows) + "\n"


def internal_doc(canary_id: str) -> str:
    """Generate a markdown internal architecture document."""
    return textwrap.dedent(f"""\
        # Internal Architecture

        **Status**: Draft — do not distribute externally.

        ## Overview

        The platform uses a microservices architecture with gRPC for
        inter-service communication and Redis for pub/sub eventing.
        Authentication flows through a central identity gateway that
        issues short-lived JWTs (15 min TTL) with refresh rotation.

        ## Service Map

        | Service         | Port  | Owner        |
        |-----------------|-------|--------------|
        | identity-gw     | 8443  | platform     |
        | billing-svc     | 8080  | payments     |
        | analytics-ingest| 9090  | data-eng     |
        | ml-inference    | 8501  | ml-platform  |

        ## Tracking

        Document tracking identifier: {canary_id}

        This identifier is used for internal audit trail purposes.
        If you encounter this document outside approved channels,
        contact security@internal.corp immediately.
    """)


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, Callable[[str], str]] = {
    "aws_creds": aws_creds,
    "db_creds": db_creds,
    "ssh_key": ssh_key,
    "api_keys": api_keys,
    "pii_data": pii_data,
    "internal_doc": internal_doc,
}


def get_template(name: str) -> Callable[[str], str]:
    """Return the generator function for the named template.

    Raises KeyError if the template name is not recognized.
    """
    return _TEMPLATES[name]


def list_templates() -> list[str]:
    """Return the names of all available templates."""
    return list(_TEMPLATES.keys())
