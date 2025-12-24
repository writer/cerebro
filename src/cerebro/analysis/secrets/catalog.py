"""Secret classification catalog."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class SecretFamily(str, Enum):
    """Known secret families supported by validation heuristics."""

    OPENAI = "openai_api_key"
    OKTA = "okta_api_token"
    AWS_ACCESS_KEY = "aws_access_key_id"
    AWS_SECRET_KEY = "aws_secret_access_key"
    GITHUB_TOKEN = "github_token"
    GENERIC = "generic_secret"


@dataclass(frozen=True)
class SecretDescriptor:
    """Descriptor containing heuristics for a secret family."""

    family: SecretFamily
    display_name: str
    keywords: Iterable[str]
    patterns: Iterable[re.Pattern]
    graph_controls: Iterable[str] = ()


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


SECRET_CATALOG: dict[SecretFamily, SecretDescriptor] = {
    SecretFamily.OPENAI: SecretDescriptor(
        family=SecretFamily.OPENAI,
        display_name="OpenAI API key",
        keywords=("openai", "sk-"),
        patterns=(_compile(r"sk-[a-zA-Z0-9]{32,}"),),
        graph_controls=("GC-SECRETS-OPENAI-001",),
    ),
    SecretFamily.OKTA: SecretDescriptor(
        family=SecretFamily.OKTA,
        display_name="Okta API token",
        keywords=("okta",),
        patterns=(_compile(r"00[a-z0-9]{20,}"),),
        graph_controls=("GC-SECRETS-OKTA-001",),
    ),
    SecretFamily.AWS_ACCESS_KEY: SecretDescriptor(
        family=SecretFamily.AWS_ACCESS_KEY,
        display_name="AWS access key ID",
        keywords=("aws_access_key", "akia"),
        patterns=(_compile(r"AKIA[0-9A-Z]{16}"),),
        graph_controls=("GC-SECRETS-AWS-ACCESS-KEY",),
    ),
    SecretFamily.AWS_SECRET_KEY: SecretDescriptor(
        family=SecretFamily.AWS_SECRET_KEY,
        display_name="AWS secret access key",
        keywords=("aws_secret",),
        patterns=(_compile(r"[A-Za-z0-9/+]{40}"),),
        graph_controls=("GC-SECRETS-AWS-SECRET-KEY",),
    ),
    SecretFamily.GITHUB_TOKEN: SecretDescriptor(
        family=SecretFamily.GITHUB_TOKEN,
        display_name="GitHub personal access token",
        keywords=("github", "ghp_"),
        patterns=(_compile(r"gh[pousr]_[A-Za-z0-9]{36}"),),
        graph_controls=("GC-SECRETS-GITHUB-TOKEN",),
    ),
    SecretFamily.GENERIC: SecretDescriptor(
        family=SecretFamily.GENERIC,
        display_name="Sensitive credential",
        keywords=(),
        patterns=(),
        graph_controls=(),
    ),
}


def identify_secret_family(
    secret_type: str | None, raw_result: dict[str, object] | None
) -> SecretDescriptor:
    """Return descriptor for the best matching secret family."""

    lowered_type = (secret_type or "").lower()
    raw_detector = "".join(str(value).lower() for value in (raw_result or {}).values())

    for descriptor in SECRET_CATALOG.values():
        if descriptor.family is SecretFamily.GENERIC:
            continue
        if any(keyword in lowered_type for keyword in descriptor.keywords):
            return descriptor
        if any(keyword in raw_detector for keyword in descriptor.keywords):
            return descriptor

    return SECRET_CATALOG[SecretFamily.GENERIC]
