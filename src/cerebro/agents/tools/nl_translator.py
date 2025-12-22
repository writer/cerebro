"""Natural language to SQL translation adapters."""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from typing import Callable, Iterable, Optional, Pattern, Tuple

import structlog

logger = structlog.get_logger(__name__)


class TranslationError(Exception):
    """Base exception for translation failures."""


class TranslationUnavailableError(TranslationError):
    """Raised when the primary translator cannot be used."""


class SQLTranslator(ABC):
    """Abstract base class for natural language SQL translators."""

    @abstractmethod
    async def translate(
        self,
        *,
        question: str,
        limit: int,
        schema: str,
        examples: str,
    ) -> str:
        """Translate a natural language question into SQL."""


class AnthropicSQLTranslator(SQLTranslator):
    """Anthropic-backed SQL translator."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        max_tokens: int,
        temperature: float,
    ) -> None:
        try:
            from anthropic import Anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise TranslationUnavailableError(
                "anthropic package is not installed"
            ) from exc

        if not api_key:
            raise TranslationUnavailableError("Anthropic API key is not configured")

        self._client = Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature

    async def translate(
        self,
        *,
        question: str,
        limit: int,
        schema: str,
        examples: str,
    ) -> str:
        prompt = _build_prompt(
            question=question, limit=limit, schema=schema, examples=examples
        )

        try:
            message = await asyncio.to_thread(
                self._client.messages.create,
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # pragma: no cover - network failures
            raise TranslationError(f"Anthropic translation failed: {exc}") from exc

        try:
            sql_query = message.content[0].text.strip()
        except Exception as exc:  # pragma: no cover - defensive
            raise TranslationError(
                "Anthropic response did not include text content"
            ) from exc

        sql_query = sql_query.replace("```sql", "").replace("```", "").strip()
        if not sql_query.lower().endswith(";"):
            sql_query = f"{sql_query};"
        return sql_query


FallbackRule = Tuple[Pattern[str], Callable[[int], str]]


def _default_rules() -> Tuple[FallbackRule, ...]:
    return (
        (
            re.compile(r"mfa|multi[-\s]?factor", re.IGNORECASE),
            lambda limit: (
                "SELECT user_name, arn, mfa_enabled "
                "FROM aws_iam_user WHERE mfa_enabled = false ORDER BY user_name LIMIT {limit}"
            ).format(limit=limit),
        ),
        (
            re.compile(r"s3|bucket", re.IGNORECASE),
            lambda limit: (
                "SELECT bucket_name, region, public_access "
                "FROM aws_s3_bucket WHERE public_access = true ORDER BY bucket_name LIMIT {limit}"
            ).format(limit=limit),
        ),
        (
            re.compile(r"critical|high severity|findings", re.IGNORECASE),
            lambda limit: (
                "SELECT id, title, severity, status, created_at "
                "FROM findings WHERE severity = 'critical' ORDER BY created_at DESC LIMIT {limit}"
            ).format(limit=limit),
        ),
        (
            re.compile(r"admin|privileged", re.IGNORECASE),
            lambda limit: (
                "SELECT role_name, arn, permissions "
                "FROM aws_iam_role WHERE permissions::text LIKE '%AdministratorAccess%' "
                "ORDER BY role_name LIMIT {limit}"
            ).format(limit=limit),
        ),
        (
            re.compile(r"lambda", re.IGNORECASE),
            lambda limit: (
                "SELECT function_name, runtime, environment_variables "
                "FROM aws_lambda_function WHERE environment_variables IS NOT NULL "
                "AND jsonb_typeof(environment_variables) = 'object' ORDER BY function_name LIMIT {limit}"
            ).format(limit=limit),
        ),
    )


class StaticFallbackTranslator(SQLTranslator):
    """Deterministic rule-based translator used as fallback."""

    def __init__(self, rules: Optional[Iterable[FallbackRule]] = None) -> None:
        self._rules: Tuple[FallbackRule, ...] = (
            tuple(rules) if rules else _default_rules()
        )

    async def translate(
        self,
        *,
        question: str,
        limit: int,
        schema: str,  # noqa: ARG002 - unused
        examples: str,  # noqa: ARG002 - unused
    ) -> str:
        normalized_question = question.strip()
        for pattern, builder in self._rules:
            if pattern.search(normalized_question):
                query = builder(limit)
                logger.debug(
                    "Fallback rule matched", pattern=pattern.pattern, query=query
                )
                return _finalize_query(query)

        default_query = (
            "SELECT id, title, severity, status, created_at "
            "FROM findings ORDER BY created_at DESC LIMIT {limit}"
        ).format(limit=limit)
        logger.debug("Fallback translator using default query", query=default_query)
        return _finalize_query(default_query)


class CompositeTranslator(SQLTranslator):
    """Feature-flag aware translator with fallback support."""

    def __init__(
        self,
        *,
        primary: Optional[SQLTranslator],
        fallback: SQLTranslator,
    ) -> None:
        self._primary = primary
        self._fallback = fallback

    async def translate(
        self,
        *,
        question: str,
        limit: int,
        schema: str,
        examples: str,
    ) -> str:
        if self._primary is not None:
            try:
                return await self._primary.translate(
                    question=question,
                    limit=limit,
                    schema=schema,
                    examples=examples,
                )
            except TranslationError as exc:
                logger.warning(
                    "Primary translator failed; using fallback",
                    error=str(exc),
                    translator=self._primary.__class__.__name__,
                )

        return await self._fallback.translate(
            question=question,
            limit=limit,
            schema=schema,
            examples=examples,
        )


def build_translator(settings) -> SQLTranslator:
    """Factory for SQL translators honoring feature flags."""

    fallback = StaticFallbackTranslator()

    if not getattr(settings, "enable_nl_query_translation", True):
        logger.info("NL query translation disabled; using fallback translator")
        return fallback

    api_key = getattr(settings, "anthropic_api_key", None)
    if not api_key:
        logger.warning("Anthropic API key missing; using fallback translator")
        return fallback

    try:
        primary = AnthropicSQLTranslator(
            api_key=api_key,
            model=getattr(settings, "claude_model", "claude-3-5-sonnet-20241022"),
            max_tokens=getattr(settings, "claude_max_tokens", 1024),
            temperature=getattr(settings, "claude_temperature", 0.0),
        )
    except TranslationError as exc:
        logger.warning(
            "Failed to initialize Anthropic translator; using fallback", error=str(exc)
        )
        return fallback

    logger.info(
        "Initialized feature-flagged natural language translator",
        translator=primary.__class__.__name__,
    )
    return CompositeTranslator(primary=primary, fallback=fallback)


def _build_prompt(*, question: str, limit: int, schema: str, examples: str) -> str:
    return (
        "You are a SQL query generator for a security database. "
        "Translate the user's natural language question into a SQL query.\n\n"
        f"{schema}\n\n"
        f"{examples}\n\n"
        f'User Question: "{question}"\n\n'
        "Instructions:\n"
        "1. Generate a valid PostgreSQL query\n"
        "2. Use appropriate tables from the schema above\n"
        f"3. Add LIMIT {limit} to the query\n"
        "4. Return ONLY the SQL query, no explanation or markdown\n"
        "5. Use proper WHERE clauses for filtering\n"
        "6. For JSON fields, use ::text or JSONB operators appropriately\n"
        "7. Use ORDER BY for better result ordering when relevant\n\n"
        "SQL Query:"
    )


def _finalize_query(query: str) -> str:
    normalized = query.strip()
    if not normalized.lower().endswith(";"):
        normalized = f"{normalized.rstrip(';')};"
    return normalized
