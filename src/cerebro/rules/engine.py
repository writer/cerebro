"""CEL rule engine implementation."""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import celpy
from cachetools import TTLCache
from celpy import CELEvalError, Environment

from cerebro.core.config import settings

from .exceptions import CompilationError

logger = logging.getLogger(__name__)


@dataclass
class EvaluationContext:
    """Context for rule evaluation."""

    resource: dict[str, Any] | None = None
    config: dict[str, Any] | None = None
    principal: dict[str, Any] | None = None
    iam_edge: dict[str, Any] | None = None
    org_config: dict[str, Any] | None = None
    user_config: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for CEL evaluation."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class RuleResult:
    """Result of rule evaluation."""

    rule_id: UUID
    matched: bool
    error: str | None = None
    execution_time_ms: float | None = None


class RuleEngine:
    """CEL-based rule engine with compilation caching."""

    def __init__(self):
        """Initialize the rule engine."""
        self._cache = TTLCache(maxsize=settings.cel_cache_size, ttl=3600)  # 1 hour TTL
        self._env = self._create_environment()

    def _create_environment(self) -> Environment:
        """Create CEL environment with variable declarations."""
        annotations = {
            "resource": celpy.celtypes.MapType,
            "config": celpy.celtypes.MapType,
            "principal": celpy.celtypes.MapType,
            "iam_edge": celpy.celtypes.MapType,
            "org_config": celpy.celtypes.MapType,
            "user_config": celpy.celtypes.MapType,
        }
        return Environment(annotations=annotations)  # type: ignore[arg-type]

    def _get_cache_key(self, expression: str) -> str:
        """Generate cache key for expression."""
        return hashlib.sha256(expression.encode()).hexdigest()

    def compile_rule(self, expression: str) -> Any:
        """Compile a CEL expression with caching."""
        cache_key = self._get_cache_key(expression)

        if cache_key in self._cache:
            logger.debug(f"Cache hit for expression: {expression[:50]}...")
            return self._cache[cache_key]

        try:
            logger.debug(f"Compiling CEL expression: {expression[:50]}...")
            compiled_ast = self._env.compile(expression)
            self._cache[cache_key] = compiled_ast
            logger.debug("Compilation successful")
            return compiled_ast
        except Exception as e:
            logger.error(f"Failed to compile CEL expression: {e}")
            raise CompilationError(f"Failed to compile expression: {e}") from e


    def _convert_to_cel_types(self, obj: Any) -> Any:
        """Convert Python objects to CEL types."""
        if isinstance(obj, dict):
            cel_dict = {}
            for k, v in obj.items():
                cel_dict[k] = self._convert_to_cel_types(v)
            return celpy.celtypes.MapType(cel_dict)
        elif isinstance(obj, list):
            return [self._convert_to_cel_types(item) for item in obj]
        else:
            return obj

    def evaluate_rule(
        self, rule_id: UUID, expression: str, context: EvaluationContext
    ) -> RuleResult:
        """Evaluate a CEL rule against the given context."""
        start_time = datetime.now()

        try:
            # Compile the expression
            compiled_ast = self.compile_rule(expression)

            # Create a program from the compiled AST
            program = self._env.program(compiled_ast)

            # Prepare evaluation context (activation) - convert to CEL types
            eval_context = context.to_dict()
            cel_context = {}
            for k, v in eval_context.items():
                cel_context[k] = self._convert_to_cel_types(v)

            # Evaluate the expression
            logger.debug(
                f"Evaluating rule {rule_id} with context keys: {list(cel_context.keys())}"
            )
            result = program.evaluate(cel_context)

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            logger.debug(f"Rule {rule_id} evaluation result: {result}")  # type: ignore[str-bytes-safe]

            return RuleResult(
                rule_id=rule_id, matched=bool(result), execution_time_ms=execution_time
            )

        except CompilationError:
            # Re-raise compilation errors from None

            raise
        except CELEvalError as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"CEL evaluation error for rule {rule_id}: {e}")
            return RuleResult(
                rule_id=rule_id,
                matched=False,
                error=f"CEL evaluation error: {e}",
                execution_time_ms=execution_time,
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"Unexpected error evaluating rule {rule_id}: {e}")
            return RuleResult(
                rule_id=rule_id,
                matched=False,
                error=f"Evaluation error: {e}",
                execution_time_ms=execution_time,
            )

    def evaluate_rules(
        self, rules: list[dict[str, Any]], context: EvaluationContext
    ) -> list[RuleResult]:
        """Evaluate multiple rules against the given context."""
        results = []

        for rule in rules:
            try:
                result = self.evaluate_rule(
                    rule_id=rule["rule_id"],
                    expression=rule["expression"],
                    context=context,
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to evaluate rule {rule['rule_id']}: {e}")
                results.append(
                    RuleResult(rule_id=rule["rule_id"], matched=False, error=str(e))
                )

        return results

    def clear_cache(self) -> None:
        """Clear the compilation cache."""
        self._cache.clear()
        logger.info("Rule compilation cache cleared")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "maxsize": self._cache.maxsize,
            "ttl": getattr(self._cache, "ttl", None),
            "hits": getattr(self._cache, "hits", 0),
            "misses": getattr(self._cache, "misses", 0),
        }


# Global rule engine instance
rule_engine = RuleEngine()
