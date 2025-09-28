"""CEL rule engine implementation."""

import hashlib
from typing import Any, Dict, Optional, Union, List
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import logging

import celpy
from celpy import Environment, CELEvalError
from cachetools import TTLCache

from cerebro.core.config import settings
from .exceptions import CompilationError, EvaluationError

logger = logging.getLogger(__name__)


@dataclass
class EvaluationContext:
    """Context for rule evaluation."""
    resource: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    principal: Optional[Dict[str, Any]] = None
    iam_edge: Optional[Dict[str, Any]] = None
    org_config: Optional[Dict[str, Any]] = None
    user_config: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CEL evaluation."""
        return {
            k: v for k, v in self.__dict__.items() 
            if v is not None
        }


@dataclass
class RuleResult:
    """Result of rule evaluation."""
    rule_id: UUID
    matched: bool
    error: Optional[str] = None
    execution_time_ms: Optional[float] = None


class RuleEngine:
    """CEL-based rule engine with compilation caching."""
    
    def __init__(self):
        """Initialize the rule engine."""
        self._cache = TTLCache(
            maxsize=settings.cel_cache_size,
            ttl=3600  # 1 hour TTL
        )
        self._env = self._create_environment()
    
    def _create_environment(self) -> Environment:
        """Create CEL environment with variable declarations."""
        annotations = {
            'resource': celpy.celtypes.MapType,
            'config': celpy.celtypes.MapType,
            'principal': celpy.celtypes.MapType,
            'iam_edge': celpy.celtypes.MapType,
            'org_config': celpy.celtypes.MapType,
            'user_config': celpy.celtypes.MapType,
        }
        return Environment(annotations=annotations)
    
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
            raise CompilationError(f"Failed to compile expression: {e}")
    
    def evaluate_rule(
        self, 
        rule_id: UUID,
        expression: str, 
        context: EvaluationContext
    ) -> RuleResult:
        """Evaluate a CEL rule against the given context."""
        start_time = datetime.now()
        
        try:
            # Compile the expression
            compiled_ast = self.compile_rule(expression)
            
            # Prepare evaluation context
            eval_context = context.to_dict()
            
            # Evaluate the expression
            logger.debug(f"Evaluating rule {rule_id} with context keys: {list(eval_context.keys())}")
            result = compiled_ast(**eval_context)
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            logger.debug(f"Rule {rule_id} evaluation result: {result}")
            
            return RuleResult(
                rule_id=rule_id,
                matched=bool(result),
                execution_time_ms=execution_time
            )
            
        except CompilationError:
            # Re-raise compilation errors
            raise
        except CELEvalError as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"CEL evaluation error for rule {rule_id}: {e}")
            return RuleResult(
                rule_id=rule_id,
                matched=False,
                error=f"CEL evaluation error: {e}",
                execution_time_ms=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"Unexpected error evaluating rule {rule_id}: {e}")
            return RuleResult(
                rule_id=rule_id,
                matched=False,
                error=f"Evaluation error: {e}",
                execution_time_ms=execution_time
            )
    
    def evaluate_rules(
        self,
        rules: List[Dict[str, Any]],
        context: EvaluationContext
    ) -> List[RuleResult]:
        """Evaluate multiple rules against the given context."""
        results = []
        
        for rule in rules:
            try:
                result = self.evaluate_rule(
                    rule_id=rule["rule_id"],
                    expression=rule["expression"],
                    context=context
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to evaluate rule {rule['rule_id']}: {e}")
                results.append(RuleResult(
                    rule_id=rule["rule_id"],
                    matched=False,
                    error=str(e)
                ))
        
        return results
    
    def clear_cache(self) -> None:
        """Clear the compilation cache."""
        self._cache.clear()
        logger.info("Rule compilation cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
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
