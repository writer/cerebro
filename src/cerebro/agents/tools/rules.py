"""
CEL Rules management tools for Cerebro agents.

These tools provide secure access to rule management functionality, allowing agents
to test rules, create rule templates, and analyze policy effectiveness.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from cerebro.core.database import get_db
from cerebro.rules.engine import RuleEngine, EvaluationContext
from cerebro.rules.exceptions import CompilationError, EvaluationError

from .base import Tool, ToolResult, AgentContext, ToolPermissionLevel

logger = structlog.get_logger(__name__)


# Input/Output Schemas

class CompileRuleInput(BaseModel):
    """Input for compiling a CEL rule."""
    expression: str = Field(description="CEL expression to compile")
    validate_only: bool = Field(default=True, description="Only validate compilation, don't store")


class CompileRuleOutput(BaseModel):
    """Output for rule compilation."""
    expression: str
    compiled_successfully: bool
    compilation_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    suggested_fixes: List[str] = Field(default_factory=list)


class TestRuleInput(BaseModel):
    """Input for testing a rule against sample data."""
    expression: str = Field(description="CEL expression to test")
    test_contexts: List[Dict[str, Any]] = Field(description="Sample contexts to test against")
    expected_results: Optional[List[bool]] = Field(None, description="Expected results for validation")


class TestRuleOutput(BaseModel):
    """Output for rule testing."""
    expression: str
    test_results: List[Dict[str, Any]]
    success_rate: float
    total_tests: int
    passed_tests: int
    failed_tests: int
    execution_time_ms: float


class RulesTool(Tool):
    """Tool for CEL rule management and testing."""
    
    def __init__(self):
        self.rule_engine = RuleEngine()
    
    @property
    def name(self) -> str:
        return "rules"
    
    @property
    def description(self) -> str:
        return "Compile, test, and validate CEL security rules with sample data"
    
    @property
    def input_schema(self) -> type:
        return BaseModel  # Will route based on operation
    
    @property
    def output_schema(self) -> type:
        return BaseModel
    
    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY  # Rule testing is read-only
    
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Execute rule operations based on input type."""
        
        raw_data = inputs.model_dump() if hasattr(inputs, 'model_dump') else inputs
        operation = raw_data.get('operation', 'compile')
        
        try:
            if operation == 'compile':
                return await self._compile_rule(raw_data, context)
            elif operation == 'test':
                return await self._test_rule(raw_data, context)
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            logger.exception("Rules tool execution failed", operation=operation, error=str(e))
            return ToolResult(
                success=False,
                error=f"Rules operation failed: {str(e)}",
            )
    
    async def _compile_rule(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Compile and validate a CEL rule."""
        inputs = CompileRuleInput(**raw_data)
        
        try:
            import time
            start_time = time.time()
            
            # Attempt to compile the rule
            compiled_ast = self.rule_engine.compile_rule(inputs.expression)
            
            compilation_time = (time.time() - start_time) * 1000
            
            output = CompileRuleOutput(
                expression=inputs.expression,
                compiled_successfully=True,
                compilation_time_ms=compilation_time,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "expression_length": len(inputs.expression),
                    "compilation_time_ms": compilation_time,
                },
            )
            
        except CompilationError as e:
            # Provide helpful suggestions for common compilation errors
            error_msg = str(e)
            suggestions = []
            
            if "undefined identifier" in error_msg.lower():
                suggestions.append("Check variable names in evaluation context")
                suggestions.append("Available context: resource, config, principal, org_config")
            elif "syntax error" in error_msg.lower():
                suggestions.append("Verify CEL syntax - use '&&' not 'and', '||' not 'or'")
                suggestions.append("String literals require double quotes")
            elif "type error" in error_msg.lower():
                suggestions.append("Check data types - use string(), int(), float() for conversions")
            
            output = CompileRuleOutput(
                expression=inputs.expression,
                compiled_successfully=False,
                error_message=error_msg,
                suggested_fixes=suggestions,
            )
            
            return ToolResult(
                success=True,  # Not a system error, just compilation failure
                data=output.model_dump(),
                metadata={
                    "compilation_failed": True,
                    "error_type": "compilation_error",
                },
            )
            
        except Exception as e:
            logger.exception("Unexpected error during rule compilation", error=str(e))
            return ToolResult(
                success=False,
                error=f"Unexpected compilation error: {str(e)}",
            )
    
    async def _test_rule(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Test a rule against sample contexts."""
        inputs = TestRuleInput(**raw_data)
        
        try:
            import time
            from uuid import uuid4
            
            start_time = time.time()
            test_results = []
            passed_tests = 0
            failed_tests = 0
            
            # Test rule against each context
            for i, test_context in enumerate(inputs.test_contexts):
                test_start = time.time()
                
                try:
                    # Create evaluation context
                    eval_context = EvaluationContext(
                        resource=test_context.get('resource'),
                        config=test_context.get('config'),
                        principal=test_context.get('principal'),
                        org_config=test_context.get('org_config'),
                    )
                    
                    # Evaluate rule
                    rule_result = self.rule_engine.evaluate_rule(
                        rule_id=uuid4(),
                        expression=inputs.expression,
                        context=eval_context
                    )
                    
                    test_time = (time.time() - test_start) * 1000
                    
                    # Check against expected result if provided
                    expected = None
                    matches_expected = None
                    if inputs.expected_results and i < len(inputs.expected_results):
                        expected = inputs.expected_results[i]
                        matches_expected = rule_result.matched == expected
                    
                    test_result = {
                        "test_index": i,
                        "result": rule_result.matched,
                        "expected": expected,
                        "matches_expected": matches_expected,
                        "execution_time_ms": test_time,
                        "error": None,
                        "context_summary": {
                            "has_resource": test_context.get('resource') is not None,
                            "has_config": test_context.get('config') is not None,
                            "has_principal": test_context.get('principal') is not None,
                        }
                    }
                    
                    test_results.append(test_result)
                    
                    if matches_expected is None or matches_expected:
                        passed_tests += 1
                    else:
                        failed_tests += 1
                        
                except Exception as eval_error:
                    test_time = (time.time() - test_start) * 1000
                    
                    test_result = {
                        "test_index": i,
                        "result": None,
                        "expected": inputs.expected_results[i] if inputs.expected_results and i < len(inputs.expected_results) else None,
                        "matches_expected": False,
                        "execution_time_ms": test_time,
                        "error": str(eval_error),
                        "context_summary": {
                            "has_resource": test_context.get('resource') is not None,
                            "has_config": test_context.get('config') is not None,
                            "has_principal": test_context.get('principal') is not None,
                        }
                    }
                    
                    test_results.append(test_result)
                    failed_tests += 1
            
            total_time = (time.time() - start_time) * 1000
            total_tests = len(inputs.test_contexts)
            success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
            
            output = TestRuleOutput(
                expression=inputs.expression,
                test_results=test_results,
                success_rate=success_rate,
                total_tests=total_tests,
                passed_tests=passed_tests,
                failed_tests=failed_tests,
                execution_time_ms=total_time,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "rule_performance": {
                        "avg_execution_time_ms": total_time / total_tests if total_tests > 0 else 0,
                        "success_rate_percent": success_rate,
                        "fastest_test_ms": min([r.get("execution_time_ms", 0) for r in test_results]) if test_results else 0,
                        "slowest_test_ms": max([r.get("execution_time_ms", 0) for r in test_results]) if test_results else 0,
                    }
                },
            )
            
        except Exception as e:
            logger.exception("Rule testing failed", error=str(e))
            return ToolResult(
                success=False,
                error=f"Rule testing error: {str(e)}",
            )
