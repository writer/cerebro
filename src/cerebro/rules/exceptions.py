"""Rule engine exceptions."""


class RuleError(Exception):
    """Base exception for rule engine errors."""

    pass


class CompilationError(RuleError):
    """Raised when rule compilation fails."""

    pass


class EvaluationError(RuleError):
    """Raised when rule evaluation fails."""

    pass
