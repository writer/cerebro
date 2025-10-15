"""Telemetry helpers for Cerebro agent runtimes."""

from __future__ import annotations

import time
from typing import Dict, Optional

import structlog

from cerebro.core.config import settings

try:  # pragma: no cover - optional dependency
    from opentelemetry import trace
except ImportError:  # pragma: no cover
    trace = None  # type: ignore


logger = structlog.get_logger("cerebro.agent")


class RuntimeSpan:
    """Span helper encapsulating telemetry for runtime operations."""

    def __init__(
        self,
        *,
        backend: str,
        agent_type: str,
        operation: str,
        session_id: Optional[str] = None,
    ) -> None:
        self.backend = backend
        self.agent_type = agent_type
        self.operation = operation
        self.session_id = session_id
        self.start_time = time.perf_counter()
        self._span_cm = None
        self._span = None
        self._closed = False

        if settings.enable_agent_telemetry and trace is not None:  # pragma: no branch
            tracer = trace.get_tracer("cerebro.agent")
            self._span_cm = tracer.start_as_current_span(f"agent.{operation}")
            self._span = self._span_cm.__enter__()
            if self._span is not None:
                self._span.set_attribute("cerebro.agent.backend", backend)
                self._span.set_attribute("cerebro.agent.type", agent_type)
                if session_id:
                    self._span.set_attribute("cerebro.session.id", session_id)

    def finish(
        self,
        *,
        success: bool,
        input_tokens: int,
        output_tokens: int,
        tool_calls: int,
        error: Optional[BaseException] = None,
        extra: Optional[Dict[str, object]] = None,
    ) -> None:
        if self._closed:
            return

        duration = time.perf_counter() - self.start_time
        payload: Dict[str, object] = {
            "backend": self.backend,
            "agent_type": self.agent_type,
            "duration": duration,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "tool_calls": tool_calls,
        }
        if self.session_id:
            payload["session_id"] = self.session_id
        if extra:
            payload.update(extra)

        if success:
            logger.info("agent.runtime.success", **payload)
        else:
            payload["error"] = str(error) if error else "unknown"
            logger.error("agent.runtime.error", **payload)

        if self._span is not None:
            span = self._span
            span.set_attribute("cerebro.agent.duration", duration)
            span.set_attribute("cerebro.agent.input_tokens", input_tokens)
            span.set_attribute("cerebro.agent.output_tokens", output_tokens)
            span.set_attribute("cerebro.agent.tool_calls", tool_calls)
            span.set_attribute("cerebro.agent.success", success)
            if not success and error is not None:
                span.record_exception(error)

        if self._span_cm is not None:
            if success or error is None:
                self._span_cm.__exit__(None, None, None)
            else:
                self._span_cm.__exit__(type(error), error, error.__traceback__)

        self._closed = True


def start_runtime_span(
    *,
    backend: str,
    agent_type: str,
    operation: str,
    session_id: Optional[str] = None,
) -> RuntimeSpan:
    """Create a runtime telemetry span."""

    return RuntimeSpan(
        backend=backend,
        agent_type=agent_type,
        operation=operation,
        session_id=session_id,
    )
