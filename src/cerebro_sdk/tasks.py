"""Celery task orchestration helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from celery import Celery

from cerebro.tasks import celery_app


@dataclass
class TaskSubmission:
    """Response when a task is enqueued."""

    task_id: str
    status: str


@dataclass
class TaskStatus:
    """Snapshot of task execution state."""

    task_id: str
    status: str
    successful: bool
    failed: bool
    result: Any
    traceback: str | None
    date_done: datetime | None


class TaskManager:
    """Facade for interacting with Celery tasks."""

    def __init__(self, app: Celery | None = None) -> None:
        self._app = app or celery_app

    def enqueue(
        self,
        task_name: str,
        *args: Any,
        queue: str | None = None,
        kwargs: dict[str, Any] | None = None,
        countdown: int | None = None,
        eta: datetime | None = None,
        priority: int | None = None,
    ) -> TaskSubmission:
        task = self._app.tasks.get(task_name)
        if task is None:
            raise ValueError(f"Unknown task '{task_name}'")

        async_result = task.apply_async(  # type: ignore[attr-defined]
            args=args,
            kwargs=kwargs or {},
            queue=queue,
            countdown=countdown,
            eta=eta,
            priority=priority,
        )
        return TaskSubmission(
            task_id=async_result.id, status=getattr(async_result, "status", "PENDING")
        )

    def send_task(
        self,
        task_name: str,
        *args: Any,
        kwargs: dict[str, Any] | None = None,
        **options: Any,
    ) -> TaskSubmission:
        async_result = self._app.send_task(
            task_name, args=args, kwargs=kwargs or {}, **options
        )
        return TaskSubmission(
            task_id=async_result.id, status=getattr(async_result, "status", "PENDING")
        )

    def get_status(self, task_id: str) -> TaskStatus:
        result = self._app.AsyncResult(task_id)
        date_done = getattr(result, "date_done", None)
        if isinstance(date_done, datetime) and date_done.tzinfo is None:
            date_done = date_done.replace(tzinfo=UTC)

        return TaskStatus(
            task_id=task_id,
            status=result.status,
            successful=result.successful(),
            failed=result.failed(),
            result=getattr(result, "result", None),
            traceback=getattr(result, "traceback", None),
            date_done=date_done,
        )

    def revoke(
        self, task_id: str, *, terminate: bool = False, signal: str | None = None
    ) -> None:
        self._app.control.revoke(task_id, terminate=terminate, signal=signal)
