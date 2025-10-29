from datetime import datetime
from unittest.mock import MagicMock

import pytest

from cerebro_sdk.tasks import TaskManager, TaskSubmission, TaskStatus


class DummyAsyncResult:
    def __init__(self, task_id: str, status: str = "PENDING", result=None, failed=False):
        self.id = task_id
        self.status = status
        self.result = result
        self._failed = failed
        self.traceback = "trace" if failed else None
        self.date_done = datetime.utcnow()

    def successful(self) -> bool:
        return not self._failed and self.status == "SUCCESS"

    def failed(self) -> bool:
        return self._failed


def build_task(name: str, result: DummyAsyncResult):
    task = MagicMock()
    task.apply_async.return_value = result
    return name, task


@pytest.fixture
def mock_celery():
    app = MagicMock()
    result = DummyAsyncResult("task-1", status="SUCCESS")
    task_name, task = build_task("cerebro.tasks.integration.sync_kandji", result)
    app.tasks = {task_name: task}
    app.send_task.return_value = DummyAsyncResult("task-2")
    app.AsyncResult.side_effect = lambda task_id: DummyAsyncResult(task_id, status="SUCCESS", result="ok")
    return app


def test_task_manager_enqueue(mock_celery):
    manager = TaskManager(app=mock_celery)

    submission = manager.enqueue("cerebro.tasks.integration.sync_kandji")

    assert isinstance(submission, TaskSubmission)
    mock_celery.tasks["cerebro.tasks.integration.sync_kandji"].apply_async.assert_called_once()


def test_task_manager_send_task(mock_celery):
    manager = TaskManager(app=mock_celery)
    submission = manager.send_task("cerebro.tasks.integration.sync_kandji", countdown=10)
    assert submission.task_id == "task-2"
    mock_celery.send_task.assert_called_once_with(
        "cerebro.tasks.integration.sync_kandji", args=(), kwargs={}, countdown=10
    )


def test_task_manager_status(mock_celery):
    manager = TaskManager(app=mock_celery)
    status = manager.get_status("task-123")
    assert isinstance(status, TaskStatus)
    assert status.result == "ok"


def test_task_manager_revoke(mock_celery):
    manager = TaskManager(app=mock_celery)
    manager.revoke("task-9", terminate=True)
    mock_celery.control.revoke.assert_called_once_with("task-9", terminate=True, signal=None)
