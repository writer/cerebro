"""Tests for SLA service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from cerebro.agents.sla_service import SLAConfig, SLAService, SLAStatus


class TestSLAConfig:
    """Test SLA configuration defaults."""

    def test_default_slas(self):
        """Test default SLA hours by priority."""
        assert SLAConfig.DEFAULT_SLAS["critical"] == 2
        assert SLAConfig.DEFAULT_SLAS["high"] == 8
        assert SLAConfig.DEFAULT_SLAS["medium"] == 24
        assert SLAConfig.DEFAULT_SLAS["low"] == 72

    def test_thresholds(self):
        """Test SLA threshold constants."""
        assert SLAConfig.WARNING_THRESHOLD == 0.75
        assert SLAConfig.CRITICAL_THRESHOLD == 1.0


class TestSLAStatus:
    """Test SLA status model."""

    def test_to_dict(self):
        """Test SLA status serialization."""
        mock_task = MagicMock()
        mock_task.id = uuid4()
        mock_task.created_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        mock_task.due_at = datetime(2024, 1, 1, 20, 0, 0, tzinfo=UTC)

        status = SLAStatus(
            task=mock_task,
            sla_hours=8,
            elapsed_hours=4.0,
            remaining_hours=4.0,
            percentage_elapsed=0.5,
            is_breached=False,
            is_at_risk=False,
        )

        result = status.to_dict()

        assert result["task_id"] == str(mock_task.id)
        assert result["sla_hours"] == 8
        assert result["elapsed_hours"] == 4.0
        assert result["remaining_hours"] == 4.0
        assert result["percentage_elapsed"] == 50.0
        assert result["is_breached"] is False
        assert result["is_at_risk"] is False
        assert result["created_at"] == "2024-01-01T12:00:00+00:00"
        assert result["due_at"] == "2024-01-01T20:00:00+00:00"

    def test_to_dict_no_due_date(self):
        """Test serialization when due_at is None."""
        mock_task = MagicMock()
        mock_task.id = uuid4()
        mock_task.created_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        mock_task.due_at = None

        status = SLAStatus(
            task=mock_task,
            sla_hours=8,
            elapsed_hours=4.0,
            remaining_hours=4.0,
            percentage_elapsed=0.5,
            is_breached=False,
            is_at_risk=False,
        )

        result = status.to_dict()
        assert result["due_at"] is None


class TestSLAService:
    """Test SLA service methods."""

    def test_calculate_sla_status_on_track(self):
        """Test SLA calculation for task on track."""
        mock_task = MagicMock()
        mock_task.priority = "high"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=2)

        status = SLAService.calculate_sla_status(mock_task)

        assert status.sla_hours == 8
        assert 1.9 <= status.elapsed_hours <= 2.1
        assert status.remaining_hours > 5.5
        assert status.percentage_elapsed < 0.75
        assert status.is_breached is False
        assert status.is_at_risk is False

    def test_calculate_sla_status_at_risk(self):
        """Test SLA calculation for task at risk (75-100% elapsed)."""
        mock_task = MagicMock()
        mock_task.priority = "high"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=7)

        status = SLAService.calculate_sla_status(mock_task)

        assert status.sla_hours == 8
        assert 6.9 <= status.elapsed_hours <= 7.1
        assert status.percentage_elapsed >= 0.75
        assert status.percentage_elapsed < 1.0
        assert status.is_breached is False
        assert status.is_at_risk is True

    def test_calculate_sla_status_breached(self):
        """Test SLA calculation for breached task."""
        mock_task = MagicMock()
        mock_task.priority = "critical"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=3)

        status = SLAService.calculate_sla_status(mock_task)

        assert status.sla_hours == 2
        assert status.elapsed_hours >= 2.9
        assert status.percentage_elapsed >= 1.0
        assert status.is_breached is True
        assert status.is_at_risk is False

    def test_calculate_sla_status_custom_slas(self):
        """Test SLA calculation with custom SLA config."""
        mock_task = MagicMock()
        mock_task.priority = "high"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=2)

        custom_slas = {"high": 4, "medium": 12}
        status = SLAService.calculate_sla_status(mock_task, custom_slas)

        assert status.sla_hours == 4
        assert 1.9 <= status.elapsed_hours <= 2.1
        assert status.percentage_elapsed >= 0.45

    def test_calculate_sla_status_default_priority(self):
        """Test SLA calculation with None priority defaults to medium."""
        mock_task = MagicMock()
        mock_task.priority = None
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=1)

        status = SLAService.calculate_sla_status(mock_task)

        assert status.sla_hours == 24  # medium default

    def test_calculate_sla_status_naive_datetime(self):
        """Test SLA calculation handles naive datetime."""
        mock_task = MagicMock()
        mock_task.priority = "low"
        mock_task.created_at = datetime(2024, 1, 1, 12, 0, 0)  # naive datetime

        with patch("cerebro.agents.sla_service.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC)
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
            status = SLAService.calculate_sla_status(mock_task)

        assert status.sla_hours == 72

    @pytest.mark.asyncio
    async def test_get_breached_tasks(self):
        """Test getting breached tasks."""
        org_id = uuid4()
        mock_task = MagicMock()
        mock_task.priority = "critical"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=5)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value = [mock_task]
        mock_session.execute.return_value = mock_result

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            breached = await SLAService.get_breached_tasks(org_id=org_id)

        assert len(breached) == 1
        assert breached[0].is_breached is True

    @pytest.mark.asyncio
    async def test_get_at_risk_tasks(self):
        """Test getting at-risk tasks."""
        org_id = uuid4()
        mock_task = MagicMock()
        mock_task.priority = "high"
        mock_task.created_at = datetime.now(UTC) - timedelta(hours=7)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value = [mock_task]
        mock_session.execute.return_value = mock_result

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            at_risk = await SLAService.get_at_risk_tasks(org_id=org_id)

        assert len(at_risk) == 1
        assert at_risk[0].is_at_risk is True

    @pytest.mark.asyncio
    async def test_set_due_date_with_datetime(self):
        """Test setting due date with explicit datetime."""
        task_id = uuid4()
        due_at = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        mock_task = MagicMock()
        mock_session = AsyncMock()
        mock_session.get.return_value = mock_task

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            result = await SLAService.set_due_date(task_id=task_id, due_at=due_at)

        assert result is mock_task
        assert mock_task.due_at == due_at
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_due_date_with_sla_hours(self):
        """Test setting due date based on SLA hours."""
        task_id = uuid4()
        mock_task = MagicMock()
        mock_task.created_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        mock_session = AsyncMock()
        mock_session.get.return_value = mock_task

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            await SLAService.set_due_date(task_id=task_id, sla_hours=8)

        expected_due = datetime(2024, 1, 1, 20, 0, 0, tzinfo=UTC)
        assert mock_task.due_at == expected_due

    @pytest.mark.asyncio
    async def test_set_due_date_task_not_found(self):
        """Test setting due date for non-existent task."""
        task_id = uuid4()
        mock_session = AsyncMock()
        mock_session.get.return_value = None

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            result = await SLAService.set_due_date(
                task_id=task_id, due_at=datetime.now(UTC)
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_get_sla_summary(self):
        """Test SLA summary statistics."""
        org_id = uuid4()
        now = datetime.now(UTC)

        # Create tasks in different states
        on_track_task = MagicMock()
        on_track_task.priority = "low"
        on_track_task.created_at = now - timedelta(hours=1)

        at_risk_task = MagicMock()
        at_risk_task.priority = "high"
        at_risk_task.created_at = now - timedelta(hours=7)

        breached_task = MagicMock()
        breached_task.priority = "critical"
        breached_task.created_at = now - timedelta(hours=5)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value = [on_track_task, at_risk_task, breached_task]
        mock_session.execute.return_value = mock_result

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            summary = await SLAService.get_sla_summary(org_id=org_id)

        assert summary["total_pending"] == 3
        assert summary["breached"] == 1
        assert summary["at_risk"] == 1
        assert summary["on_track"] == 1
        assert summary["compliance_rate"] == pytest.approx(33.3, rel=0.1)

    @pytest.mark.asyncio
    async def test_get_sla_summary_empty(self):
        """Test SLA summary with no tasks."""
        org_id = uuid4()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value = []
        mock_session.execute.return_value = mock_result

        with patch(
            "cerebro.agents.sla_service.async_session_factory"
        ) as mock_factory:
            mock_factory.return_value.__aenter__.return_value = mock_session

            summary = await SLAService.get_sla_summary(org_id=org_id)

        assert summary["total_pending"] == 0
        assert summary["compliance_rate"] == 100
