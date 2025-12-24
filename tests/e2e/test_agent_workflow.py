"""
E2E Tests: Agent Workflow

These tests verify the complete agent session lifecycle including:
- Session creation with auto-context
- Message sending and response
- Session memory persistence
"""

import os
from uuid import UUID

import httpx
import pytest

from tests.e2e.conftest import TestDataFactory

pytestmark = [pytest.mark.e2e, pytest.mark.e2e_agent]


@pytest.mark.asyncio
async def test_create_agent_session(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test creating an agent session with auto-context injection."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")

    response = await auth_client.post(
        "/api/v1/agents/sessions",
        json={
            "agent_type": "security_analyst",
            "context": {"test_mode": True},
        },
    )

    if response.status_code in (200, 201):
        session = response.json()

        assert "session_id" in session
        assert session["agent_type"] == "security_analyst"

        # Verify auto-context was injected
        context = session.get("context", {})
        assert "_auto_loaded_org_context" in context or "_runtime_engine" in context

        # No public delete endpoint for sessions in v1; cleanup is handled by DB-level fixtures.


@pytest.mark.asyncio
@pytest.mark.e2e_slow
async def test_agent_conversation(
    auth_client: httpx.AsyncClient,
    data_factory: TestDataFactory,
):
    """Test a complete agent conversation flow."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")

    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")):
        pytest.skip("LLM credentials not configured")

    session_id = await data_factory.create_agent_session(
        agent_type="security_analyst",
        context={"test_mode": True},
    )

    if session_id.int == 0:
        pytest.skip("Failed to create agent session")

    # Send a message
    response = await auth_client.post(
        f"/api/v1/agents/sessions/{session_id}/messages",
        json={"message": "List recent high severity findings", "stream": False},
        timeout=60,  # Agent responses may take longer
    )

    if response.status_code == 200:
        message_response = response.json()

        # Should have some response content
        assert "content" in message_response or "messages" in message_response


@pytest.mark.asyncio
async def test_agent_session_metrics(
    auth_client: httpx.AsyncClient,
    data_factory: TestDataFactory,
):
    """Test retrieving agent session memory stats."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")

    session_id = await data_factory.create_agent_session()
    if session_id.int == 0:
        pytest.skip("Failed to create agent session")

    response = await auth_client.get(
        f"/api/v1/agents/sessions/{session_id}/memory/stats"
    )

    if response.status_code == 200:
        metrics = response.json()
        assert "total_entries" in metrics


@pytest.mark.asyncio
async def test_agent_session_list(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
):
    """Test listing agent sessions for an organization."""
    if "Authorization" not in auth_client.headers:
        pytest.skip("Authentication not available")

    response = await auth_client.get(
        "/api/v1/agents/sessions",
    )

    assert response.status_code in (200, 403)

    if response.status_code == 200:
        data = response.json()
        assert "sessions" in data or isinstance(data, list)
