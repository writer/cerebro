from __future__ import annotations

import asyncio

from cerebro.agents.models import AgentRuntimeEvent, AgentSession, AgentType


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_runtime_health_summary_endpoint(client, test_db, test_org, test_token):
    async def _seed_events():
        session = AgentSession(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="tester",
            context={},
        )
        test_db.add(session)
        await test_db.flush()

        events = [
            AgentRuntimeEvent(
                org_id=test_org.org_id,
                session_id=session.id,
                event_type="runtime_metadata",
                payload={
                    "runtime": "claude",
                    "usage": {"input_tokens": 10, "output_tokens": 20},
                },
            ),
            AgentRuntimeEvent(
                org_id=test_org.org_id,
                session_id=session.id,
                event_type="runtime_warning",
                payload={
                    "runtime": "claude",
                    "reason": "claude_cli_missing",
                },
            ),
            AgentRuntimeEvent(
                org_id=test_org.org_id,
                session_id=session.id,
                event_type="runtime_error",
                payload={
                    "runtime": "claude",
                    "reason": "exception",
                    "message": "boom",
                },
            ),
        ]

        test_db.add_all(events)
        await test_db.commit()

    _run_async(_seed_events())

    headers = {"Authorization": f"Bearer {test_token}"}
    response = client.get(
        "/api/v1/analytics/runtime-health",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    runtimes = payload.get("runtimes", [])
    assert runtimes, "Expected at least one runtime summary"

    claude_summary = next((item for item in runtimes if item["runtime"] == "claude"), None)
    assert claude_summary, payload

    events = claude_summary.get("events", {})
    assert events.get("runtime_metadata", {}).get("count") == 1
    assert events.get("runtime_warning", {}).get("count") == 1
    assert events.get("runtime_error", {}).get("count") == 1

    warnings = claude_summary.get("warnings", {})
    assert warnings.get("claude_cli_missing", {}).get("count") == 1

    metadata = claude_summary.get("latest_metadata")
    assert metadata is not None
    assert metadata["payload"]["runtime"] == "claude"
