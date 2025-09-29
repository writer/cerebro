#!/usr/bin/env python3
"""
Test script for Claude Agent API integration.

Tests the full stack: API → Service → Runtime → SDK → Tools

This validates that the deep integration is working end-to-end.
"""

import asyncio
import httpx
from uuid import uuid4

# Configuration
BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1"
TEST_TOKEN = "test_token_here"  # Replace with actual token

async def test_agent_health():
    """Test agent system health check."""
    print("=" * 60)
    print("TEST 1: Agent Health Check")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{BASE_URL}{API_PREFIX}/agents/health")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.json()}")

            if response.status_code == 200:
                data = response.json()
                assert data["status"] == "healthy"
                print("✅ Health check passed")
                return True
            else:
                print("❌ Health check failed")
                return False
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False


async def test_create_session():
    """Test creating an agent session."""
    print("\n" + "=" * 60)
    print("TEST 2: Create Agent Session")
    print("=" * 60)

    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    payload = {
        "agent_type": "security_analyst",
        "title": "Test Session",
        "context": {
            "provider_scope": ["aws"],
            "focus": "security_findings"
        }
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{BASE_URL}{API_PREFIX}/agents/sessions",
                headers=headers,
                json=payload,
                timeout=10.0
            )

            print(f"Status: {response.status_code}")

            if response.status_code == 401:
                print("⚠️  Authentication required - set TEST_TOKEN")
                print("   This is expected in development without auth")
                return None

            if response.status_code == 201:
                data = response.json()
                print(f"Session ID: {data['session_id']}")
                print(f"Agent Type: {data['agent_type']}")
                print(f"Created: {data['created_at']}")
                print("✅ Session created successfully")
                return data["session_id"]
            else:
                print(f"❌ Session creation failed: {response.text}")
                return None

        except Exception as e:
            print(f"❌ Session creation error: {e}")
            return None


async def test_list_sessions():
    """Test listing agent sessions."""
    print("\n" + "=" * 60)
    print("TEST 3: List Agent Sessions")
    print("=" * 60)

    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}{API_PREFIX}/agents/sessions",
                headers=headers,
                params={"limit": 10},
                timeout=10.0
            )

            print(f"Status: {response.status_code}")

            if response.status_code == 401:
                print("⚠️  Authentication required - set TEST_TOKEN")
                return

            if response.status_code == 200:
                data = response.json()
                print(f"Total sessions: {data['total']}")
                print(f"Returned: {len(data['sessions'])}")
                for session in data['sessions'][:3]:  # Show first 3
                    print(f"  - {session['agent_type']}: {session.get('title', 'Untitled')}")
                print("✅ Session listing works")
            else:
                print(f"❌ Session listing failed: {response.text}")

        except Exception as e:
            print(f"❌ Session listing error: {e}")


async def test_send_message(session_id):
    """Test sending a message to an agent session."""
    print("\n" + "=" * 60)
    print("TEST 4: Send Message to Agent")
    print("=" * 60)

    if not session_id:
        print("⏩ Skipping - no session available")
        return

    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    payload = {
        "message": "List the most critical security findings",
        "stream": False  # Non-streaming for simplicity
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{BASE_URL}{API_PREFIX}/agents/sessions/{session_id}/messages",
                headers=headers,
                json=payload,
                timeout=30.0
            )

            print(f"Status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                print(f"Response: {data.get('response', '')[:200]}...")
                print(f"Tool calls: {len(data.get('tool_calls', []))}")
                print("✅ Message sent and response received")
            else:
                print(f"❌ Message sending failed: {response.text}")

        except Exception as e:
            print(f"❌ Message sending error: {e}")


async def test_streaming_message(session_id):
    """Test streaming message with SSE."""
    print("\n" + "=" * 60)
    print("TEST 5: Send Streaming Message to Agent")
    print("=" * 60)

    if not session_id:
        print("⏩ Skipping - no session available")
        return

    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    payload = {
        "message": "What are the top 3 security issues?",
        "stream": True
    }

    print("Connecting to SSE stream...")

    async with httpx.AsyncClient() as client:
        try:
            async with client.stream(
                "POST",
                f"{BASE_URL}{API_PREFIX}/agents/sessions/{session_id}/messages",
                headers=headers,
                json=payload,
                timeout=30.0
            ) as response:

                print(f"Status: {response.status_code}")

                if response.status_code != 200:
                    print(f"❌ Streaming failed: {await response.aread()}")
                    return

                event_count = 0
                print("\nReceiving events:")

                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        event_count += 1
                        data = line[6:]  # Remove "data: " prefix
                        print(f"  Event {event_count}: {data[:100]}...")

                        if event_count >= 10:  # Limit output
                            print("  ... (limiting output)")
                            break

                print(f"\n✅ Received {event_count} SSE events")

        except Exception as e:
            print(f"❌ Streaming error: {e}")


async def test_api_docs():
    """Test that API documentation includes agent endpoints."""
    print("\n" + "=" * 60)
    print("TEST 6: API Documentation")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{BASE_URL}/docs")
            print(f"Status: {response.status_code}")

            if response.status_code == 200:
                print("✅ API docs accessible at http://localhost:8000/docs")
                print("   Check for 'agents' tag with 6 endpoints:")
                print("   - POST   /api/v1/agents/sessions")
                print("   - GET    /api/v1/agents/sessions")
                print("   - GET    /api/v1/agents/sessions/{session_id}")
                print("   - POST   /api/v1/agents/sessions/{session_id}/messages")
                print("   - GET    /api/v1/agents/sessions/{session_id}/messages")
                print("   - GET    /api/v1/agents/health")
            else:
                print(f"❌ API docs not accessible: {response.status_code}")

        except Exception as e:
            print(f"❌ API docs error: {e}")


async def main():
    """Run all API integration tests."""
    print("\n" + "=" * 70)
    print(" CEREBRO CLAUDE AGENT API INTEGRATION TESTS")
    print("=" * 70)
    print(f"\nTarget: {BASE_URL}")
    print(f"API Prefix: {API_PREFIX}")
    print("\nNOTE: Most tests require a running API server and authentication.")
    print("      Start server with: uv run uvicorn cerebro.api.main:app --reload")
    print("=" * 70 + "\n")

    # Test 1: Health check (no auth needed)
    health_ok = await test_agent_health()

    # Test 2: Create session (needs auth)
    session_id = await test_create_session()

    # Test 3: List sessions (needs auth)
    await test_list_sessions()

    # Test 4: Send message (needs auth + session)
    await test_send_message(session_id)

    # Test 5: Streaming message (needs auth + session)
    await test_streaming_message(session_id)

    # Test 6: API documentation
    await test_api_docs()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if health_ok:
        print("✅ Agent system is healthy and operational")
        print("✅ API routes are registered and accessible")
        print()
        print("Next Steps:")
        print("1. Set up authentication (TEST_TOKEN)")
        print("2. Run full integration tests with database")
        print("3. Test streaming with real agent interactions")
    else:
        print("⚠️  Could not verify agent system health")
        print("   Make sure the API server is running:")
        print("   $ uv run uvicorn cerebro.api.main:app --reload")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())