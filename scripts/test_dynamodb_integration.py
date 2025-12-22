#!/usr/bin/env python3
"""Integration test script for DynamoDB implementation.

Tests the full stack: DynamoDB client -> repositories -> API endpoints.
Requires DynamoDB Local running at http://localhost:8000.

Usage:
    # Start DynamoDB Local
    docker run -p 8000:8000 amazon/dynamodb-local

    # Create tables
    python scripts/dynamodb_local_setup.py

    # Run tests
    python scripts/test_dynamodb_integration.py

    # Or with docker-compose
    docker-compose up dynamodb-local dynamodb-setup
    python scripts/test_dynamodb_integration.py
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set environment for local DynamoDB
os.environ.setdefault("DYNAMODB_ENDPOINT_URL", "http://localhost:8000")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "local")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "local")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")


def print_result(test_name: str, passed: bool, error: str = None):
    """Print test result."""
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {test_name}")
    if error:
        print(f"         Error: {error}")


async def test_organization_repository():
    """Test Organization repository CRUD operations."""
    from cerebro.core.repositories.organization import (
        Organization,
        OrganizationRepository,
    )

    repo = OrganizationRepository()
    results = []

    # Test create
    try:
        org = Organization(name=f"Test Org {uuid4().hex[:8]}")
        created = await repo.create(org)
        results.append(
            (
                "Create organization",
                created is not None and created.name == org.name,
                None,
            )
        )
        org_id = created.org_id
    except Exception as e:
        results.append(("Create organization", False, str(e)))
        return results

    # Test get
    try:
        retrieved = await repo.get(org_id)
        results.append(
            (
                "Get organization",
                retrieved is not None and retrieved.org_id == org_id,
                None,
            )
        )
    except Exception as e:
        results.append(("Get organization", False, str(e)))

    # Test update
    try:
        updated = await repo.update(org_id, name="Updated Name")
        results.append(
            (
                "Update organization",
                updated is not None and updated.name == "Updated Name",
                None,
            )
        )
    except Exception as e:
        results.append(("Update organization", False, str(e)))

    # Test list
    try:
        orgs = await repo.list_all()
        results.append(("List organizations", len(orgs) > 0, None))
    except Exception as e:
        results.append(("List organizations", False, str(e)))

    # Test delete
    try:
        deleted = await repo.delete(org_id)
        results.append(("Delete organization", deleted is True, None))

        # Verify deleted
        retrieved = await repo.get(org_id)
        results.append(("Verify deletion", retrieved is None, None))
    except Exception as e:
        results.append(("Delete organization", False, str(e)))

    return results


async def test_finding_repository():
    """Test Finding repository operations."""
    from cerebro.core.repositories.finding import (
        Finding,
        FindingRepository,
        FindingStatus,
        Severity,
    )
    from cerebro.core.repositories.organization import (
        Organization,
        OrganizationRepository,
    )

    org_repo = OrganizationRepository()
    finding_repo = FindingRepository()
    results = []

    # Create test org
    try:
        org = Organization(name=f"Finding Test Org {uuid4().hex[:8]}")
        org = await org_repo.create(org)
        org_id = org.org_id
    except Exception as e:
        results.append(("Setup test org", False, str(e)))
        return results

    # Test create finding
    try:
        finding = Finding(
            org_id=org_id,
            account_id=uuid4(),
            provider="aws",
            rule_id=uuid4(),
            severity=Severity.HIGH,
            fingerprint=f"fp-{uuid4().hex[:8]}",
            title="Test Finding",
            summary="This is a test finding",
        )
        created = await finding_repo.create(finding)
        results.append(("Create finding", created is not None, None))
        finding_id = created.finding_id
    except Exception as e:
        results.append(("Create finding", False, str(e)))
        return results

    # Test get finding
    try:
        retrieved = await finding_repo.get(finding_id, org_id)
        results.append(
            (
                "Get finding",
                retrieved is not None and retrieved.title == "Test Finding",
                None,
            )
        )
    except Exception as e:
        results.append(("Get finding", False, str(e)))

    # Test list by org
    try:
        findings = await finding_repo.list_by_org(org_id)
        results.append(("List findings by org", len(findings) > 0, None))
    except Exception as e:
        results.append(("List findings by org", False, str(e)))

    # Test update status
    try:
        updated = await finding_repo.update(
            finding_id, org_id, status=FindingStatus.SUPPRESSED
        )
        results.append(
            (
                "Update finding status",
                updated is not None and updated.status == FindingStatus.SUPPRESSED,
                None,
            )
        )
    except Exception as e:
        results.append(("Update finding status", False, str(e)))

    # Test count by status
    try:
        counts = await finding_repo.count_by_status(org_id)
        results.append(("Count by status", "suppressed" in counts, None))
    except Exception as e:
        results.append(("Count by status", False, str(e)))

    # Cleanup
    try:
        await finding_repo.delete(finding_id, org_id)
        await org_repo.delete(org_id)
    except Exception:
        pass

    return results


async def test_agent_session_repository():
    """Test AgentSession repository operations."""
    from cerebro.core.repositories.agents import (
        AgentSession,
        AgentSessionRepository,
        AgentType,
    )

    repo = AgentSessionRepository()
    results = []
    org_id = uuid4()

    # Test create session
    try:
        session = AgentSession(
            org_id=org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test-user",
            title="Test Session",
        )
        created = await repo.create(session)
        results.append(("Create session", created is not None, None))
        session_id = created.id
    except Exception as e:
        results.append(("Create session", False, str(e)))
        return results

    # Test get session
    try:
        retrieved = await repo.get(session_id, org_id)
        results.append(
            (
                "Get session",
                retrieved is not None and retrieved.title == "Test Session",
                None,
            )
        )
    except Exception as e:
        results.append(("Get session", False, str(e)))

    # Test list by org
    try:
        sessions, total = await repo.list_by_org(org_id)
        results.append(("List sessions", len(sessions) > 0, None))
    except Exception as e:
        results.append(("List sessions", False, str(e)))

    # Test deactivate
    try:
        deactivated = await repo.deactivate(session_id, org_id)
        results.append(
            (
                "Deactivate session",
                deactivated is not None and deactivated.is_active is False,
                None,
            )
        )
    except Exception as e:
        results.append(("Deactivate session", False, str(e)))

    # Cleanup
    try:
        await repo.delete(session_id, org_id)
    except Exception:
        pass

    return results


async def test_agent_message_repository():
    """Test AgentMessage repository operations."""
    from cerebro.core.repositories.agents import (
        AgentSession,
        AgentSessionRepository,
        AgentType,
        AgentMessage,
        AgentMessageRepository,
        MessageRole,
    )

    session_repo = AgentSessionRepository()
    message_repo = AgentMessageRepository()
    results = []
    org_id = uuid4()

    # Create test session
    try:
        session = AgentSession(
            org_id=org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test-user",
        )
        session = await session_repo.create(session)
        session_id = session.id
    except Exception as e:
        results.append(("Setup test session", False, str(e)))
        return results

    # Test create messages
    try:
        for i, role in enumerate([MessageRole.USER, MessageRole.ASSISTANT]):
            message = AgentMessage(
                session_id=session_id,
                org_id=org_id,
                role=role,
                content={"text": f"Message {i}"},
                input_tokens=100 if role == MessageRole.USER else None,
                output_tokens=200 if role == MessageRole.ASSISTANT else None,
            )
            await message_repo.create(message)
        results.append(("Create messages", True, None))
    except Exception as e:
        results.append(("Create messages", False, str(e)))

    # Test list messages
    try:
        messages = await message_repo.list_by_session(session_id)
        results.append(("List messages", len(messages) == 2, None))
    except Exception as e:
        results.append(("List messages", False, str(e)))

    # Test token usage
    try:
        usage = await message_repo.get_token_usage(session_id)
        results.append(("Get token usage", usage["total_tokens"] == 300, None))
    except Exception as e:
        results.append(("Get token usage", False, str(e)))

    # Cleanup
    try:
        await session_repo.delete(session_id, org_id)
    except Exception:
        pass

    return results


async def test_dynamodb_client():
    """Test low-level DynamoDB client operations."""
    from cerebro.core.dynamodb_client import (
        get_client,
        put_item,
        get_item,
        delete_item,
        query,
        pk,
        sk,
        TableName,
    )

    results = []
    test_pk = pk("TEST", str(uuid4()))
    test_sk = sk("ITEM", str(uuid4()))

    # Test put_item
    try:
        item = {
            "PK": test_pk,
            "SK": test_sk,
            "entity_type": "TEST",
            "data": "test data",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await put_item(TableName.CORE, item)
        results.append(("put_item", True, None))
    except Exception as e:
        results.append(("put_item", False, str(e)))
        return results

    # Test get_item
    try:
        retrieved = await get_item(TableName.CORE, test_pk, test_sk)
        results.append(
            (
                "get_item",
                retrieved is not None and retrieved["data"] == "test data",
                None,
            )
        )
    except Exception as e:
        results.append(("get_item", False, str(e)))

    # Test query
    try:
        items = await query(TableName.CORE, test_pk)
        results.append(("query", len(items) > 0, None))
    except Exception as e:
        results.append(("query", False, str(e)))

    # Test delete_item
    try:
        deleted = await delete_item(TableName.CORE, test_pk, test_sk)
        results.append(("delete_item", deleted is True, None))

        # Verify deletion
        retrieved = await get_item(TableName.CORE, test_pk, test_sk)
        results.append(("verify deletion", retrieved is None, None))
    except Exception as e:
        results.append(("delete_item", False, str(e)))

    return results


async def test_health_check():
    """Test DynamoDB health check."""
    from cerebro.core.dynamodb_client import health_check

    results = []

    try:
        health = await health_check()
        results.append(("health_check returns", health is not None, None))
        results.append(("has tables info", "tables" in health, None))
        results.append(("has healthy flag", "healthy" in health, None))

        # Check core table
        if "core" in health.get("tables", {}):
            core_status = health["tables"]["core"].get("status")
            results.append(
                ("core table status", core_status == "ACTIVE", f"status={core_status}")
            )
        else:
            results.append(("core table exists", False, "Not found in health check"))

    except Exception as e:
        results.append(("health_check", False, str(e)))

    return results


async def test_repository_factory():
    """Test repository factory pattern."""
    from cerebro.core.repositories import (
        get_repositories,
        get_org_repo,
        get_finding_repo,
        RepositoryFactory,
    )

    results = []

    try:
        # Test factory singleton
        factory1 = get_repositories()
        factory2 = get_repositories()
        results.append(("factory singleton", factory1 is factory2, None))

        # Test repository access
        org_repo = get_org_repo()
        results.append(("get_org_repo", org_repo is not None, None))

        finding_repo = get_finding_repo()
        results.append(("get_finding_repo", finding_repo is not None, None))

        # Test property access
        results.append(
            ("factory.organizations", factory1.organizations is not None, None)
        )
        results.append(("factory.findings", factory1.findings is not None, None))

        # Test reset
        RepositoryFactory.reset()
        factory3 = get_repositories()
        results.append(("factory reset", factory3 is not factory1, None))

    except Exception as e:
        results.append(("repository factory", False, str(e)))

    return results


async def run_all_tests():
    """Run all integration tests."""
    print_section("DynamoDB Integration Tests")
    print(
        f"Endpoint: {os.environ.get('DYNAMODB_ENDPOINT_URL', 'http://localhost:8000')}"
    )
    print(f"Time: {datetime.now().isoformat()}")

    all_results = []

    # Test health check first
    print_section("Health Check")
    results = await test_health_check()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test repository factory
    print_section("Repository Factory")
    results = await test_repository_factory()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test DynamoDB client
    print_section("DynamoDB Client")
    results = await test_dynamodb_client()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test Organization repository
    print_section("Organization Repository")
    results = await test_organization_repository()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test Finding repository
    print_section("Finding Repository")
    results = await test_finding_repository()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test AgentSession repository
    print_section("AgentSession Repository")
    results = await test_agent_session_repository()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Test AgentMessage repository
    print_section("AgentMessage Repository")
    results = await test_agent_message_repository()
    for name, passed, error in results:
        print_result(name, passed, error)
    all_results.extend(results)

    # Summary
    print_section("Summary")
    passed = sum(1 for _, p, _ in all_results if p)
    failed = sum(1 for _, p, _ in all_results if not p)
    total = len(all_results)

    print(f"  Total:  {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")

    if failed > 0:
        print("\n  SOME TESTS FAILED!")
        sys.exit(1)
    else:
        print("\n  ALL TESTS PASSED!")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
