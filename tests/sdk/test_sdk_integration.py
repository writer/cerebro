#!/usr/bin/env python3
"""
Quick test to verify Claude SDK integration works correctly.
Tests MCP bridge and runtime initialization without requiring database.
"""

from uuid import uuid4

# Test 1: Verify imports work
print("Test 1: Verifying imports...")
try:
    from cerebro.agents.runtime import CerebroClaudeRuntime
    from cerebro.agents.models import AgentType
    from cerebro.agents.tools import tool_registry, AgentContext, ToolPermissionLevel
    from cerebro.agents.mcp_bridge import create_cerebro_mcp_server

    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    exit(1)

# Test 2: Verify MCP bridge creates server
print("\nTest 2: Creating MCP server...")
try:
    # Create a mock agent context without database session
    org_id = uuid4()
    session_id = uuid4()
    user_id = str(uuid4())

    context = AgentContext(
        session_id=session_id,
        org_id=org_id,
        user_id=user_id,
        agent_type=AgentType.SECURITY_ANALYST.value,
        permission_level=ToolPermissionLevel.READ_ONLY,
    )

    # Create MCP server - need to pass tools, context, and executor
    from cerebro.agents.tools import ToolExecutor

    tools = [tool for tool in tool_registry._tools.values()]
    executor = ToolExecutor()

    mcp_server = create_cerebro_mcp_server(
        tools=tools,
        context=context,
        executor=executor,
    )
    print("✅ MCP server created successfully")
    print(f"   Server type: {type(mcp_server)}")

except Exception as e:
    print(f"❌ MCP server creation failed: {e}")
    import traceback

    traceback.print_exc()
    exit(1)

# Test 3: Verify runtime initialization
print("\nTest 3: Initializing runtime...")
try:
    runtime = CerebroClaudeRuntime(
        model="claude-3-5-sonnet-20241022",
        max_tokens=8192,
        temperature=0.1,
    )
    print("✅ Runtime initialized successfully")
    print(f"   Model: {runtime.model}")
    print(f"   Max tokens: {runtime.max_tokens}")
    print(f"   Temperature: {runtime.temperature}")
except Exception as e:
    print(f"❌ Runtime initialization failed: {e}")
    import traceback

    traceback.print_exc()
    exit(1)

# Test 4: Verify tool registry
print("\nTest 4: Checking tool registry...")
try:
    available_tools = list(tool_registry.list_tools())
    print(f"✅ Tool registry has {len(available_tools)} tools:")
    for tool_obj in available_tools:
        # list_tools returns tool objects, not names
        desc = (
            tool_obj.description[:60] + "..."
            if len(tool_obj.description) > 60
            else tool_obj.description
        )
        print(f"   - {tool_obj.name}: {desc}")
except Exception as e:
    print(f"❌ Tool registry check failed: {e}")
    import traceback

    traceback.print_exc()
    exit(1)

print("\n" + "=" * 60)
print("🎉 All SDK integration tests passed!")
print("=" * 60)
print("\nNext steps:")
print("1. Set up PostgreSQL database")
print("2. Run: make db-migrate")
print("3. Run full integration tests: uv run pytest tests/agents/")
