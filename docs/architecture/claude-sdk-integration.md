# Claude Code SDK Integration Architecture

This document provides a deep dive into Cerebro's integration with the Claude Code SDK, explaining design decisions, patterns used, and alignment with SDK best practices.

## Overview

Cerebro uses the [Claude Agent SDK for Python](https://github.com/anthropics/claude-agent-sdk-python) to provide AI-powered security agents. The integration follows the SDK's recommended MCP (Model Context Protocol) server pattern for tool execution.

## SDK Architecture

### Message Flow

```
User Input
    │
    ▼
┌────────────────────────────────────┐
│  CerebroClaudeRuntime              │
│  • create AgentContext             │
│  • build MCP server from tools     │
│  • configure ClaudeAgentOptions    │
└─────────────┬──────────────────────┘
              │
              │ query(message)
              ▼
┌────────────────────────────────────┐
│  ClaudeSDKClient                   │
│  • connects to Claude Code CLI     │
│  • manages conversation state      │
│  • handles tool execution loop     │
└─────────────┬──────────────────────┘
              │
              │ receive_messages()
              ▼
┌────────────────────────────────────┐
│  Message Stream                    │
│  • AssistantMessage (text)         │
│  • ToolUseBlock (tool call)        │
│  • SystemMessage (metadata)        │
│  • ResultMessage (completion)      │
└─────────────┬──────────────────────┘
              │
              │ Tool execution handled by SDK
              ▼
┌────────────────────────────────────┐
│  MCP Server                        │
│  • invokes tool_func(args)         │
│  • returns content blocks          │
└─────────────┬──────────────────────┘
              │
              ▼
┌────────────────────────────────────┐
│  cerebro_tool_to_mcp()             │
│  • wraps ToolExecutor.execute()    │
│  • enforces security policies      │
│  • formats results for SDK         │
└─────────────┬──────────────────────┘
              │
              ▼
┌────────────────────────────────────┐
│  Cerebro Database                  │
│  • findings, audit logs, etc.      │
└────────────────────────────────────┘
```

## Key Integration Points

### 1. MCP Server Creation

**SDK Pattern**:
```python
@tool("calculator_add", "Add two numbers", {"a": float, "b": float})
async def add_numbers(args: dict[str, Any]) -> dict[str, Any]:
    result = args["a"] + args["b"]
    return {
        "content": [{"type": "text", "text": f"Result: {result}"}]
    }

mcp_server = create_sdk_mcp_server(
    name="calculator",
    version="1.0.0",
    tools=[add_numbers],
)
```

**Cerebro Implementation** (`mcp_bridge.py`):
```python
def cerebro_tool_to_mcp(cerebro_tool, context, executor):
    # Extract input schema from Pydantic model
    input_schema = cerebro_tool.input_schema.model_json_schema()

    # Create wrapper function
    async def tool_func(args: Dict[str, Any]) -> Dict[str, Any]:
        # Execute through Cerebro's security infrastructure
        result = await executor.execute_tool(
            tool=cerebro_tool,
            raw_inputs=args,
            context=context,
        )

        # Format for SDK
        if result.success:
            content_text = json.dumps(result.data, indent=2)
            return {
                "content": [{"type": "text", "text": content_text}],
                "isError": False,
            }
        else:
            return {
                "content": [{"type": "text", "text": f"Error: {result.error}"}],
                "isError": True,
            }

    # Apply SDK decorator
    return sdk_tool(
        name=cerebro_tool.name,
        description=cerebro_tool.description,
        input_schema=input_schema,
    )(tool_func)
```

**Why This Works**:
- Preserves Cerebro's security layer (CEL policies, permissions, dry-run)
- Maintains audit logging and approval workflows
- Adapts Cerebro's ToolResult to SDK's content block format
- Allows per-context tool configuration (permission levels, scope)

### 2. Client Configuration

**SDK Pattern**:
```python
options = ClaudeAgentOptions(
    model="claude-3-5-sonnet-20241022",
    max_tokens=8192,
    temperature=0.1,
    system_prompt="You are a helpful assistant",
    mcp_servers={"calc": calculator_server},
    allowed_tools=["mcp__calc__add", "mcp__calc__subtract"],
)

async with ClaudeSDKClient(options=options) as client:
    await client.connect()
    await client.query("Calculate 15 + 27")
```

**Cerebro Implementation** (`runtime.py`):
```python
# Get tools based on user's permission level
available_tools = tool_registry.list_tools(agent_context.permission_level)

# Create MCP server with security context
mcp_server = create_cerebro_mcp_server(
    tools=available_tools,
    context=agent_context,
    executor=self.tool_executor,
    server_name="cerebro",
    server_version="1.0.0",
)

# Build allowed tools list (SDK naming convention)
allowed_tools = [f"mcp__cerebro__{tool.name}" for tool in available_tools]

options = ClaudeAgentOptions(
    model=self.model,
    max_tokens=self.max_tokens,
    temperature=self.temperature,
    system_prompt=self._get_system_prompt(session.agent_type),
    mcp_servers={"cerebro": mcp_server},
    allowed_tools=allowed_tools,
)

async with ClaudeSDKClient(options=options) as client:
    await client.connect()
    await client.query(message, session_id=str(session.id))
```

**Key Differences**:
- Cerebro filters tools by permission level dynamically
- Agent context (org_id, user_id, provider_scope) embedded in MCP server
- Session-specific tool configuration
- Security policies evaluated at runtime

### 3. Message Processing

**SDK Pattern**:
```python
async for msg in client.receive_messages():
    if isinstance(msg, AssistantMessage):
        for block in msg.content:
            if isinstance(block, TextBlock):
                print(f"Claude: {block.text}")
            elif isinstance(block, ToolUseBlock):
                print(f"Tool: {block.name}")
    elif isinstance(msg, ResultMessage):
        print(f"Tokens: {msg.usage.input_tokens}")
```

**Cerebro Implementation**:
```python
async for response_msg in client.receive_messages():
    if isinstance(response_msg, AssistantMessage):
        for block in response_msg.content:
            if isinstance(block, TextBlock):
                # Stream to user
                if stream:
                    yield {
                        "type": "text",
                        "content": block.text,
                        "metadata": {"streaming": True}
                    }
                assistant_content.append({"type": "text", "text": block.text})

            elif isinstance(block, ToolUseBlock):
                # Log tool invocation (SDK executes via MCP automatically)
                logger.info("Tool invoked", tool_name=block.name)
                tool_calls_count += 1

                if stream:
                    yield {
                        "type": "tool_use",
                        "content": {"tool_name": block.name, "input": block.input},
                        "metadata": {"tool_call_id": block.id}
                    }

    elif isinstance(response_msg, SystemMessage):
        # Log system events
        logger.info("System message", subtype=response_msg.subtype)

    elif isinstance(response_msg, ResultMessage):
        # Extract token usage for cost tracking
        if response_msg.usage:
            total_input_tokens = response_msg.usage.input_tokens
            total_output_tokens = response_msg.usage.output_tokens
```

**Cerebro Enhancements**:
- Streaming support with structured yield format
- Tool invocation tracking for metrics
- Token usage extraction for billing
- System message logging for debugging
- Database persistence of full conversation

## Design Decisions

### 1. Why MCP Server Pattern?

**Alternative Considered**: Manual tool execution with ToolResultBlock

```python
# ❌ Old approach (manual execution)
if isinstance(block, ToolUseBlock):
    tool = tool_registry.get(block.name)
    result = await executor.execute_tool(tool, block.input, context)

    # Manually format and send back
    tool_result = ToolResultBlock(
        tool_use_id=block.id,
        content=json.dumps(result.data),
        is_error=not result.success
    )
    await client.send_tool_result(tool_result)  # ❌ Not part of SDK API
```

**MCP Server Approach** (current):
```python
# ✅ SDK handles execution automatically
mcp_server = create_cerebro_mcp_server(tools, context, executor)
options = ClaudeAgentOptions(mcp_servers={"cerebro": mcp_server})

# Tool execution happens inside SDK
async for msg in client.receive_messages():
    if isinstance(msg, ToolUseBlock):
        # Just observe, SDK invokes MCP server automatically
        logger.info("Tool being executed by SDK")
```

**Benefits**:
- SDK manages multi-turn conversation loop
- Automatic tool result formatting
- Error handling within SDK
- Support for parallel tool execution
- Better streaming performance

### 2. Security Context in MCP Server

Each MCP server is created **per-session** with embedded security context:

```python
mcp_server = create_cerebro_mcp_server(
    tools=available_tools,
    context=agent_context,  # ← Includes org_id, user_id, permissions
    executor=self.tool_executor,
)
```

This means:
- Different users get different tool sets (permission filtering)
- Org isolation enforced at MCP server creation
- Provider scope applied per-session
- CEL policies evaluated with session context

**Why Not Global MCP Server?**

A global server would require:
```python
# ❌ Insecure: All users share same tools
global_mcp_server = create_cerebro_mcp_server(
    tools=ALL_TOOLS,  # No filtering
    context=None,     # No security context
)
```

This would break:
- Permission-based tool access
- Org isolation
- Provider scoping
- Audit trail attribution

### 3. Tool Result Formatting

**SDK Expectation**:
```python
{
    "content": [
        {"type": "text", "text": "Result data here"},
        {"type": "image", "source": "..."},  # Optional
    ],
    "isError": False  # Optional
}
```

**Cerebro Mapping**:
```python
if result.dry_run and result.preview:
    content_text = f"**DRY RUN PREVIEW**\n\n{json.dumps(result.preview, indent=2)}"
elif result.data:
    content_text = json.dumps(result.data, indent=2)
else:
    content_text = "Tool executed successfully"

if result.warnings:
    content_text += f"\n\n**Warnings:**\n" + "\n".join(result.warnings)

return {
    "content": [{"type": "text", "text": content_text}],
    "isError": not result.success,
}
```

**Enhancements**:
- Dry-run preview formatting with markdown
- Warning messages appended
- Approval requirement indication
- Structured JSON for data results

### 4. Import Minimalism

**What We Import**:
```python
# runtime.py
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    TextBlock,
    ToolUseBlock,
    ResultMessage,
    SystemMessage,
)

# mcp_bridge.py
from claude_agent_sdk import tool as sdk_tool, create_sdk_mcp_server
```

**What We Don't Import**:
- `UserMessage` - Not needed, we pass strings to `client.query()`
- `ToolResultBlock` - SDK handles via MCP, we never construct these
- `StreamEvent` - Not used in current implementation
- `query()` function - We use `ClaudeSDKClient` directly

This keeps dependencies minimal and clear about which SDK features we use.

## Performance Optimizations

### 1. Connection Pooling

The SDK client uses `async with` for proper connection lifecycle:

```python
async with ClaudeSDKClient(options=options) as client:
    await client.connect()
    # Connection reused for all messages in session
    await client.query(message)
    async for msg in client.receive_messages():
        # Process messages
```

Connection is closed automatically on context exit.

### 2. Streaming

We yield messages as they arrive:

```python
async for response_msg in client.receive_messages():
    if isinstance(response_msg, AssistantMessage):
        for block in response_msg.content:
            if isinstance(block, TextBlock) and stream:
                yield {"type": "text", "content": block.text}
```

This provides real-time feedback to users without waiting for complete response.

### 3. Token Tracking

Extract token usage from ResultMessage:

```python
elif isinstance(response_msg, ResultMessage):
    if response_msg.usage:
        total_input_tokens = response_msg.usage.input_tokens
        total_output_tokens = response_msg.usage.output_tokens
```

Used for:
- Cost estimation
- Rate limiting
- Performance monitoring

## Error Handling

### SDK Error Types

The SDK provides specific error types:

```python
from claude_agent_sdk import CLINotFoundError, CLIConnectionError

try:
    async with ClaudeSDKClient(options=options) as client:
        await client.connect()
except CLINotFoundError:
    raise RuntimeError("Claude Code CLI not installed")
except CLIConnectionError:
    raise RuntimeError("Failed to connect to Claude Code CLI")
```

### Cerebro Error Handling

We wrap SDK operations and provide structured errors:

```python
try:
    async with ClaudeSDKClient(options=options) as client:
        await client.connect()
        await client.query(message, session_id=str(session.id))
        # ... process messages
except Exception as e:
    logger.exception("Agent message processing failed", error=str(e))

    # Store error in database
    await self._store_message(
        session,
        MessageRole.ASSISTANT,
        {"error": str(e), "type": "system_error"}
    )

    # Yield error to user
    yield {
        "type": "error",
        "content": {"message": "Agent processing failed", "error": str(e)},
        "metadata": {"session_id": str(session.id)}
    }
```

## Testing Strategy

### Unit Tests

Test MCP bridge in isolation:

```python
def test_cerebro_tool_to_mcp():
    # Create mock tool
    tool = FindingsListTool()
    context = AgentContext(...)
    executor = ToolExecutor()

    # Convert to MCP
    mcp_func = cerebro_tool_to_mcp(tool, context, executor)

    # Verify it's callable and has SDK metadata
    assert callable(mcp_func)
    assert hasattr(mcp_func, '_tool_name')
```

### Integration Tests

Test full flow with SDK:

```python
async def test_agent_session_with_tool_call():
    runtime = CerebroClaudeRuntime()
    session = await runtime.create_session(...)

    responses = []
    async for response in runtime.send_message(
        session=session,
        message="List high severity findings",
        user_id="test@example.com",
        stream=True
    ):
        responses.append(response)

    # Verify tool was called
    tool_use_msgs = [r for r in responses if r["type"] == "tool_use"]
    assert len(tool_use_msgs) > 0
    assert tool_use_msgs[0]["content"]["tool_name"] == "findings_list"
```

### Mock Testing

For tests without API keys:

```python
class MockClaudeSDKClient:
    async def connect(self):
        pass

    async def query(self, message, session_id):
        pass

    async def receive_messages(self):
        yield AssistantMessage(content=[
            TextBlock(text="Here are the findings"),
            ToolUseBlock(name="findings_list", input={"severity": "high"})
        ])
        yield ResultMessage(usage=Usage(input_tokens=100, output_tokens=200))
```

## Comparison with Direct Anthropic API

| Feature | Direct API | Claude SDK | Cerebro + SDK |
|---------|------------|------------|---------------|
| Tool Calling | Manual format | MCP servers | MCP + security |
| Multi-turn | Manual state | Automatic | Automatic + audit |
| Streaming | SSE parsing | Built-in | Built-in + yield |
| Error Handling | HTTP errors | Typed errors | Typed + structured |
| Tool Execution | Manual invoke | In-process | In-process + policies |
| Code | ~500 lines | ~200 lines | ~250 lines |

## SDK Version Compatibility

**Current SDK Version**: v1.0.0

**Breaking Changes to Watch**:
- MCP server API changes
- Message type additions/removals
- Client lifecycle changes

**Upgrade Strategy**:
1. Monitor SDK changelog
2. Test in staging environment
3. Update mcp_bridge.py first (isolated layer)
4. Update runtime.py message handling
5. Update tests
6. Roll out to production

## Future SDK Features

Features from SDK roadmap that Cerebro should adopt:

1. **Hooks**: Pre/post tool execution callbacks
   ```python
   options = ClaudeAgentOptions(
       hooks={
           "before_tool": log_tool_invocation,
           "after_tool": record_metrics,
       }
   )
   ```

2. **Multiple MCP Servers**: Combine Cerebro tools with external MCP servers
   ```python
   options = ClaudeAgentOptions(
       mcp_servers={
           "cerebro": cerebro_mcp_server,
           "external": external_mcp_server,
       }
   )
   ```

3. **Custom Transports**: For non-CLI deployments
   ```python
   transport = HTTPTransport(endpoint="https://api.cerebro.com")
   client = ClaudeSDKClient(options=options, transport=transport)
   ```

## References

- [Claude Agent SDK GitHub](https://github.com/anthropics/claude-agent-sdk-python)
- [MCP Protocol Spec](https://spec.modelcontextprotocol.io)
- [Claude API Documentation](https://docs.anthropic.com/claude/reference)
- [Cerebro Agent Fixes Summary](../agents/fixes-summary.md)

---

**Last Updated**: 2025-09-29
**SDK Version**: v1.0.0
**Author**: Cerebro Engineering Team