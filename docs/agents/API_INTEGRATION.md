# Claude Agent API Integration

Complete REST API integration for Claude agents with streaming support.

## Overview

The Cerebro agent system provides a fully integrated REST API that enables:

- **Session Management**: Create and manage agent conversation sessions
- **Streaming Responses**: Real-time agent responses via Server-Sent Events (SSE)
- **Tool Execution**: Automatic tool calling with security guardrails
- **Audit Logging**: Complete audit trail of all agent actions
- **Multi-turn Conversations**: Context-aware conversations with message history

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      REST API Layer                          │
│  /api/v1/agents/* (FastAPI Router with SSE support)         │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Service Layer                              │
│  AgentSessionService (Session management & orchestration)   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Runtime Layer                              │
│  CerebroClaudeRuntime (SDK integration & message streaming) │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                 Claude SDK (v1.0.0)                          │
│  ClaudeSDKClient with MCP Server integration                │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   MCP Bridge                                 │
│  Converts Cerebro tools to SDK-compatible MCP tools         │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Tool System (5 tools)                           │
│  findings_list, finding_update_status, rules, query,        │
│  timeline - all with security guardrails                     │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### 1. Health Check

```http
GET /api/v1/agents/health
```

**Response:**
```json
{
  "status": "healthy",
  "runtime": "operational",
  "sdk_integration": "active"
}
```

### 2. Create Session

```http
POST /api/v1/agents/sessions
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_type": "security_analyst",
  "title": "Investigate AWS findings",
  "context": {
    "provider_scope": ["aws"],
    "finding_ids": ["<uuid>"]
  }
}
```

**Response (201):**
```json
{
  "session_id": "<uuid>",
  "org_id": "<uuid>",
  "agent_type": "security_analyst",
  "title": "Investigate AWS findings",
  "created_at": "2025-09-29T12:00:00Z",
  "created_by": "user@example.com",
  "status": "active",
  "context": {
    "provider_scope": ["aws"],
    "finding_ids": ["<uuid>"]
  }
}
```

### 3. List Sessions

```http
GET /api/v1/agents/sessions?limit=50&offset=0&agent_type=security_analyst
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "sessions": [
    {
      "session_id": "<uuid>",
      "agent_type": "security_analyst",
      "title": "Investigate AWS findings",
      "created_at": "2025-09-29T12:00:00Z",
      "status": "active"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

### 4. Get Session with Messages

```http
GET /api/v1/agents/sessions/<session_id>?message_limit=50
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "session": {
    "session_id": "<uuid>",
    "agent_type": "security_analyst",
    "title": "Investigate AWS findings",
    "created_at": "2025-09-29T12:00:00Z",
    "status": "active",
    "context": {}
  },
  "messages": [
    {
      "message_id": "<uuid>",
      "role": "user",
      "content": "List critical findings",
      "timestamp": "2025-09-29T12:01:00Z"
    },
    {
      "message_id": "<uuid>",
      "role": "assistant",
      "content": "I found 5 critical findings...",
      "timestamp": "2025-09-29T12:01:05Z",
      "metadata": {
        "tool_calls": ["findings_list"]
      }
    }
  ],
  "message_count": 2
}
```

### 5. Send Message (Non-Streaming)

```http
POST /api/v1/agents/sessions/<session_id>/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "List the most critical security findings",
  "stream": false
}
```

**Response (200):**
```json
{
  "session_id": "<uuid>",
  "response": "I found 3 critical security findings:\n1. Public S3 bucket...",
  "tool_calls": [
    {
      "type": "tool_use",
      "tool_name": "findings_list",
      "result": "success"
    }
  ]
}
```

### 6. Send Message (Streaming with SSE)

```http
POST /api/v1/agents/sessions/<session_id>/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "Analyze these findings and suggest remediation",
  "stream": true
}
```

**Response (200):** Server-Sent Events stream

```
event: message_start
data: {"type": "message_start"}

event: content_delta
data: {"type": "content_delta", "content": "I'll analyze"}

event: content_delta
data: {"type": "content_delta", "content": " the findings"}

event: tool_use
data: {"type": "tool_use", "content": {"tool": "findings_list"}}

event: tool_result
data: {"type": "tool_result", "content": {"status": "success"}}

event: content_delta
data: {"type": "content_delta", "content": "Based on the findings..."}

event: complete
data: {"type": "complete"}
```

### 7. Get Message History

```http
GET /api/v1/agents/sessions/<session_id>/messages?limit=100&offset=0
Authorization: Bearer <token>
```

**Response (200):**
```json
[
  {
    "message_id": "<uuid>",
    "role": "user",
    "content": "List critical findings",
    "timestamp": "2025-09-29T12:01:00Z"
  },
  {
    "message_id": "<uuid>",
    "role": "assistant",
    "content": "I found 5 critical findings...",
    "timestamp": "2025-09-29T12:01:05Z"
  }
]
```

## Usage Examples

### Python with httpx

```python
import httpx
import asyncio

async def create_and_chat():
    headers = {"Authorization": "Bearer YOUR_TOKEN"}
    base_url = "http://localhost:8000/api/v1/agents"

    async with httpx.AsyncClient() as client:
        # Create session
        response = await client.post(
            f"{base_url}/sessions",
            headers=headers,
            json={
                "agent_type": "security_analyst",
                "title": "Security Investigation"
            }
        )
        session_id = response.json()["session_id"]

        # Send message with streaming
        async with client.stream(
            "POST",
            f"{base_url}/sessions/{session_id}/messages",
            headers=headers,
            json={
                "message": "What are the critical issues?",
                "stream": True
            }
        ) as stream:
            async for line in stream.aiter_lines():
                if line.startswith("data: "):
                    print(line[6:])

asyncio.run(create_and_chat())
```

### JavaScript/TypeScript

```typescript
// Create session
const response = await fetch('/api/v1/agents/sessions', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    agent_type: 'security_analyst',
    title: 'Security Investigation'
  })
});

const { session_id } = await response.json();

// Stream messages using EventSource
const eventSource = new EventSource(
  `/api/v1/agents/sessions/${session_id}/messages`,
  {
    headers: {
      'Authorization': 'Bearer YOUR_TOKEN',
    }
  }
);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Event:', data.type, data.content);
};

eventSource.addEventListener('complete', () => {
  eventSource.close();
});
```

### cURL

```bash
# Create session
curl -X POST http://localhost:8000/api/v1/agents/sessions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_type": "security_analyst",
    "title": "Test Session"
  }'

# Send message (non-streaming)
curl -X POST http://localhost:8000/api/v1/agents/sessions/<SESSION_ID>/messages \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "List critical findings",
    "stream": false
  }'

# Send message (streaming)
curl -N -X POST http://localhost:8000/api/v1/agents/sessions/<SESSION_ID>/messages \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Analyze security posture",
    "stream": true
  }'
```

## Error Handling

### Common Error Responses

**401 Unauthorized:**
```json
{
  "detail": "Not authenticated"
}
```

**404 Not Found:**
```json
{
  "detail": "Session not found or access denied"
}
```

**400 Bad Request:**
```json
{
  "detail": "Invalid agent type: invalid_type"
}
```

**500 Internal Server Error:**
```json
{
  "detail": "Failed to create agent session"
}
```

## Testing

### Run Integration Tests

```bash
# Test SDK integration (no database required)
uv run python test_sdk_integration.py

# Test API integration (requires running server)
uv run python test_agents_api.py

# Start development server
uv run uvicorn cerebro.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Access API Documentation

Interactive API documentation is available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

Look for the **agents** tag with 6 endpoints.

## Security

### Authentication

All endpoints (except `/health`) require authentication via Bearer token:

```http
Authorization: Bearer <your-jwt-token>
```

### Authorization

- Users can only access sessions within their organization
- All API calls are scoped to `current_user.org_id`
- Session access is validated on every request

### Tool Execution

- All tool calls go through `ToolExecutor` with security checks
- CEL policies are enforced on every tool invocation
- Dry-run mode available for testing without side effects

### Audit Logging

- Every agent action is logged with full context
- Tool invocations are recorded in `agent_tool_invocations` table
- Messages are stored in `agent_messages` table
- Audit trail accessible via `AgentAuditEvent` system

## Performance

### Streaming Benefits

- **Real-time feedback**: Users see agent thinking in real-time
- **Early cancellation**: Clients can disconnect if response is sufficient
- **Reduced latency**: First tokens arrive quickly, before completion
- **Better UX**: Progress indicators and intermediate results

### Optimization Tips

1. **Use streaming** for interactive use cases
2. **Batch operations** when processing multiple findings
3. **Set message limits** when fetching history (default: 50)
4. **Use pagination** for session lists (default: 50, max: 100)

## Monitoring

### Key Metrics

- Session creation rate
- Message throughput (messages/sec)
- Tool execution success rate
- Average response time
- Stream connection duration

### Health Checks

```bash
# Check agent system health
curl http://localhost:8000/api/v1/agents/health

# Check overall API health
curl http://localhost:8000/health
```

## Troubleshooting

### Agent System Unavailable

**Problem:** `/agents/health` returns 503

**Solutions:**
1. Check Claude SDK initialization
2. Verify MCP server creation
3. Review runtime logs for errors
4. Ensure tools are registered

### Streaming Not Working

**Problem:** SSE events not received

**Solutions:**
1. Ensure `stream: true` in request
2. Check Content-Type is `text/event-stream`
3. Verify proxy/load balancer allows streaming
4. Use `-N` flag with cURL for streaming

### Session Not Found

**Problem:** 404 when accessing session

**Solutions:**
1. Verify session belongs to your organization
2. Check session_id is valid UUID
3. Ensure session wasn't expired/deleted

## Next Steps

1. **Authentication**: Implement JWT token generation and validation
2. **Database**: Set up PostgreSQL and run migrations
3. **Configuration**: Configure Claude API key in environment
4. **Production**: Deploy with proper CORS, rate limiting, and monitoring

## Related Documentation

- [Agent Architecture](./README.md)
- [Tool Development Guide](./tool-development.md)
- [SDK Integration Details](./fixes-summary.md)
- [Security Model](../architecture/security.md)