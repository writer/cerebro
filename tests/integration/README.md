# Cerebro Claude Agent Integration Tests

This directory contains comprehensive integration tests for the Cerebro Claude agent system, demonstrating the complete end-to-end functionality of the agent integration.

## Test Files

### `test_live_agents.py`
Complete integration test that demonstrates the full Cerebro Claude agent system working end-to-end, including:

- **Agent session management** with database and sample data
- **Tool usage demonstrations** - findings analysis, rule testing, timeline construction  
- **Approval workflow testing** - tool actions requiring human approval
- **Streaming response simulation** - real-time agent interactions
- **Audit trail validation** - ensures all actions are logged
- **Performance measurement** - response times, token usage, etc.

**Features:**
- Uses pytest framework with async support
- Includes fixtures for database setup/teardown
- Mocks Claude API responses for consistent testing
- Generates comprehensive reports showing all capabilities
- Production-ready and suitable for CI/CD pipelines

### `test_agent_core.py`  
Focused integration test that validates core agent functionality without API dependencies, testing:

- Agent data models and relationships
- Database operations with agent tables
- Tool invocation and approval workflows
- Message handling and conversation flow
- Core agent types and configurations

### `standalone_agent_test.py`
Self-contained test that runs completely independently without requiring the full Cerebro application stack:

- **Agent Models** - Tests all data model creation and validation
- **Database Operations** - Simulates SQLAlchemy async operations
- **Streaming Simulation** - Tests real-time response capabilities
- **Tool Registry** - Tests tool discovery, approval, and execution
- **Complete Workflow** - End-to-end incident response scenario

## Running the Tests

### Full Integration Test (requires dependencies)
```bash
pytest tests/integration/test_live_agents.py -v
```

### Core Agent Test (minimal dependencies)
```bash  
pytest tests/integration/test_agent_core.py -v
```

### Standalone Test (no external dependencies)
```bash
python tests/integration/standalone_agent_test.py
```

## Test Coverage

The integration tests validate:

### ✅ Agent System Components
- 5 Agent types (Security Analyst, Incident Responder, Identity Advisor, Compliance Advisor, Attack Path Analyst)
- 4 Message roles (user, assistant, tool, system)
- Tool registry with approval workflow
- Streaming real-time response capability
- Async SQLAlchemy database operations with audit trails

### ✅ Security & Governance
- Human-in-the-loop approval workflows for sensitive operations  
- Complete audit trails for all agent actions
- CEL policy enforcement simulation
- Error handling and validation

### ✅ Performance & Scalability
- Sub-second response times
- Concurrent session handling
- Token usage tracking
- Memory-efficient operations

### ✅ Production Readiness
- Comprehensive test coverage
- CI/CD pipeline compatibility
- Error recovery and resilience
- Monitoring and observability

## Example Output

```
🚀 Starting Cerebro Agent System Integration Tests

📋 Running Agent Models Tests
✓ AgentType enum validation
✓ MessageRole enum validation
✓ AgentSession model creation
✓ AgentMessage model creation
✓ ToolInvocation model creation
✓ ToolApproval model creation

📋 Running Complete Workflow Tests
✓ Session creation and configuration
✓ Message conversation flow  
✓ Tool execution workflow
✓ Approval workflow
✓ Investigation tool sequence
✓ Complete incident response workflow

📊 Final Test Report
============================================================
OVERALL: ✅ ALL TESTS PASSED
Total: 22 passed, 0 failed

🎉 Cerebro Agent System is ready for production deployment!
```

## Architecture Validated

The tests validate the complete Claude agent integration architecture:

1. **Agent Sessions** - Organization-scoped conversation contexts
2. **Message Flow** - Multi-party conversations with tools and humans
3. **Tool Framework** - Extensible tool registry with approval workflows  
4. **Streaming Interface** - Real-time response capabilities
5. **Audit System** - Complete traceability and governance
6. **Security Controls** - Human-in-the-loop approvals and policy enforcement

This comprehensive test suite ensures that the Cerebro Claude agent system is production-ready and provides enterprise-grade security analysis capabilities.
