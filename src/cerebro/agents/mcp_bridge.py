"""
Bridge between Cerebro tools and Claude SDK MCP servers.

Converts Cerebro Tool objects into SDK-compatible MCP tool functions.
"""

import json
from typing import Any, Callable, Dict, List
from functools import wraps

import structlog
from claude_agent_sdk import tool as sdk_tool, create_sdk_mcp_server

from cerebro.agents.tools.base import Tool, AgentContext, ToolExecutor

logger = structlog.get_logger(__name__)


def cerebro_tool_to_mcp(
    cerebro_tool: Tool,
    context: AgentContext,
    executor: ToolExecutor,
) -> Callable:
    """
    Convert a Cerebro Tool into an SDK-compatible MCP tool function.

    Args:
        cerebro_tool: The Cerebro Tool instance
        context: Agent context for execution
        executor: Tool executor with security checks

    Returns:
        An async function decorated with @sdk_tool
    """

    # Build input schema dict from Pydantic model
    input_schema = cerebro_tool.input_schema.model_json_schema()

    # Create the tool function
    async def tool_func(args: Dict[str, Any]) -> Dict[str, Any]:
        """
        SDK MCP tool function that wraps Cerebro tool execution.

        The SDK expects tools to return a dict with:
        - content: List of content blocks (text, images, etc.)
        - isError: Optional boolean indicating error
        """
        logger.info(
            "MCP tool invoked",
            tool_name=cerebro_tool.name,
            args=args,
            session_id=context.session_id,
        )

        try:
            # Execute through Cerebro's tool executor (handles security, audit, etc.)
            result = await executor.execute_tool(
                tool=cerebro_tool,
                raw_inputs=args,
                context=context,
            )

            # Format result for SDK
            if result.success:
                # Build content text
                content_text = ""

                if result.dry_run and result.preview:
                    content_text = f"**DRY RUN PREVIEW**\n\n{json.dumps(result.preview, indent=2)}"
                elif result.data:
                    content_text = json.dumps(result.data, indent=2)
                else:
                    content_text = "Tool executed successfully"

                if result.warnings:
                    content_text += f"\n\n**Warnings:**\n" + "\n".join(f"- {w}" for w in result.warnings)

                if result.requires_approval:
                    content_text += f"\n\n**Approval Required**: {result.approval_id}"

                return {
                    "content": [{"type": "text", "text": content_text}],
                    "isError": False,
                }
            else:
                # Tool failed
                error_text = f"**Tool Error**: {result.error}"
                if result.metadata:
                    error_text += f"\n\nMetadata: {json.dumps(result.metadata, indent=2)}"

                return {
                    "content": [{"type": "text", "text": error_text}],
                    "isError": True,
                }

        except Exception as e:
            logger.exception("MCP tool execution failed", tool_name=cerebro_tool.name, error=str(e))
            return {
                "content": [{"type": "text", "text": f"Tool execution error: {str(e)}"}],
                "isError": True,
            }

    # Apply SDK tool decorator
    decorated_func = sdk_tool(
        name=cerebro_tool.name,
        description=cerebro_tool.description,
        input_schema=input_schema,
    )(tool_func)

    return decorated_func


def create_cerebro_mcp_server(
    tools: List[Tool],
    context: AgentContext,
    executor: ToolExecutor,
    server_name: str = "cerebro",
    server_version: str = "1.0.0",
):
    """
    Create an SDK MCP server from Cerebro tools.

    Args:
        tools: List of Cerebro Tool instances
        context: Agent context for execution
        executor: Tool executor
        server_name: Name of the MCP server
        server_version: Version of the MCP server

    Returns:
        MCP server instance for use with ClaudeAgentOptions
    """

    # Convert all Cerebro tools to MCP tool functions
    mcp_tools = []
    for tool in tools:
        try:
            mcp_tool = cerebro_tool_to_mcp(tool, context, executor)
            mcp_tools.append(mcp_tool)
            logger.info(
                "Registered Cerebro tool with MCP server",
                tool_name=tool.name,
                server_name=server_name,
            )
        except Exception as e:
            logger.error(
                "Failed to register tool with MCP server",
                tool_name=tool.name,
                error=str(e),
            )

    # Create SDK MCP server
    mcp_server = create_sdk_mcp_server(
        name=server_name,
        version=server_version,
        tools=mcp_tools,
    )

    logger.info(
        "Created Cerebro MCP server",
        server_name=server_name,
        tool_count=len(mcp_tools),
    )

    return mcp_server