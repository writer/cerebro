"""Agent tool that answers common security self-service questions."""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from cerebro.agents.self_service import SelfServiceKnowledgeService

from .base import AgentContext, StructuredTool, ToolPermissionLevel, ToolResult


class SecurityQuestionInput(BaseModel):
    question: str = Field(
        ...,
        description="Security question asked by the engineer",
        min_length=5,
        examples=[
            "Does john@writer.com have admin access to production AWS?",
            "Is Redis allowed in production?",
            "What are the critical findings in my team's AWS account?",
            "When is our next SOC2 audit?",
        ],
    )


class SecurityQuestionOutput(BaseModel):
    question_type: str
    confidence: float
    summary: str
    evidence: list[Dict[str, Any]]
    details: Dict[str, Any]
    follow_up: str


class SecuritySelfServiceTool(StructuredTool):
    tool_name = "self_service_security"
    tool_description = (
        "Answer common security access, policy, finding, and compliance questions using "
        "Cerebro's data sources. Each answer includes supporting evidence and a reminder to "
        "loop in security when something looks uncertain."
    )
    input_model = SecurityQuestionInput
    output_model = SecurityQuestionOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    def __init__(self, service: Optional[SelfServiceKnowledgeService] = None) -> None:
        super().__init__()
        self.service = service or SelfServiceKnowledgeService()

    async def _run(self, context: AgentContext, question: str) -> ToolResult:
        answer = await self.service.answer_question(
            org_id=context.org_id,
            session_id=context.session_id,
            user_id=context.user_id,
            question=question,
        )

        payload = answer.to_dict()
        output = SecurityQuestionOutput(**payload)
        return ToolResult(success=True, data=output.model_dump())
