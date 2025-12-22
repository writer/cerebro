"""Prompt construction utilities for Cerebro agents."""

from __future__ import annotations

from typing import List, Optional

from cerebro.agents.models import AgentSession, AgentType
from cerebro.core.config import settings


def build_security_agent_prompt(
    agent_type: AgentType,
    *,
    session: Optional[AgentSession] = None,
    memory_snippets: Optional[List[str]] = None,
) -> str:
    """Build the shared system prompt for agent runtimes."""

    base_prompt = (
        "You are a specialized security agent within the Cerebro security system of record.\n"
        "You have access to powerful tools for analyzing security findings, investigating incidents,"
        " and providing actionable recommendations.\n\n"
        "MULTI-STEP PLANNING:\n"
        "For complex tasks, break them down into clear steps and execute them sequentially:\n\n"
        'Example 1 - "Conduct full AWS security audit":\n'
        "Step 1: Use get_org_context to identify AWS accounts\n"
        "Step 2: Use findings_list filtered to AWS resources\n"
        "Step 3: Use query to pull configuration gaps and recent changes\n"
        "Step 4: Use security_analysis to cluster high-risk findings\n"
        "Step 5: Use remediation to produce prioritized actions\n"
        "Step 6: Summarize key insights with smart_finding_summarizer\n\n"
        'Example 2 - "Investigate suspicious user activity":\n'
        "Step 1: Use query to gather the user's recent events\n"
        "Step 2: Use timeline to build a chronological view\n"
        "Step 3: Use security_analysis to evaluate risk indicators\n"
        "Step 4: Use remediation to recommend containment actions\n"
        "Step 5: Capture highlights with smart_finding_summarizer\n\n"
        'Example 3 - "Prepare for SOC2 audit":\n'
        "Step 1: Use get_org_context to understand scope\n"
        "Step 2: Use findings_list filtered by compliance frameworks\n"
        "Step 3: Use rules to validate critical guardrails\n"
        "Step 4: Use smart_finding_summarizer for executive-ready insights\n"
        "Step 5: Use natural_language_query to answer stakeholder questions\n\n"
        "WHEN TO USE MULTI-STEP PLANNING:\n"
        "- Comprehensive audits or assessments\n"
        "- Complex investigations requiring multiple data sources\n"
        "- Compliance preparation requiring evidence collection\n"
        "- Risk analysis needing multiple perspectives\n"
        '- Any task with "full", "comprehensive", "complete" in the request\n\n'
        "SAFETY GUIDELINES:\n"
        "- Always default to dry-run mode for any potentially destructive actions\n"
        "- Request human approval for any changes to production systems\n"
        "- Never expose sensitive credentials or secrets in responses\n"
        "- All your actions are audited in append-only logs\n"
        "- Provide clear, actionable recommendations with compliance mappings\n\n"
        "RESPONSE STYLE:\n"
        "- Be concise and technical - assume security expertise\n"
        "- Cite specific evidence from findings and audit trails\n"
        "- Map security issues to CIS, NIST, or CWE frameworks when relevant\n"
        "- Prioritize actions by risk and business impact\n"
        "- Always provide clear next steps\n"
        "- For multi-step tasks, announce your plan before starting execution"
    )

    context_section = ""
    if session and session.context:
        org_context = session.context.get("_auto_loaded_org_context")
        system_context = session.context.get("_auto_loaded_system_context")
        session_memory = session.context.get("_auto_loaded_session_memory", [])

        if org_context or system_context or session_memory:
            context_lines: list[str] = [
                "",
                "=== YOUR ENVIRONMENT (YOU ALREADY KNOW THIS) ===",
            ]

            if org_context:
                org_name = org_context.get("org_name", "Unknown Organization")
                context_lines.append("")
                context_lines.append(f"Organization: {org_name}")

                repos = org_context.get("repositories", [])
                if repos:
                    context_lines.append("")
                    context_lines.append(f"Repositories ({len(repos)}):")
                    for repo in repos[:5]:
                        context_lines.append(
                            f"  - {repo.get('name')}: {repo.get('framework', 'unknown')}"
                            f" ({repo.get('type', 'unknown')})"
                        )

                providers = org_context.get("providers_connected", [])
                if providers:
                    context_lines.append("")
                    context_lines.append(f"Connected Providers ({len(providers)}):")
                    for provider in providers:
                        context_lines.append(
                            f"  - {provider.get('provider', 'unknown').upper()}:"
                            f" {provider.get('resource_count', 0)} resources"
                        )

                stats = org_context.get("statistics", {})
                if stats:
                    context_lines.append("")
                    context_lines.append("Security Statistics:")
                    context_lines.append(
                        f"  - Total Resources: {stats.get('total_resources', 0)}"
                    )
                    context_lines.append(
                        f"  - Total Principals: {stats.get('total_principals', 0)}"
                    )
                    context_lines.append(
                        f"  - Open Findings: {stats.get('open_findings', 0)}"
                    )

                tools_count = org_context.get("agent_tools_count", 0)
                if tools_count > 0:
                    context_lines.append("")
                    context_lines.append(
                        f"Available Tools: {tools_count} specialized security tools"
                    )

            if system_context:
                db_info = system_context.get("database", {})
                if db_info.get("connected"):
                    db_line = "Database: PostgreSQL"
                    if db_info.get("pg_version"):
                        db_line += f" {db_info['pg_version']}"
                    context_lines.append("")
                    context_lines.append(db_line)

                env_info = system_context.get("environment", {})
                if env_info:
                    deployment = env_info.get("deployment_type", "unknown")
                    environment = env_info.get("environment", "unknown")
                    context_lines.append("")
                    context_lines.append(f"Deployment: {deployment} ({environment})")

                provider_health = system_context.get("provider_health", [])
                if provider_health:
                    degraded = [
                        entry
                        for entry in provider_health
                        if entry.get("status") != "healthy"
                    ]
                    if degraded:
                        context_lines.append("")
                        context_lines.append("⚠️ Provider Health Alerts:")
                        for entry in degraded:
                            context_lines.append(
                                f"  - {entry.get('provider', 'unknown').upper()}:"
                                f" {entry.get('status', 'unknown')}"
                            )

            # Include learned session memory (cross-session context)
            if session_memory:
                context_lines.append("")
                context_lines.append(
                    "=== REMEMBERED CONTEXT (from previous sessions) ==="
                )

                # Group by context type
                preferences = [
                    m for m in session_memory if m.get("type") == "user_preference"
                ]
                facts = [m for m in session_memory if m.get("type") == "learned_fact"]
                corrections = [
                    m for m in session_memory if m.get("type") == "correction"
                ]
                environment = [
                    m for m in session_memory if m.get("type") == "environment"
                ]

                if preferences:
                    context_lines.append("")
                    context_lines.append("User Preferences:")
                    for pref in preferences[:5]:
                        context_lines.append(
                            f"  - {pref.get('key')}: {pref.get('value')}"
                        )

                if facts:
                    context_lines.append("")
                    context_lines.append("Learned Facts:")
                    for fact in facts[:5]:
                        confidence = fact.get("confidence", 1.0)
                        conf_str = (
                            f" (confidence: {confidence:.0%})"
                            if confidence < 1.0
                            else ""
                        )
                        context_lines.append(
                            f"  - {fact.get('key')}: {fact.get('value')}{conf_str}"
                        )

                if corrections:
                    context_lines.append("")
                    context_lines.append("Corrections/Feedback:")
                    for corr in corrections[:3]:
                        context_lines.append(
                            f"  - {corr.get('key')}: {corr.get('value')}"
                        )

                if environment:
                    context_lines.append("")
                    context_lines.append("Environment Mappings:")
                    for env in environment[:5]:
                        context_lines.append(
                            f"  - {env.get('key')}: {env.get('value')}"
                        )

                context_lines.append("")
                context_lines.append(
                    "IMPORTANT: This is information you learned from previous conversations."
                )
                context_lines.append(
                    "Apply this context automatically - don't ask about things you already know."
                )
                context_lines.append("=== END REMEMBERED CONTEXT ===")

            context_lines.extend(
                [
                    "",
                    "IMPORTANT: You ALREADY KNOW this information. Don't ask the user about it.",
                    "Use this context to provide specific, informed responses without needing to ask",
                    "for basic setup details.",
                    "=== END ENVIRONMENT CONTEXT ===",
                    "",
                ]
            )

            context_section = "\n".join(context_lines)

    agent_prompts = {
        AgentType.SECURITY_ANALYST: (
            "ROLE: Security Analyst\n"
            "FOCUS: Triage findings, assess risk, cluster similar issues, recommend remediation\n"
            "EXPERTISE: Vulnerability assessment, risk scoring, compliance mapping, threat analysis"
        ),
        AgentType.INCIDENT_RESPONDER: (
            "ROLE: Incident Response Specialist\n"
            "FOCUS: Build timelines, coordinate containment, collect evidence, manage incidents\n"
            "EXPERTISE: Digital forensics, incident coordination, timeline analysis, containment strategies"
        ),
        AgentType.IDENTITY_ADVISOR: (
            "ROLE: Identity & Access Management Advisor\n"
            "FOCUS: Analyze IAM configurations, privilege escalation, access reviews, identity stitching\n"
            "EXPERTISE: Identity governance, privilege management, access controls, identity correlation"
        ),
        AgentType.COMPLIANCE_ADVISOR: (
            "ROLE: Compliance & Risk Advisor\n"
            "FOCUS: Map findings to frameworks, generate compliance reports, track remediation\n"
            "EXPERTISE: CIS Controls, NIST Cybersecurity Framework, SOC 2, compliance management"
        ),
        AgentType.ATTACK_PATH_ANALYST: (
            "ROLE: Attack Path & Threat Analyst\n"
            "FOCUS: Model attack paths, identify choke points, recommend defensive measures\n"
            "EXPERTISE: Attack path modeling, threat modeling, network analysis, defensive architecture"
        ),
    }

    memory_section = ""
    if memory_snippets:
        memory_lines: list[str] = ["", "=== RETAINED MEMORY SNIPPETS ==="]
        for snippet in memory_snippets[: settings.agent_memory_max_snippets]:
            memory_lines.append(f"- {snippet}")
        memory_lines.append(
            "Always verify these facts against current data before acting."
        )
        memory_lines.append("=== END MEMORY SNIPPETS ===")
        memory_section = "\n".join(memory_lines)

    agent_specific = agent_prompts.get(agent_type, "")

    prompt_parts = [base_prompt]
    if context_section:
        prompt_parts.append(context_section)
    if memory_section:
        prompt_parts.append(memory_section)
    if agent_specific:
        prompt_parts.append(agent_specific)

    return "\n\n".join(prompt_parts).strip()
