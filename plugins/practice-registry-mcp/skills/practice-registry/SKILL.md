---
name: practice-registry
description: Use when generating, editing, or reviewing Scala, Python, TypeScript, JavaScript, or Rust code so company-specific practices are checked before planning, after edits, and before final handoff.
---

# Practice Registry

Use the Practice Registry MCP server for Scala, Python, TypeScript, JavaScript, and Rust code work.

1. Before non-trivial code generation or edits, call `preflight` when intent or files are known.
2. Call `check_plan` with the intent, files, language, framework, dependencies, and planned approach before writing code.
3. After edits, call `scan_diff` with the final diff for concrete changed-line findings.
4. Use `check_diff` for advisory practice guidance when the code shape is broader than a concrete Semgrep finding.
5. Before the final response, call `finalize_change` with the final diff and pass the matching `check_plan` observation id when available.
6. Trust the `passed` field. Treat only `allowed` and `follow_guidance` as pass decisions.
7. Use `explain_practice` before overriding a `discouraged`, `legacy_accepted`, or `needs_review` result.
8. Treat `banned` findings as blockers. Change the code before finishing.
9. Treat `legacy_accepted` as allowed only for the recorded context. Do not add new handwritten uses of legacy patterns.
10. Use `propose_practice` for repeated uncovered decisions and `record_exception` for scoped exception requests.
11. Resolve `needs_review` through the named owner or `record_approval`. Research approval requires an indexed practice plus at least two directly supporting HTTPS sources from independent publishers and domains.
12. Do not use research approval to approve an exception. Exceptions still require the recorded owner decision.

If hooks or CI report a practice finding, fix the code and rerun the same check before summarizing the work.
