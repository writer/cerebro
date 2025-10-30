# SDK Migration Notes

## October 2025

### Agent Enhancements
- **Transactional safety:** `AgentReviewManager`, `AgentToolingManager`, and `AgentNotificationManager` now use nested-aware transactions. Existing callers no longer need to call `commit()` after invoking these helpers, but they should avoid wrapping them in manual transactions unless necessary.
- **Enum-friendly APIs:** `AgentManager` and review helpers accept `AgentType` and `ReviewTaskStatus` enum values directly (strings still work for backwards compatibility).
- **Memory analytics:** `get_memory_stats` performs SQL aggregation. Optional filters (`role`, `scope_type`, `since_hours`) tighten result sets. Consumers relying on per-entry payloads should switch to `list_memory_entries`.
- **Session lookup queries:** `sessions_for_finding`/`sessions_for_incident` use JSON containment and support pagination via `limit`/`offset`.

### Integration Registry
- `IntegrationTaskRegistry` centralizes Celery task registration. Custom integrations must register their task before calling `IntegrationService.trigger_sync`.
- Legacy direct accesses to the `_TASKS` dictionary should migrate to the registry helper.

### Compatibility Checklist
| Action | Required | Notes |
|--------|----------|-------|
| Remove manual `commit()` calls after review/comment helpers | ✅ | Helpers now commit internally. |
| Replace `_TASKS[...]` references with `IntegrationTaskRegistry.register/get` | ✅ | The old attribute is removed. |
| Update unit tests to expect enum inputs | ⚠️ | Tests passing raw strings still work, but teams should prefer enums for type safety. |
| Adjust memory analytics consumers | ⚠️ | Aggregated stats return counts; call `list_memory_entries` for detailed payloads. |
