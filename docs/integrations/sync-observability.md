# Integration Sync Observability Enhancements

## Issue History Logging
- Every sync health check now records detected issues in an append-only history table.
- History can be queried via `GET /api/v1/integrations/status/issues/history` with filters for integration, scope, lookback window, and aggregation bucket size.
- Stored fields include severity, issue type, descriptive message, timestamps, and metadata snapshots to support auditing and trend analysis.

## Dashboard Trends & Timeline
- The integrations dashboard fetches history data to render recent issue trends and a scoped timeline when inspecting a specific integration.
- Operators can switch between 6h, 24h, and 7d lookback windows to identify recurring failures or prolonged staleness.
- Active issues remain highlighted separately for quick remediation focus.

## Manual Retry Status Tracking
- Triggering a manual retry now returns a task identifier and the UI polls `GET /api/v1/integrations/sync/{task_id}` for completion updates.
- Task responses expose Celery status, completion timestamp, and (when available) serialized results, enabling operators to confirm retry outcomes without leaving the dashboard.

## Operational Guidance
- Use the history endpoint to feed custom alerts or reports that track integration stability over time.
- Combine trend buckets with active issue data to prioritize remediation for tenants experiencing repeated failures.
- When automating runbooks, poll the task status endpoint after scheduling retries to programmatically react to success or failure states.
