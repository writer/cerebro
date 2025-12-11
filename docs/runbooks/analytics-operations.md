# Analytics Operations Runbook

## Background Jobs

- Ensure the Celery analytics worker is running with the `analytics` queue:
  - `celery -A cerebro.tasks.celery_app worker -l info -Q analytics`
- Celery beat must be active so `collect_security_metrics_all_orgs` executes hourly:
  - `celery -A cerebro.tasks.celery_app beat -l info`
- Environment variables:
  - `ENVIRONMENT=test` (development/testing)
  - `DATABASE_URL` (core transactional DB)
  - `SNOWFLAKE_DATABASE_URL` (analytics warehouse)

## Metrics Instrumentation

- Dashboard generation timings are exported via Prometheus histogram `cerebro_dashboard_component_duration_seconds`.
- Scrape Flask/ASGI metrics endpoint (default `/metrics`) to collect timing data.
- Monitor component labels (`security_metrics`, `executive_summary`, `identity_analytics`, `risk_heatmap`, `compliance_status`, `total`) for hot spots.
- Recommended alert: high percentile (>5s) for `total` component sustained for 5 minutes.

## CI Pipeline

- `unit-tests` job runs `uv run pytest -m "not integration"` on every push/PR.
- `snowflake-integration-tests` job validates Snowflake connectivity for analytics workloads.
- To reproduce locally: `SNOWFLAKE_DATABASE_URL=... uv run pytest tests/integration/analytics/test_analytics_tasks_snowflake.py`.
