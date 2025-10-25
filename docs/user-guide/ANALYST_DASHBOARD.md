# Analyst Dashboard Overview

This guide walks through the analyst dashboard that now ships with Cerebro. It
explains the data pipelines that populate the experience, highlights the key
panels analysts will rely on, and documents the operational playbook for keeping
the views fresh.

## Data Collection Pipeline

The executive dashboard depends on two scheduled jobs:

1. **`collect_security_metrics_all_orgs`** – executes hourly and records daily
   finding statistics, SLA performance, and overall risk scores for every
   tenant. It is defined in `cerebro.tasks.analytics_tasks` and runs via the new
   `analytics` Celery queue.
2. **`collect_security_metrics_for_org`** – invoked by the all-org task for each
   tenant and can be triggered ad hoc. It gathers finding counts, writes
   `SecurityMetricSnapshot` rows, and persists the latest `RiskScoringEngine`
   outputs.

> **Operational tip:** Verify the analytics worker is running (`celery -A
> cerebro.tasks.celery_app worker -Q analytics`). Snapshots should begin
> appearing in `security_metric_snapshots` within a few minutes of enabling the
> queue.

## Executive Dashboard Panels

The front-end page at `/analytics/executive` layers analytics from multiple
services:

- **Executive Overview** – overall risk score, dimension scores, trend, and
  board-ready talking points.
- **Findings and Operations** – real-time totals, severity mix, SLA breaches,
  and daily remediation velocity.
- **Compliance Coverage** – normalised view of CIS/NIST control adherence using
  the `DashboardAnalytics` repository helpers.
- **Identity Risk Posture** – privilege sprawl summary, top risky identities,
  MFA coverage by provider, and privilege anomalies from
  `IdentityAnalyzer` / `PrivilegeSprawlDetector`.
- **Risk Heatmap** – provider/resource concentration analysis produced by the
  `RiskScoringEngine.generate_risk_heatmap` helper.

Each panel consumes the FastAPI endpoint exposed at
`GET /api/v1/analytics/organizations/{org_id}/dashboard`, which wraps
`DashboardAnalytics.generate_comprehensive_dashboard`.

## Enabling the Experience

1. **Seed baseline data** – run resource collectors or load fixtures so that
   findings, IAM edges, and resources exist for the tenant.
2. **Start Celery beat** – ensure the default beat schedule is active so the
   hourly analytics job kicks off automatically.
3. **Configure the front-end** – set `NEXT_PUBLIC_API_BASE_URL` so the dashboard
   page can reach the API from the browser or during local development.
4. **Validate via tests** – execute `uv run pytest tests/analytics
   tests/api/test_analytics_dashboard_api.py` to confirm the collectors and API
   endpoints behave as expected.

Following these steps provides analysts with a continuously refreshed view of
organizational risk posture, identity exposure, and compliance coverage.
