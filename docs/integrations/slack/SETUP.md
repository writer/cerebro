This guide documents the supported Slack webhook workflow. It is intended for operators configuring notifications and for developers maintaining the integration.

---

## Features

### 🔔 Supported Event Types

1. **Finding Created** - New security findings
2. **Finding Updated** - Status changes on findings
3. **Compliance Failed** - Failed compliance control tests
4. **Monitoring Alert** - Proactive monitoring alerts

### Formatting and Delivery Behavior

- Slack payloads are rendered with Block Kit using severity-specific colors.
- Severity filters and event filters are enforced per webhook configuration.
- Delivery uses exponential backoff (three attempts by default) with a 10s timeout.
- Notification status, retries, and error details are written to `slack_notifications`.

---

## Setup

### Step 1: Create Slack Incoming Webhook

1. Go to your Slack workspace settings
2. Navigate to **Apps** → **Manage** → **Custom Integrations**
3. Click **Incoming Webhooks**
4. Click **Add to Slack**
5. Select a channel (e.g., `#security-alerts`)
6. Click **Add Incoming WebHooks Integration**
7. Copy the **Webhook URL** (looks like `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX`)

### Step 2: Configure Webhook in Cerebro

#### Via API:

```bash
curl -X POST https://cerebro.example.com/api/v1/slack/webhooks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Alerts",
    "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
    "channel": "#security-alerts",
    "enabled": true,
    "severity_filter": ["critical", "high"],
    "event_types": ["finding_created", "compliance_failed", "monitoring_alert"]
  }'
```

#### Via Web UI:

1. Log in to Cerebro
2. Navigate to **Settings** → **Integrations** → **Slack**
3. Click **Add Webhook**
4. Fill in the form:
   - **Name**: Human-readable name (e.g., "Security Alerts")
   - **Webhook URL**: Paste the URL from Step 1
   - **Channel**: The Slack channel (e.g., `#security-alerts`)
   - **Enabled**: Toggle on
   - **Severity Filter**: Select `critical` and `high`
   - **Event Types**: Select desired event types
5. Click **Save**

---

## Configuration

### Webhook Configuration Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable webhook name |
| `webhook_url` | URL | Yes | Slack incoming webhook URL |
| `channel` | string | No | Slack channel (for reference) |
| `enabled` | boolean | No | Enable/disable webhook (default: `true`) |
| `severity_filter` | array | No | Filter by severity: `["critical", "high", "medium", "low"]` |
| `finding_type_filter` | array | No | Filter by finding types (future feature) |
| `event_types` | array | Yes | Event types to monitor (see below) |

### Event Types

| Event Type | Description | Use Case |
|------------|-------------|----------|
| `finding_created` | New security finding detected | Real-time security alerts |
| `finding_updated` | Finding status changed | Track remediation progress |
| `compliance_failed` | Compliance control failed | Regulatory compliance monitoring |
| `monitoring_alert` | Proactive monitoring alert | Background threat detection |

### Example Configurations

#### 1. Critical Security Alerts Only

```json
{
  "name": "Critical Security Alerts",
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#security-critical",
  "enabled": true,
  "severity_filter": ["critical"],
  "event_types": ["finding_created", "monitoring_alert"]
}
```

#### 2. Compliance Monitoring

```json
{
  "name": "Compliance Alerts",
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#compliance",
  "enabled": true,
  "severity_filter": null,
  "event_types": ["compliance_failed"]
}
```

#### 3. All Security Events

```json
{
  "name": "All Security Events",
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#security-all",
  "enabled": true,
  "severity_filter": null,
  "event_types": [
    "finding_created",
    "finding_updated",
    "compliance_failed",
    "monitoring_alert"
  ]
}
```

---

## API Reference

### Endpoints

#### Create Webhook

```http
POST /api/v1/slack/webhooks
```

**Request Body:**
```json
{
  "name": "Security Alerts",
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#security-alerts",
  "enabled": true,
  "severity_filter": ["critical", "high"],
  "event_types": ["finding_created", "monitoring_alert"]
}
```

**Response:** `201 Created`
```json
{
  "webhook_id": "123e4567-e89b-12d3-a456-426614174000",
  "org_id": "123e4567-e89b-12d3-a456-426614174001",
  "name": "Security Alerts",
  "webhook_url": "***************XXXX",
  "channel": "#security-alerts",
  "enabled": true,
  "severity_filter": ["critical", "high"],
  "finding_type_filter": null,
  "event_types": ["finding_created", "monitoring_alert"],
  "created_at": "2025-09-29T12:00:00Z",
  "updated_at": "2025-09-29T12:00:00Z",
  "created_by": "user@example.com"
}
```

---

#### List Webhooks

```http
GET /api/v1/slack/webhooks
```

**Response:** `200 OK`
```json
[
  {
    "webhook_id": "123e4567-e89b-12d3-a456-426614174000",
    "org_id": "123e4567-e89b-12d3-a456-426614174001",
    "name": "Security Alerts",
    "webhook_url": "***************XXXX",
    "channel": "#security-alerts",
    "enabled": true,
    ...
  }
]
```

---

#### Get Webhook

```http
GET /api/v1/slack/webhooks/{webhook_id}
```

**Response:** `200 OK` (same format as Create)

---

#### Update Webhook

```http
PATCH /api/v1/slack/webhooks/{webhook_id}
```

**Request Body:** (all fields optional)
```json
{
  "name": "Updated Name",
  "enabled": false,
  "severity_filter": ["critical"]
}
```

**Response:** `200 OK` (updated webhook)

---

#### Delete Webhook

```http
DELETE /api/v1/slack/webhooks/{webhook_id}
```

**Response:** `204 No Content`

---

#### List Notifications

```http
GET /api/v1/slack/notifications?webhook_id={webhook_id}&limit=50
```

**Response:** `200 OK`
```json
[
  {
    "notification_id": "123e4567-e89b-12d3-a456-426614174000",
    "webhook_id": "123e4567-e89b-12d3-a456-426614174001",
    "event_type": "finding_created",
    "finding_id": "123e4567-e89b-12d3-a456-426614174002",
    "severity": "critical",
    "status": "sent",
    "status_code": 200,
    "error_message": null,
    "retry_count": 0,
    "sent_at": "2025-09-29T12:00:00Z",
    "created_at": "2025-09-29T12:00:00Z"
  }
]
```

---

#### Get Notification Statistics

```http
GET /api/v1/slack/notifications/stats
```

**Response:** `200 OK`
```json
{
  "total_sent": 1234,
  "total_failed": 12,
  "last_24h_sent": 56,
  "last_24h_failed": 1,
  "by_severity": {
    "critical": 45,
    "high": 123,
    "medium": 456,
    "low": 610
  },
  "by_event_type": {
    "finding_created": 800,
    "monitoring_alert": 234,
    "compliance_failed": 200
  }
}
```

---

## Message Formats

### Finding Created

```
🚨 New Security Finding: CRITICAL

Organization: Acme Corp
Severity: CRITICAL
Rule: aws-s3-public-bucket
Status: open

Title:
S3 Bucket Publicly Accessible

Description:
S3 bucket 'prod-data-bucket' allows public read access,
exposing sensitive data to the internet.

Resource ID: arn:aws:s3:::prod-data-bucket
Sep 29, 2025 at 12:00 PM
```

**Color:** Red (#d32f2f) for critical

---

### Compliance Failed

```
⚠️ Compliance Control Failed

Organization: Acme Corp
Control ID: CIS-AWS-1.1
Control: Ensure MFA is enabled for root account
Failures: 1

Sep 29, 2025 at 12:00 PM
```

**Color:** Orange (#f57c00)

---

### Monitoring Alert

```
🚨 Security Alert: New Critical Findings Detected

Organization: Acme Corp
Severity: HIGH

5 new critical findings detected in the last 5 minutes.
Review immediately in Cerebro dashboard.

Sep 29, 2025 at 12:00 PM
```

**Color:** Orange (#f57c00) for high severity

---

## Monitoring

### Notification Audit Trail

All notifications are logged in the `slack_notifications` table:

```sql
SELECT
  notification_id,
  event_type,
  status,
  status_code,
  retry_count,
  sent_at,
  error_message
FROM slack_notifications
WHERE org_id = 'YOUR_ORG_ID'
ORDER BY created_at DESC
LIMIT 100;
```

### Webhook Status

Check webhook configuration and notification stats:

```bash
# List all webhooks
GET /api/v1/slack/webhooks

# Get notification history for a webhook
GET /api/v1/slack/notifications?webhook_id=WEBHOOK_ID&limit=100

# Get overall stats
GET /api/v1/slack/notifications/stats
```

### Health Checks

Monitor Slack integration health:

```bash
# Check recent failures
SELECT COUNT(*)
FROM slack_notifications
WHERE status = 'failed'
  AND created_at > NOW() - INTERVAL '24 hours';

# Check retry rates
SELECT
  AVG(retry_count) as avg_retries,
  MAX(retry_count) as max_retries
FROM slack_notifications
WHERE created_at > NOW() - INTERVAL '24 hours';
```

---

## Troubleshooting

### Common Issues

#### 1. Notifications Not Arriving

**Problem:** Slack notifications aren't being received

**Solutions:**
- ✅ Verify webhook is enabled: `GET /api/v1/slack/webhooks`
- ✅ Check severity filters match finding severity
- ✅ Verify event type is in `event_types` array
- ✅ Check Slack webhook URL is valid and not expired
- ✅ Review notification logs: `GET /api/v1/slack/notifications`

#### 2. HTTP 404 Errors

**Problem:** `status_code: 404` in notification logs

**Cause:** Slack webhook URL is invalid or deleted

**Solution:**
1. Recreate webhook in Slack workspace
2. Update webhook URL in Cerebro:
   ```bash
   PATCH /api/v1/slack/webhooks/{webhook_id}
   {
     "webhook_url": "NEW_URL"
   }
   ```

#### 3. HTTP 500 Errors

**Problem:** `status_code: 500` in notification logs

**Cause:** Slack service error or malformed message

**Solution:**
- Check Slack status: https://status.slack.com
- Review error message in notification log
- Contact Cerebro support if issue persists

#### 4. Too Many Notifications

**Problem:** Slack channel is flooded with notifications

**Solutions:**
- **Increase severity filter:**
  ```json
  {
    "severity_filter": ["critical"]  // Only critical
  }
  ```
- **Disable non-critical event types:**
  ```json
  {
    "event_types": ["finding_created"]  // Remove monitoring_alert
  }
  ```
- **Temporarily disable webhook:**
  ```json
  {
    "enabled": false
  }
  ```

#### 5. Retry Exhaustion

**Problem:** `retry_count: 3`, `status: failed`

**Cause:** Webhook URL consistently unreachable

**Solution:**
1. Test webhook URL manually:
   ```bash
   curl -X POST WEBHOOK_URL \
     -H "Content-Type: application/json" \
     -d '{"text": "Test from Cerebro"}'
   ```
2. If test fails, recreate webhook in Slack
3. Update URL in Cerebro

---

## Advanced Configuration

### Custom Message Templates

Future feature: Custom message templates using Jinja2

```json
{
  "message_template": {
    "finding_created": {
      "text": "🚨 {{ severity|upper }}: {{ title }}",
      "blocks": [...]
    }
  }
}
```

### Rate Limiting

Built-in rate limiting prevents webhook exhaustion:

- **Max retries:** 3 (configurable)
- **Retry delay:** 2s, 4s, 8s (exponential backoff)
- **Timeout:** 10s per request

### Multiple Webhooks

Configure multiple webhooks for different alert types:

```json
[
  {
    "name": "Critical Alerts - On-Call",
    "channel": "#security-oncall",
    "severity_filter": ["critical"],
    "event_types": ["finding_created", "monitoring_alert"]
  },
  {
    "name": "All Findings - Security Team",
    "channel": "#security-team",
    "severity_filter": null,
    "event_types": ["finding_created", "finding_updated"]
  },
  {
    "name": "Compliance - Audit Team",
    "channel": "#compliance",
    "severity_filter": null,
    "event_types": ["compliance_failed"]
  }
]
```

---

## Security Considerations

### Webhook URL Protection

- ✅ Webhook URLs are **masked** in API responses (only last 8 chars shown)
- ✅ Webhook URLs are **stored encrypted** in database (if envelope encryption enabled)
- ✅ Webhook URLs are **never logged** in application logs
- ⚠️ Treat webhook URLs as **secrets** - they grant write access to Slack channels

### Access Control

- ✅ Webhook management requires **authentication**
- ✅ Users can only manage webhooks for **their organization**
- ✅ Webhook creation/deletion is **audit logged**

### Network Security

- ✅ HTTPS only (no HTTP support)
- ✅ TLS 1.2+ required
- ✅ Certificate validation enforced

---

## Database Schema

### `slack_webhooks` Table

```sql
CREATE TABLE slack_webhooks (
    webhook_id UUID PRIMARY KEY,
    org_id UUID REFERENCES orgs(org_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    webhook_url TEXT NOT NULL,
    channel VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    severity_filter TEXT[],
    finding_type_filter TEXT[],
    event_types TEXT[] NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255)
);
```

### `slack_notifications` Table

```sql
CREATE TABLE slack_notifications (
    notification_id UUID PRIMARY KEY,
    webhook_id UUID REFERENCES slack_webhooks(webhook_id) ON DELETE CASCADE,
    org_id UUID REFERENCES orgs(org_id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    finding_id UUID,
    severity VARCHAR(50),
    payload JSONB NOT NULL,
    status VARCHAR(50) NOT NULL,  -- sent, failed, retrying
    status_code INTEGER,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Support

For issues or questions:

1. **Check logs:** `/api/v1/slack/notifications`
2. **Review documentation:** This guide
3. **Contact support:** security@example.com

---

**Last Updated:** 2025-09-29
**Version:** 1.0.0
**Status:** ✅ Production Ready