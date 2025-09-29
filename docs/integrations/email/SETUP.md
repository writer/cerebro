# 📧 Email Notifications Setup Guide

Send security findings and compliance alerts via email with Cerebro's email notification system.

## Features

✅ **SMTP Support** - Use any SMTP server (Gmail, SendGrid, AWS SES, etc.)
✅ **HTML Templates** - Professional, color-coded email templates
✅ **Severity Filtering** - Only send critical/high severity alerts
✅ **Event Filtering** - Choose which event types trigger emails
✅ **Digest Mode** - Daily/weekly email digests instead of immediate alerts
✅ **Retry Logic** - Automatic retry with exponential backoff
✅ **TLS/STARTTLS** - Secure email transmission
✅ **CC Recipients** - Send copies to multiple addresses
✅ **Audit Logging** - Complete delivery tracking and status

---

## Quick Start

### 1. Prepare SMTP Credentials

Choose your email provider and get SMTP credentials:

#### Gmail

```bash
# Enable 2FA and create App Password:
# https://myaccount.google.com/apppasswords

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@gmail.com
```

#### SendGrid

```bash
# Create API key: https://app.sendgrid.com/settings/api_keys

SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.xxx
FROM_EMAIL=security@yourdomain.com
```

#### AWS SES

```bash
# Get SMTP credentials from SES console
# https://console.aws.amazon.com/ses/

SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-username
SMTP_PASSWORD=your-ses-password
FROM_EMAIL=security@yourdomain.com
```

### 2. Create Email Configuration

```bash
curl -X POST http://localhost:8000/api/v1/notifications/email/configs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Alerts",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "your-email@gmail.com",
    "smtp_password": "your-app-password",
    "from_email": "security@yourdomain.com",
    "from_name": "Cerebro Security",
    "to_emails": ["security-team@yourdomain.com"],
    "cc_emails": ["ciso@yourdomain.com"],
    "use_tls": true,
    "enabled": true,
    "severity_filter": ["critical", "high"],
    "event_types": ["finding.created", "compliance.check_failed"],
    "digest_mode": false
  }'
```

### 3. Test Your Configuration

```bash
# Send a test email
curl -X POST http://localhost:8000/api/v1/notifications/email/test/{config_id} \
  -H "Authorization: Bearer $TOKEN"
```

---

## Configuration Options

### Email Config Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Human-readable configuration name |
| `smtp_host` | string | ✅ | SMTP server hostname |
| `smtp_port` | integer | ❌ | SMTP port (default: 587) |
| `smtp_username` | string | ❌ | SMTP authentication username |
| `smtp_password` | string | ❌ | SMTP authentication password |
| `from_email` | string | ✅ | Sender email address |
| `from_name` | string | ❌ | Sender display name |
| `to_emails` | array | ✅ | List of recipient email addresses |
| `cc_emails` | array | ❌ | List of CC email addresses |
| `use_tls` | boolean | ❌ | Use TLS encryption (default: true) |
| `enabled` | boolean | ❌ | Enable this configuration (default: true) |
| `severity_filter` | array | ❌ | Filter by severity: `["critical", "high"]` |
| `event_types` | array | ✅ | Event types to send emails for |
| `digest_mode` | boolean | ❌ | Send digest instead of immediate (default: false) |
| `digest_frequency` | string | ❌ | Digest frequency: `daily` or `weekly` |

### Event Types

- `finding.created` - New security finding detected
- `compliance.check_failed` - Compliance control failure
- `monitoring.alert` - Proactive monitoring alert

### Severity Levels

- `critical` - Critical vulnerabilities requiring immediate action
- `high` - High-priority security issues
- `medium` - Medium-priority findings
- `low` - Low-priority informational findings

---

## Use Cases

### Critical Findings Only

```json
{
  "name": "Critical Alerts",
  "severity_filter": ["critical"],
  "event_types": ["finding.created"],
  "to_emails": ["on-call@company.com"]
}
```

### Compliance Team Digest

```json
{
  "name": "Compliance Weekly Digest",
  "event_types": ["compliance.check_failed"],
  "digest_mode": true,
  "digest_frequency": "weekly",
  "to_emails": ["compliance@company.com"]
}
```

### Executive Summary

```json
{
  "name": "Executive Summary",
  "severity_filter": ["critical", "high"],
  "event_types": ["finding.created", "compliance.check_failed"],
  "digest_mode": true,
  "digest_frequency": "daily",
  "to_emails": ["ciso@company.com", "ceo@company.com"]
}
```

---

## API Reference

### Create Email Config

```bash
POST /api/v1/notifications/email/configs
```

**Request Body:**
```json
{
  "name": "string",
  "smtp_host": "string",
  "smtp_port": 587,
  "from_email": "string",
  "to_emails": ["string"],
  "event_types": ["string"]
}
```

**Response:** `201 Created`
```json
{
  "config_id": "uuid",
  "org_id": "uuid",
  "name": "string",
  "enabled": true,
  "created_at": "2025-09-29T10:00:00Z"
}
```

### List Email Configs

```bash
GET /api/v1/notifications/email/configs?enabled=true
```

### Get Email Config

```bash
GET /api/v1/notifications/email/configs/{config_id}
```

### Update Email Config

```bash
PATCH /api/v1/notifications/email/configs/{config_id}
```

**Request Body:**
```json
{
  "enabled": false,
  "to_emails": ["new-email@company.com"]
}
```

### Delete Email Config

```bash
DELETE /api/v1/notifications/email/configs/{config_id}
```

### Send Test Email

```bash
POST /api/v1/notifications/email/test/{config_id}
```

### List Email Notifications

```bash
GET /api/v1/notifications/email/notifications?status=sent&limit=100
```

**Query Parameters:**
- `config_id` - Filter by config ID
- `status` - Filter by status: `sent`, `failed`, `retrying`
- `limit` - Max results (default: 100)
- `offset` - Pagination offset

### Get Email Statistics

```bash
GET /api/v1/notifications/email/notifications/stats?config_id={config_id}
```

**Response:**
```json
{
  "total_sent": 1523,
  "total_failed": 12,
  "total_retrying": 3,
  "success_rate": 99.21
}
```

---

## Email Templates

Cerebro includes professional HTML email templates:

### Finding Created Template

- Color-coded by severity (red for critical, orange for high)
- Finding title, severity badge, and description
- Affected resource details
- OCSF data and compliance frameworks
- Direct link to finding (if web UI configured)

### Compliance Failed Template

- Framework and control information
- Number of failing findings
- Affected accounts
- Remediation guidance

### Monitoring Alert Template

- Alert title and description
- Severity indicator
- Related finding link
- Metadata display

---

## Troubleshooting

### Test Email Not Received

1. **Check spam folder** - Security alerts may be flagged
2. **Verify SMTP credentials** - Test with email client first
3. **Check firewall** - Ensure port 587 (or 465) is open
4. **Review logs** - Check email_notifications table for error_message

```sql
SELECT * FROM email_notifications
WHERE status = 'failed'
ORDER BY created_at DESC
LIMIT 10;
```

### Gmail Authentication Failed

- **Enable 2FA** - Required for App Passwords
- **Create App Password** - Don't use account password
- **Allow less secure apps** - Or use OAuth2

### SendGrid Delivery Issues

- **Verify sender domain** - Add SPF/DKIM records
- **Check API key permissions** - Needs Mail Send permission
- **Review SendGrid logs** - Check activity feed

### AWS SES Issues

- **Verify email addresses** - Both sender and recipients (sandbox mode)
- **Request production access** - For unlimited sending
- **Check SES sending statistics** - Monitor bounces and complaints

### High Retry Count

```bash
# Check for persistent failures
curl http://localhost:8000/api/v1/notifications/email/notifications?status=failed \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.retry_count > 2)'
```

Common causes:
- Invalid recipient addresses
- SMTP server rate limiting
- Network connectivity issues
- Authentication token expiration

---

## Best Practices

### Security

- 🔒 **Use App Passwords** - Never use account passwords
- 🔒 **Rotate credentials** - Change SMTP passwords regularly
- 🔒 **Encrypt passwords** - Store securely in environment variables
- 🔒 **Audit access** - Monitor who creates email configs

### Reliability

- 📊 **Monitor statistics** - Check success rates regularly
- 📊 **Set up alerts** - Alert on delivery failures
- 📊 **Use digest mode** - Reduce email volume
- 📊 **Test regularly** - Verify configs after changes

### Performance

- ⚡ **Limit recipients** - Keep to_emails list reasonable
- ⚡ **Use severity filters** - Only send important alerts
- ⚡ **Enable digest mode** - For high-volume environments
- ⚡ **Monitor retry counts** - Investigate persistent failures

---

## Provider-Specific Guides

### Gmail Setup

1. Enable 2-Factor Authentication
2. Create App Password: https://myaccount.google.com/apppasswords
3. Use `smtp.gmail.com:587` with STARTTLS
4. Consider Google Workspace for higher sending limits

**Sending Limits:**
- Free Gmail: 500 emails/day
- Google Workspace: 2,000 emails/day

### SendGrid Setup

1. Create account: https://sendgrid.com
2. Verify sender domain with DNS records
3. Create API key with "Mail Send" permission
4. Use `smtp.sendgrid.net:587`

**Sending Limits:**
- Free tier: 100 emails/day
- Essentials: 50,000 emails/month

### AWS SES Setup

1. Verify email addresses (sender and recipients)
2. Request production access (removes sandbox limits)
3. Get SMTP credentials from console
4. Use region-specific endpoint

**Sending Limits:**
- Sandbox: 200 emails/day (verified addresses only)
- Production: 50,000+ emails/day (scales with usage)

---

## Integration Examples

### Python

```python
import requests

# Create email config
response = requests.post(
    "http://localhost:8000/api/v1/notifications/email/configs",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "name": "Security Alerts",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_username": "alerts@company.com",
        "smtp_password": "app-password",
        "from_email": "alerts@company.com",
        "to_emails": ["security@company.com"],
        "event_types": ["finding.created"],
        "severity_filter": ["critical", "high"]
    }
)

config_id = response.json()["config_id"]

# Send test email
requests.post(
    f"http://localhost:8000/api/v1/notifications/email/test/{config_id}",
    headers={"Authorization": f"Bearer {token}"}
)
```

### Terraform

```hcl
resource "cerebro_email_config" "security_alerts" {
  name          = "Security Alerts"
  smtp_host     = "smtp.gmail.com"
  smtp_port     = 587
  smtp_username = var.smtp_username
  smtp_password = var.smtp_password
  from_email    = "security@company.com"
  to_emails     = ["security-team@company.com"]
  event_types   = ["finding.created", "compliance.check_failed"]
  severity_filter = ["critical", "high"]
}
```

---

## Next Steps

- [Webhook Notifications](../webhooks/SETUP.md) - Send to custom endpoints
- [Slack Integration](../slack/SETUP.md) - Real-time Slack notifications
- [API Reference](/docs/user-guide/API.md) - Complete API documentation

---

**Need Help?** Check [Troubleshooting Guide](/docs/user-guide/TROUBLESHOOTING.md) or open an issue on [GitHub](https://github.com/haasonsaas/cerebro/issues)