# 🔗 Generic Webhook Notifications Setup Guide

Send security findings and compliance alerts to any HTTP endpoint with Cerebro's flexible webhook system.

## Features

✅ **Custom Payloads** - Jinja2 templates for complete control
✅ **HMAC Signatures** - Secure webhook verification with HMAC-SHA256
✅ **HTTP Methods** - Support for POST, PUT, PATCH
✅ **Custom Headers** - Add authentication headers, API keys, etc.
✅ **Authentication** - Bearer tokens, API keys, custom auth
✅ **Event Filtering** - Choose which events trigger webhooks
✅ **Severity Filtering** - Only send critical/high severity alerts
✅ **Retry Logic** - Automatic retry with exponential backoff
✅ **Audit Logging** - Complete delivery tracking with responses

---

## Quick Start

### 1. Create Webhook Configuration

```bash
curl -X POST http://localhost:8000/api/v1/notifications/webhooks/configs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Dashboard",
    "url": "https://dashboard.company.com/api/security/alerts",
    "http_method": "POST",
    "headers": {
      "Content-Type": "application/json",
      "X-API-Key": "your-api-key"
    },
    "payload_template": {
      "event": "security_alert",
      "severity": "{{ finding.severity }}",
      "title": "{{ finding.title }}",
      "resource": "{{ finding.resource_id }}",
      "timestamp": "{{ timestamp }}"
    },
    "use_hmac_signature": true,
    "hmac_secret": "your-secret-key",
    "enabled": true,
    "event_types": ["finding.created"],
    "severity_filter": ["critical", "high"]
  }'
```

### 2. Test Your Configuration

```bash
# Send a test webhook
curl -X POST http://localhost:8000/api/v1/notifications/webhooks/test/{config_id} \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Verify HMAC Signature (Receiver Side)

```python
import hmac
import hashlib
import json

def verify_webhook(payload_str, signature_header, secret):
    """Verify webhook HMAC signature."""
    expected = hmac.new(
        secret.encode('utf-8'),
        payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    received = signature_header.replace('sha256=', '')
    return hmac.compare_digest(expected, received)

# In your webhook handler
@app.post("/api/security/alerts")
def handle_webhook(request):
    payload_str = request.body.decode('utf-8')
    signature = request.headers.get('X-Webhook-Signature')

    if not verify_webhook(payload_str, signature, secret='your-secret-key'):
        return {"error": "Invalid signature"}, 401

    payload = json.loads(payload_str)
    # Process webhook...
```

---

## Configuration Options

### Webhook Config Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Human-readable configuration name |
| `url` | string | ✅ | Webhook endpoint URL |
| `http_method` | string | ❌ | HTTP method: POST, PUT, PATCH (default: POST) |
| `headers` | object | ❌ | Custom HTTP headers |
| `payload_template` | object | ✅ | Jinja2 template for payload |
| `authentication` | object | ❌ | Authentication configuration |
| `use_hmac_signature` | boolean | ❌ | Add HMAC signature header (default: false) |
| `hmac_secret` | string | ❌ | HMAC secret key (required if use_hmac_signature=true) |
| `enabled` | boolean | ❌ | Enable this configuration (default: true) |
| `severity_filter` | array | ❌ | Filter by severity: `["critical", "high"]` |
| `event_types` | array | ✅ | Event types to send webhooks for |
| `timeout_seconds` | integer | ❌ | Request timeout (default: 10, max: 60) |

### Event Types

- `finding.created` - New security finding detected
- `compliance.check_failed` - Compliance control failure
- `monitoring.alert` - Proactive monitoring alert

---

## Payload Templates

### Default Finding Template

```json
{
  "event_type": "finding.created",
  "timestamp": "{{ timestamp }}",
  "organization": {
    "id": "{{ org_id }}",
    "name": "{{ org_name }}"
  },
  "finding": {
    "id": "{{ finding.finding_id }}",
    "title": "{{ finding.title }}",
    "severity": "{{ finding.severity }}",
    "status": "{{ finding.status }}",
    "provider": "{{ finding.provider }}",
    "resource_id": "{{ finding.resource_id }}",
    "resource_type": "{{ finding.resource_type }}",
    "account_id": "{{ finding.account_id }}",
    "region": "{{ finding.region }}",
    "compliance_frameworks": "{{ finding.compliance_frameworks | default([]) }}",
    "created_at": "{{ finding.created_at }}"
  }
}
```

### Default Compliance Template

```json
{
  "event_type": "compliance.check_failed",
  "timestamp": "{{ timestamp }}",
  "organization": {
    "id": "{{ org_id }}",
    "name": "{{ org_name }}"
  },
  "compliance": {
    "framework": "{{ framework }}",
    "control_id": "{{ control_id }}",
    "control_title": "{{ control_title }}",
    "status": "{{ status }}",
    "severity": "{{ severity }}",
    "findings_count": "{{ findings_count }}",
    "account_id": "{{ account_id }}"
  }
}
```

### Get Default Templates

```bash
curl -X GET http://localhost:8000/api/v1/notifications/webhooks/templates \
  -H "Authorization: Bearer $TOKEN"
```

---

## Use Cases

### PagerDuty Integration

```json
{
  "name": "PagerDuty Incidents",
  "url": "https://events.pagerduty.com/v2/enqueue",
  "headers": {
    "Content-Type": "application/json"
  },
  "payload_template": {
    "routing_key": "your-integration-key",
    "event_action": "trigger",
    "payload": {
      "summary": "{{ finding.title }}",
      "severity": "{{ finding.severity }}",
      "source": "cerebro",
      "custom_details": {
        "resource_id": "{{ finding.resource_id }}",
        "provider": "{{ finding.provider }}",
        "account_id": "{{ finding.account_id }}"
      }
    }
  },
  "event_types": ["finding.created"],
  "severity_filter": ["critical", "high"]
}
```

### Datadog Events

```json
{
  "name": "Datadog Security Events",
  "url": "https://api.datadoghq.com/api/v1/events",
  "headers": {
    "Content-Type": "application/json",
    "DD-API-KEY": "your-api-key"
  },
  "payload_template": {
    "title": "{{ finding.title }}",
    "text": "Security finding detected in {{ finding.resource_id }}",
    "tags": [
      "severity:{{ finding.severity }}",
      "provider:{{ finding.provider }}",
      "cerebro:finding"
    ],
    "alert_type": "error"
  },
  "event_types": ["finding.created"]
}
```

### Microsoft Teams

```json
{
  "name": "Teams Security Channel",
  "url": "https://outlook.office.com/webhook/YOUR_WEBHOOK_URL",
  "payload_template": {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "{{ finding.title }}",
    "themeColor": "{% if finding.severity == 'critical' %}d32f2f{% elif finding.severity == 'high' %}f57c00{% else %}0277bd{% endif %}",
    "title": "🚨 Security Finding: {{ finding.severity | upper }}",
    "sections": [{
      "activityTitle": "{{ finding.title }}",
      "facts": [
        {"name": "Severity", "value": "{{ finding.severity }}"},
        {"name": "Resource", "value": "{{ finding.resource_id }}"},
        {"name": "Provider", "value": "{{ finding.provider }}"}
      ]
    }]
  },
  "event_types": ["finding.created"]
}
```

### Custom SIEM Integration

```json
{
  "name": "Internal SIEM",
  "url": "https://siem.company.internal/api/v1/events",
  "http_method": "POST",
  "headers": {
    "Authorization": "Bearer YOUR_TOKEN",
    "X-Source": "cerebro"
  },
  "payload_template": {
    "event_type": "security_finding",
    "event_id": "{{ finding.finding_id }}",
    "timestamp": "{{ timestamp }}",
    "severity": "{{ finding.severity }}",
    "source": {
      "system": "cerebro",
      "provider": "{{ finding.provider }}",
      "account": "{{ finding.account_id }}"
    },
    "finding": {
      "title": "{{ finding.title }}",
      "resource": "{{ finding.resource_id }}",
      "type": "{{ finding.resource_type }}",
      "region": "{{ finding.region }}",
      "ocsf": "{{ finding.ocsf_data | default({}) }}"
    }
  },
  "use_hmac_signature": true,
  "hmac_secret": "shared-secret-key",
  "event_types": ["finding.created", "compliance.check_failed"]
}
```

---

## API Reference

### Create Webhook Config

```bash
POST /api/v1/notifications/webhooks/configs
```

**Request Body:**
```json
{
  "name": "string",
  "url": "https://example.com/webhook",
  "http_method": "POST",
  "payload_template": {},
  "event_types": ["finding.created"]
}
```

**Response:** `201 Created`

### List Webhook Configs

```bash
GET /api/v1/notifications/webhooks/configs?enabled=true
```

### Get Webhook Config

```bash
GET /api/v1/notifications/webhooks/configs/{config_id}
```

### Update Webhook Config

```bash
PATCH /api/v1/notifications/webhooks/configs/{config_id}
```

### Delete Webhook Config

```bash
DELETE /api/v1/notifications/webhooks/configs/{config_id}
```

### Send Test Webhook

```bash
POST /api/v1/notifications/webhooks/test/{config_id}
```

### List Webhook Notifications

```bash
GET /api/v1/notifications/webhooks/notifications?status=sent&limit=100
```

**Query Parameters:**
- `config_id` - Filter by config ID
- `status` - Filter by status: `sent`, `failed`, `retrying`
- `limit` - Max results (default: 100)
- `offset` - Pagination offset

### Get Webhook Statistics

```bash
GET /api/v1/notifications/webhooks/notifications/stats?config_id={config_id}
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

## Jinja2 Template Guide

### Available Variables

#### Finding Events
- `timestamp` - Current timestamp (ISO 8601)
- `org_id` - Organization UUID
- `org_name` - Organization name
- `finding` - Finding object with all fields

#### Compliance Events
- `timestamp` - Current timestamp
- `org_id` - Organization UUID
- `org_name` - Organization name
- `framework` - Compliance framework (SOC2, CIS, etc.)
- `control_id` - Control identifier
- `control_title` - Control title
- `status` - Control status
- `severity` - Alert severity
- `findings_count` - Number of findings
- `account_id` - Account ID

#### Monitoring Events
- `timestamp` - Current timestamp
- `org_id` - Organization UUID
- `org_name` - Organization name
- `alert_title` - Alert title
- `alert_description` - Alert description
- `severity` - Alert severity
- `finding_id` - Related finding ID (if any)
- `metadata` - Additional metadata

### Template Filters

```jinja2
{{ finding.severity | upper }}  # Convert to uppercase: "CRITICAL"
{{ finding.compliance_frameworks | default([]) }}  # Default value if null
{{ finding.ocsf_data | default({}) }}  # Default empty object
```

### Conditional Logic

```jinja2
{
  "color": "{% if finding.severity == 'critical' %}#d32f2f{% elif finding.severity == 'high' %}#f57c00{% else %}#0277bd{% endif %}"
}
```

### Nested Objects

```jinja2
{
  "finding": {
    "id": "{{ finding.finding_id }}",
    "severity": "{{ finding.severity }}",
    "resource": {
      "id": "{{ finding.resource_id }}",
      "type": "{{ finding.resource_type }}",
      "provider": "{{ finding.provider }}"
    }
  }
}
```

---

## Security

### HMAC Signature Verification

When `use_hmac_signature` is enabled, Cerebro adds the `X-Webhook-Signature` header:

```
X-Webhook-Signature: sha256=abc123...
```

**Verification (Python):**
```python
import hmac
import hashlib

def verify_webhook(payload_str, signature_header, secret):
    expected = hmac.new(
        secret.encode('utf-8'),
        payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    received = signature_header.replace('sha256=', '')
    return hmac.compare_digest(expected, received)
```

**Verification (Node.js):**
```javascript
const crypto = require('crypto');

function verifyWebhook(payloadStr, signatureHeader, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payloadStr)
    .digest('hex');

  const received = signatureHeader.replace('sha256=', '');
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(received)
  );
}
```

**Verification (Go):**
```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func verifyWebhook(payload []byte, signature, secret string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    expected := hex.EncodeToString(mac.Sum(nil))

    received := strings.TrimPrefix(signature, "sha256=")
    return hmac.Equal([]byte(expected), []byte(received))
}
```

---

## Troubleshooting

### Webhook Delivery Failed

```sql
-- Check failed webhooks
SELECT
    notification_id,
    config_id,
    event_type,
    status,
    error_message,
    retry_count,
    response_status,
    created_at
FROM webhook_notifications
WHERE status = 'failed'
ORDER BY created_at DESC
LIMIT 10;
```

### Common Issues

**Connection Timeout**
- Increase `timeout_seconds` in config
- Check firewall rules
- Verify endpoint is reachable

**Authentication Failed**
- Verify API keys in headers
- Check Bearer token expiration
- Review authentication config

**HMAC Verification Failed (Receiver)**
- Ensure using raw request body (not parsed JSON)
- Check secret key matches
- Verify signature format: `sha256=<hex>`

**High Retry Count**
```bash
# Check for persistent failures
curl http://localhost:8000/api/v1/notifications/webhooks/notifications?status=failed \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.retry_count > 2)'
```

### Debugging Tips

1. **Test with webhook.site**
   ```json
   {
     "url": "https://webhook.site/YOUR-UNIQUE-URL",
     "http_method": "POST",
     "payload_template": {"test": "{{ timestamp }}"}
   }
   ```

2. **Check response body**
   ```sql
   SELECT response_status, response_body
   FROM webhook_notifications
   WHERE notification_id = 'YOUR_ID';
   ```

3. **Verify template rendering**
   ```bash
   # Send test webhook to see rendered payload
   curl -X POST /api/v1/notifications/webhooks/test/{config_id} \
     -H "Authorization: Bearer $TOKEN" | jq '.payload'
   ```

---

## Best Practices

### Security

- 🔒 **Always use HMAC** - Enable signature verification
- 🔒 **Use HTTPS** - Never send to HTTP endpoints
- 🔒 **Rotate secrets** - Change HMAC secrets regularly
- 🔒 **Store securely** - Use environment variables for secrets

### Reliability

- 📊 **Monitor statistics** - Check success rates regularly
- 📊 **Set appropriate timeouts** - Balance between reliability and speed
- 📊 **Use severity filters** - Reduce webhook volume
- 📊 **Test regularly** - Verify configs after changes

### Performance

- ⚡ **Keep payloads small** - Only include necessary data
- ⚡ **Use async processing** - Don't block on webhook delivery
- ⚡ **Monitor retry counts** - Investigate persistent failures
- ⚡ **Set up alerts** - Alert on delivery failures

---

## Integration Examples

### Python (Receiver)

```python
from flask import Flask, request, jsonify
import hmac
import hashlib
import json

app = Flask(__name__)
SECRET = "your-secret-key"

@app.route('/api/security/alerts', methods=['POST'])
def handle_webhook():
    # Verify HMAC signature
    payload_str = request.get_data(as_text=True)
    signature = request.headers.get('X-Webhook-Signature', '')

    if not verify_signature(payload_str, signature):
        return jsonify({"error": "Invalid signature"}), 401

    # Process webhook
    payload = json.loads(payload_str)
    print(f"Received finding: {payload['finding']['title']}")

    # Return success
    return jsonify({"status": "received"}), 200

def verify_signature(payload, signature):
    expected = hmac.new(
        SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    received = signature.replace('sha256=', '')
    return hmac.compare_digest(expected, received)

if __name__ == '__main__':
    app.run(port=5000)
```

### Node.js (Receiver)

```javascript
const express = require('express');
const crypto = require('crypto');

const app = express();
const SECRET = 'your-secret-key';

app.use(express.text({ type: 'application/json' }));

app.post('/api/security/alerts', (req, res) => {
  // Verify HMAC signature
  const signature = req.headers['x-webhook-signature'] || '';

  if (!verifySignature(req.body, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Process webhook
  const payload = JSON.parse(req.body);
  console.log(`Received finding: ${payload.finding.title}`);

  // Return success
  res.json({ status: 'received' });
});

function verifySignature(payload, signature) {
  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(payload)
    .digest('hex');

  const received = signature.replace('sha256=', '');

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(received)
  );
}

app.listen(5000, () => {
  console.log('Webhook receiver listening on port 5000');
});
```

---

## Next Steps

- [Email Notifications](../email/SETUP.md) - Send via email
- [Slack Integration](../slack/SETUP.md) - Real-time Slack notifications
- [API Reference](/docs/user-guide/API.md) - Complete API documentation

---

**Need Help?** Check [Troubleshooting Guide](/docs/user-guide/TROUBLESHOOTING.md) or open an issue on [GitHub](https://github.com/WriterInternal/cerebro/issues)