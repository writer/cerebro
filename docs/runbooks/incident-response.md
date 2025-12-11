# Cerebro Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to incidents affecting the Cerebro security platform. Follow these procedures to minimize impact and restore service.

## Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **SEV1** | Complete service outage | 15 min | API down, data loss, security breach |
| **SEV2** | Major degradation | 30 min | >50% error rate, agent failures, auth issues |
| **SEV3** | Minor degradation | 2 hours | Slow queries, partial feature failures |
| **SEV4** | Low impact | 24 hours | UI glitches, non-critical feature issues |

## On-Call Contacts

| Role | Primary | Backup |
|------|---------|--------|
| Platform Engineer | @platform-oncall | @platform-backup |
| Security Engineer | @security-oncall | @security-backup |
| Engineering Manager | @eng-manager | @eng-director |

## Initial Response (All Incidents)

### 1. Acknowledge & Assess (5 min)

```bash
# Check service health
curl -s https://cerebro.writer.com/health | jq

# Check Kubernetes pod status
kubectl -n cerebro-production get pods

# Check recent deployments
kubectl -n cerebro-production rollout history deployment/cerebro-api
```

### 2. Create Incident Channel

- Create Slack channel: `#inc-cerebro-YYYYMMDD-brief-description`
- Post initial assessment with severity level
- Tag relevant on-call personnel

### 3. Communication Template

```
🚨 INCIDENT: [Brief Description]
Severity: SEV[1-4]
Status: Investigating / Identified / Monitoring / Resolved
Impact: [User-facing impact description]
Start Time: [UTC timestamp]
Current Actions: [What's being done]
Next Update: [Time]
```

---

## Common Incident Scenarios

### Scenario 1: API Unresponsive (SEV1)

**Symptoms:**
- Health endpoint returns 5xx or timeout
- Alerts: `CerebroAPIDown`, `HighErrorRate`

**Diagnosis:**

```bash
# Check API pods
kubectl -n cerebro-production get pods -l app.kubernetes.io/component=api

# Check pod logs
kubectl -n cerebro-production logs -l app.kubernetes.io/component=api --tail=100

# Check resource usage
kubectl -n cerebro-production top pods

# Check recent events
kubectl -n cerebro-production get events --sort-by='.lastTimestamp' | tail -20
```

**Resolution Steps:**

1. **Quick Mitigation - Restart pods:**
   ```bash
   kubectl -n cerebro-production rollout restart deployment/cerebro-api
   ```

2. **If OOM/Resource issues:**
   ```bash
   # Scale up temporarily
   kubectl -n cerebro-production scale deployment/cerebro-api --replicas=6
   ```

3. **If bad deployment - Rollback:**
   ```bash
   kubectl -n cerebro-production rollout undo deployment/cerebro-api
   ```

4. **If database connection issues:**
   - Check DynamoDB service health in AWS console
   - Verify IAM role permissions
   - Check connection pool exhaustion in logs

---

### Scenario 2: High Error Rate (SEV2)

**Symptoms:**
- Error rate >5% on API endpoints
- Alerts: `HighErrorRate`, `LatencySpike`

**Diagnosis:**

```bash
# Check error patterns in logs
kubectl -n cerebro-production logs -l app.kubernetes.io/component=api --tail=500 | grep -i error | head -50

# Check Prometheus metrics
# Access Grafana dashboard: https://grafana.internal/d/cerebro-api

# Check recent changes
git log --oneline -10
```

**Resolution Steps:**

1. Identify error pattern (5xx vs 4xx, specific endpoint)
2. Check if correlated with deployment or config change
3. If new code issue:
   ```bash
   kubectl -n cerebro-production rollout undo deployment/cerebro-api
   ```
4. If external dependency issue:
   - Enable circuit breaker / fallback mode
   - Contact vendor if third-party service

---

### Scenario 3: Celery Worker Failures (SEV2)

**Symptoms:**
- Tasks stuck in queue
- Alerts: `CeleryWorkerDown`, `TaskQueueBacklog`

**Diagnosis:**

```bash
# Check worker pods
kubectl -n cerebro-production get pods -l app.kubernetes.io/component=worker

# Check worker logs
kubectl -n cerebro-production logs -l app.kubernetes.io/component=worker --tail=100

# Check Redis queue depth
kubectl -n cerebro-production exec -it deploy/cerebro-api -- \
  python -c "import redis; r=redis.from_url('$REDIS_URL'); print(r.llen('celery'))"

# Check Flower dashboard
# https://flower.internal.cerebro/
```

**Resolution Steps:**

1. **Restart workers:**
   ```bash
   kubectl -n cerebro-production rollout restart deployment/cerebro-worker
   ```

2. **Scale workers for backlog:**
   ```bash
   kubectl -n cerebro-production scale deployment/cerebro-worker --replicas=10
   ```

3. **Clear stuck tasks (last resort):**
   ```bash
   kubectl -n cerebro-production exec -it deploy/cerebro-api -- \
     celery -A cerebro.tasks.celery_app purge
   ```

---

### Scenario 4: Agent Runtime Failures (SEV2)

**Symptoms:**
- Agent sessions failing to start or respond
- High latency on agent endpoints
- Alerts: `AgentSessionFailures`

**Diagnosis:**

```bash
# Check agent-specific logs
kubectl -n cerebro-production logs -l app.kubernetes.io/component=api --tail=200 | grep -i agent

# Check Anthropic/OpenAI API status
curl -s https://status.anthropic.com/api/v2/status.json | jq
curl -s https://status.openai.com/api/v2/status.json | jq

# Check rate limits
kubectl -n cerebro-production logs -l app.kubernetes.io/component=api | grep -i "rate limit"
```

**Resolution Steps:**

1. If provider issue - enable fallback provider:
   ```bash
   kubectl -n cerebro-production set env deployment/cerebro-api AGENT_FALLBACK_ENABLED=true
   ```

2. If rate limited - reduce concurrency:
   ```bash
   kubectl -n cerebro-production set env deployment/cerebro-api AGENT_MAX_CONCURRENT=5
   ```

3. If memory pressure in agent sessions - restart with increased limits

---

### Scenario 5: Data Integrity / Security Incident (SEV1)

**Symptoms:**
- Unexpected data modifications
- Unauthorized access attempts
- Alerts: `SecurityAnomaly`, `UnauthorizedAccess`

**CRITICAL: Do NOT delete logs or evidence**

**Immediate Actions:**

1. **Isolate affected systems:**
   ```bash
   # Scale down to prevent further damage
   kubectl -n cerebro-production scale deployment/cerebro-api --replicas=0
   ```

2. **Preserve evidence:**
   ```bash
   # Export logs
   kubectl -n cerebro-production logs -l app.kubernetes.io/name=cerebro --all-containers > /tmp/incident-logs-$(date +%s).txt
   
   # Export audit events
   kubectl -n cerebro-production exec deploy/cerebro-api -- \
     python -c "from cerebro.auditability import export_recent; export_recent()" > /tmp/audit-$(date +%s).json
   ```

3. **Notify Security Team immediately**
4. **Do NOT discuss in public channels**
5. **Follow Writer Security Incident Process**

---

## Post-Incident

### Immediate (within 24 hours)

- [ ] Service restored and stable
- [ ] Temporary mitigations documented
- [ ] Stakeholders notified of resolution

### Follow-up (within 72 hours)

- [ ] Incident timeline documented
- [ ] Root cause identified
- [ ] Post-incident review scheduled
- [ ] Action items created for prevention

### Post-Incident Review Template

```markdown
## Incident Review: [Title]

**Date:** YYYY-MM-DD
**Duration:** X hours Y minutes
**Severity:** SEV[1-4]
**Responders:** @names

### Summary
[2-3 sentence summary]

### Timeline
- HH:MM - Event
- HH:MM - Action taken
- HH:MM - Resolution

### Root Cause
[Technical explanation]

### Impact
- Users affected: X
- Data affected: None / [description]
- Revenue impact: $X / None

### What Went Well
- 

### What Could Be Improved
- 

### Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
|        |       |          |        |
```

---

## Useful Commands Reference

```bash
# Get all Cerebro resources
kubectl -n cerebro-production get all

# Describe problematic pod
kubectl -n cerebro-production describe pod <pod-name>

# Execute into pod for debugging
kubectl -n cerebro-production exec -it deploy/cerebro-api -- /bin/bash

# Check HPA status
kubectl -n cerebro-production get hpa

# Check PDB status
kubectl -n cerebro-production get pdb

# Force delete stuck pod
kubectl -n cerebro-production delete pod <pod-name> --grace-period=0 --force

# Check node issues
kubectl get nodes
kubectl describe node <node-name>
```

## Escalation Matrix

| Condition | Escalate To |
|-----------|-------------|
| SEV1 not resolved in 30 min | Engineering Manager |
| SEV1 not resolved in 1 hour | Engineering Director |
| Data breach suspected | CISO + Legal |
| Customer-facing for >1 hour | Customer Success + Comms |
