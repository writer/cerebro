##OCSF Integration

**Open Cybersecurity Schema Framework Support**

Cerebro implements OCSF v1.4.0 for standardized security event formatting and interoperability with SIEM platforms, data lakes, and security analytics tools.

---

## Overview

OCSF (Open Cybersecurity Schema Framework) is an open standard for cybersecurity event data that enables:
- **Interoperability** with AWS Security Lake, Splunk, Snowflake, and other OCSF consumers
- **Standardization** of security event formats across tools and vendors
- **Analytics** with normalized schema for cross-platform queries

**Cerebro OCSF Support:**
- OCSF Version: **1.4.0+**
- Schema: https://schema.ocsf.io/
- Categories: Findings (2), Identity & Access Management (3)
- Classes: Security Finding (2001), Compliance Finding (2003)

---

## Supported Mappings

### Cerebro → OCSF Findings

| Cerebro Concept | OCSF Mapping |
|----------------|--------------|
| Finding | OCSF Security Finding (Class 2001) |
| Compliance Test Result | OCSF Compliance Finding (Class 2003) |
| Severity (critical/high/medium/low) | OCSF Severity (5/4/3/2) |
| Finding Status (open/fixed) | OCSF Activity (Create/Close) |
| Resources | OCSF Resource objects |
| Principals/Identities | OCSF Actor/User objects |
| Cloud Account | OCSF Cloud object |
| Compliance Frameworks | OCSF Compliance requirements |

### Example Transformation

**Cerebro Finding:**
```json
{
  "id": "f123",
  "title": "S3 Bucket Publicly Accessible",
  "severity": "high",
  "status": "open",
  "resource_id": "arn:aws:s3:::mybucket",
  "compliance_frameworks": ["CIS AWS 2.1.1"]
}
```

**OCSF Security Finding:**
```json
{
  "class_uid": 2001,
  "class_name": "Security Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "type_uid": 200201,
  "severity_id": 4,
  "severity": "High",
  "activity_id": 1,
  "activity_name": "Create",
  "finding_info": {
    "title": "S3 Bucket Publicly Accessible",
    "uid": "f123",
    "types": ["Misconfiguration"]
  },
  "resources": [{
    "uid": "arn:aws:s3:::mybucket",
    "type": "AWS::S3::Bucket"
  }],
  "compliance": {
    "requirements": ["CIS AWS 2.1.1"],
    "status": "Fail"
  },
  "metadata": {
    "version": "1.4.0",
    "product": {
      "name": "Cerebro",
      "vendor_name": "Cerebro Security"
    }
  }
}
```

---

## Usage

### Python API

```python
from cerebro.ocsf import OCSFMapper, OCSFExporter, OCSFFormat

# Initialize mapper
mapper = OCSFMapper()

# Convert Cerebro finding to OCSF
ocsf_finding = await mapper.finding_to_ocsf(
    finding=cerebro_finding,
    resources=related_resources,
    account=cloud_account,
)

# Export to various formats
exporter = OCSFExporter()

# JSON
exporter.export_to_file(
    events=ocsf_finding,
    output_path=Path("findings.json"),
    format=OCSFFormat.JSON,
)

# JSONL (newline-delimited, ideal for streaming)
exporter.export_to_file(
    events=ocsf_finding,
    output_path=Path("findings.jsonl"),
    format=OCSFFormat.JSONL,
    append=True,  # Append mode for continuous export
)

# Parquet (for AWS Security Lake)
exporter.export_to_file(
    events=ocsf_finding,
    output_path=Path("findings.parquet"),
    format=OCSFFormat.PARQUET,
)

# CSV (flattened for spreadsheet analysis)
exporter.export_to_file(
    events=ocsf_finding,
    output_path=Path("findings.csv"),
    format=OCSFFormat.CSV,
)
```

### Batch Export

```python
from cerebro.ocsf import OCSFBatchExporter

# Streaming export with batching
with OCSFBatchExporter(
    output_path=Path("findings.jsonl"),
    format=OCSFFormat.JSONL,
    batch_size=100,
) as exporter:
    for finding in findings:
        ocsf_event = await mapper.finding_to_ocsf(finding)
        exporter.add(ocsf_event)
    # Automatically flushes on exit
```

### CLI

```bash
# Export all findings to OCSF JSON
cerebro findings export --format ocsf --output findings.json

# Export with filters
cerebro findings export --format ocsf \
    --severity critical,high \
    --status open \
    --output critical_findings.jsonl

# Continuous export (watch mode)
cerebro findings export --format ocsf \
    --output findings.jsonl \
    --watch \
    --append

# Export compliance test results
cerebro compliance export --format ocsf \
    --framework soc2 \
    --output soc2_compliance.json
```

### REST API

```bash
# Export findings as OCSF
curl "http://localhost:8000/api/v1/findings/export/ocsf?severity=critical"

# Stream OCSF events (Server-Sent Events)
curl "http://localhost:8000/api/v1/events/ocsf/stream"
```

---

## Integration with Security Platforms

### AWS Security Lake

AWS Security Lake natively supports OCSF format. Export Cerebro findings to Parquet and upload to Security Lake S3 bucket:

```python
# Export to Parquet
exporter.export_to_file(
    events=findings,
    output_path=Path("cerebro_findings.parquet"),
    format=OCSFFormat.PARQUET,
)

# Upload to Security Lake S3
# aws s3 cp cerebro_findings.parquet s3://your-security-lake-bucket/cerebro/
```

**Security Lake Configuration:**
- Source: Custom Source (Cerebro)
- Format: OCSF Parquet
- Category: Findings (Category 2)
- Classes: Security Finding (2001), Compliance Finding (2003)

### Splunk

Splunk supports OCSF via Universal Forwarder or HEC (HTTP Event Collector):

```bash
# Export to JSONL
cerebro findings export --format ocsf --output /var/log/cerebro/findings.jsonl

# Configure Splunk Universal Forwarder
[monitor:///var/log/cerebro/findings.jsonl]
sourcetype = ocsf:security_finding
index = security
```

**Splunk OCSF App:**
- Install OCSF App for Splunk
- Configure data inputs to use `sourcetype = ocsf:security_finding`
- Pre-built dashboards and searches for OCSF data

### Snowflake

Load OCSF events into Snowflake for analytics:

```sql
-- Create OCSF findings table
CREATE TABLE ocsf_findings (
    event VARIANT  -- JSON column
);

-- Load from S3
COPY INTO ocsf_findings
FROM 's3://your-bucket/cerebro_findings.jsonl'
FILE_FORMAT = (TYPE = 'JSON');

-- Query OCSF data
SELECT
    event:finding_info:title::STRING as finding_title,
    event:severity::STRING as severity,
    event:time::TIMESTAMP as event_time
FROM ocsf_findings
WHERE event:severity_id >= 4  -- High or Critical
```

### Custom SIEM

For custom SIEM integration, use JSONL format for streaming:

```python
# Continuous export to file
with OCSFBatchExporter(
    output_path=Path("/var/log/cerebro/ocsf.jsonl"),
    format=OCSFFormat.JSONL,
    batch_size=100,
) as exporter:
    # Your SIEM can tail this file
    async for finding in findings_stream():
        ocsf_event = await mapper.finding_to_ocsf(finding)
        exporter.add(ocsf_event)
```

---

## OCSF Schema Details

### Profiles Used

Cerebro applies OCSF profiles based on context:
- **Cloud** - For AWS/Azure/GCP findings
- **Container** - For container security findings
- **Host** - For host/instance findings
- **Security Control** - For compliance findings

### Observables

Cerebro extracts observables (IoCs) from findings:
- **Resource UIDs** - ARNs, resource IDs
- **User Identities** - Principal IDs, user names
- **IP Addresses** - (if available in metadata)
- **File Hashes** - (if available for vulnerable packages)

### Unmapped Fields

Original Cerebro metadata is preserved in `unmapped` field:
```json
{
  "unmapped": {
    "cerebro_metadata": {
      "rule_id": "r123",
      "documentation": "https://docs.cerebro.com/..."
    }
  }
}
```

---

## Performance Considerations

### Batch Size
- JSONL append: Fast, optimal for streaming
- JSON array: Good for < 10K events
- Parquet: Best for > 100K events

### Export Frequency
- **Real-time**: Use JSONL append mode with batch size 100
- **Hourly**: Use JSON or Parquet
- **Daily**: Use Parquet for large volumes

### Compression
- **JSONL**: Use gzip (`findings.jsonl.gz`)
- **Parquet**: Snappy compression (default)

---

## Compliance Mapping

OCSF compliance findings map Cerebro control tests to framework requirements:

```python
ocsf_compliance = await mapper.compliance_result_to_ocsf(
    control_id="SOC2-CC6.1",
    control_title="Logical Access Controls",
    status="fail",  # or "pass"
    framework="SOC2",
    evidence={
        "test_date": "2025-09-29",
        "findings_count": 5,
    },
)
```

**OCSF Compliance Object:**
```json
{
  "compliance": {
    "requirements": ["SOC2 CC6.1"],
    "status": "Fail",
    "status_detail": "Logical Access Controls"
  }
}
```

---

## Roadmap

### Planned Features

**Additional Event Classes:**
- IAM Activity (Class 3001) - Authentication events
- Entity Management Activity (Class 3004) - User/group changes
- Network Activity (Category 4) - Connection logs

**Enhanced Observables:**
- File hashes for vulnerable packages
- Network indicators (IPs, domains)
- Process information

**Real-time Streaming:**
- WebSocket streaming of OCSF events
- Direct integration with AWS Kinesis
- Kafka producer for OCSF events

**Enrichment:**
- Threat intelligence enrichment
- Geolocation data for IPs
- CVE/CWE details for vulnerabilities

---

## References

- **OCSF Schema:** https://schema.ocsf.io/
- **OCSF GitHub:** https://github.com/ocsf
- **OCSF Specification:** https://github.com/ocsf/ocsf-docs
- **AWS Security Lake:** https://docs.aws.amazon.com/security-lake/
- **Splunk OCSF App:** https://splunkbase.splunk.com/

---

## Support

For OCSF-related issues or questions:
- File issues at https://github.com/WriterInternal/cerebro/issues
- Tag with `ocsf` label
- Include OCSF version and target platform (AWS Security Lake, Splunk, etc.)

---

**Built for enterprises that need standards-based security data.**