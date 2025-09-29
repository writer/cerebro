# Cerebro SDK Design Document

## Vision: Developer Experience Multiplier

Instead of "works on my machine" - create SDKs that make Cerebro integration effortless for any developer.

## 🎯 Target Developer Experience

### Python SDK
```python
from cerebro import Cerebro

# Initialize with automatic configuration discovery
client = Cerebro.from_env()

# Simple, intuitive API
findings = client.findings.list(severity='critical', provider='aws')
for finding in findings:
    if finding.can_auto_remediate:
        finding.remediate()
        print(f"✅ Fixed: {finding.title}")

# Temporal queries made simple
results = client.investigate.who_had_access(
    resource='prod-database',
    when='2024-03-15 14:30:00'
)

# Real-time monitoring
@client.on('new_finding')
def handle_finding(finding):
    if finding.severity == 'critical':
        slack.send(f"🚨 Critical: {finding.title}")
```

### TypeScript SDK
```typescript
import { Cerebro } from '@cerebro/sdk';

const cerebro = new Cerebro({
  apiKey: process.env.CEREBRO_API_KEY,
  baseUrl: 'https://api.cerebro.com'
});

// Type-safe operations
const findings = await cerebro.findings.list({
  severity: 'critical',
  provider: 'aws'
});

// Real-time subscriptions
cerebro.subscribe('findings', {
  onNew: (finding) => console.log('New finding:', finding),
  onResolved: (finding) => console.log('Resolved:', finding)
});

// Compliance automation
const report = await cerebro.compliance.generateReport({
  framework: 'soc2',
  format: 'pdf'
});
```

### CLI Tool
```bash
# Intuitive commands
cerebro scan aws --org production
cerebro findings list --critical --provider aws
cerebro investigate "who had S3 admin access last week?"
cerebro vendor risk-assess --name "DataDog" --framework soc2
cerebro compliance report --soc2 --output compliance-report.pdf

# Pipeline integration
cerebro findings export --json | jq '.[] | select(.severity=="critical")'
```

## 🔧 Implementation Plan

### Phase 1: Python SDK Core
```python
# File: cerebro-sdk-python/cerebro/__init__.py
class Cerebro:
    def __init__(self, api_key=None, base_url=None):
        self.client = APIClient(api_key, base_url)
        self.findings = FindingsAPI(self.client)
        self.compliance = ComplianceAPI(self.client)
        self.investigate = InvestigationAPI(self.client)
        
    @classmethod
    def from_env(cls):
        return cls(
            api_key=os.getenv('CEREBRO_API_KEY'),
            base_url=os.getenv('CEREBRO_BASE_URL', 'https://api.cerebro.com')
        )
```

### Phase 2: TypeScript SDK
```typescript
// File: cerebro-sdk-ts/src/index.ts
export class Cerebro {
  private client: APIClient;
  
  public findings: FindingsAPI;
  public compliance: ComplianceAPI;
  public investigate: InvestigationAPI;
  
  constructor(config: CerebroConfig) {
    this.client = new APIClient(config);
    this.findings = new FindingsAPI(this.client);
    // ...
  }
}
```

### Phase 3: CLI Tool
```python
# File: cerebro-cli/cerebro_cli/main.py
import click
from cerebro import Cerebro

@click.group()
def cli():
    """Cerebro Security Platform CLI"""
    pass

@cli.command()
@click.option('--provider', help='Provider to scan')
@click.option('--org', help='Organization name')
def scan(provider, org):
    """Scan infrastructure for security issues"""
    client = Cerebro.from_env()
    results = client.scan(provider=provider, org=org)
    click.echo(f"Found {len(results.findings)} security issues")
```

## 📚 Documentation Structure

### Interactive Documentation
```bash
# Auto-generated from OpenAPI spec
docs/
├── api/              # API reference with examples
├── sdks/             # SDK documentation
├── tutorials/        # Step-by-step guides
├── examples/         # Real-world use cases
└── reference/        # Complete reference
```

### Code Examples Repository
```bash
examples/
├── python/
│   ├── basic-monitoring.py
│   ├── compliance-automation.py
│   └── custom-rules.py
├── typescript/
│   ├── next-js-integration/
│   ├── react-dashboard/
│   └── webhook-handler/
├── cli/
│   ├── ci-cd-integration.sh
│   ├── scheduled-scans.sh
│   └── report-automation.sh
└── integrations/
    ├── slack-notifications/
    ├── jira-ticketing/
    └── pagerduty-alerts/
```

## 🎯 Developer Onboarding Flow

### 1. One-Command Setup
```bash
curl -sSL https://get.cerebro.com/install.sh | bash
cerebro init my-security-project
cd my-security-project
cerebro dev start
```

### 2. Guided Configuration
```bash
cerebro configure
# Interactive wizard:
# ✓ AWS credentials
# ✓ GitHub token  
# ✓ Okta domain
# ✓ Compliance frameworks
```

### 3. Immediate Value
```bash
cerebro scan --all-providers
cerebro dashboard --open
# Browser opens with populated security dashboard
```

## 📈 Success Metrics

### Developer Adoption
- **Time to First Value**: < 5 minutes from install to dashboard
- **API Discovery**: Interactive docs with try-it-now buttons
- **Error Messages**: Actionable with clear next steps
- **Examples**: Copy-pasteable for common use cases

### Platform Adoption  
- **SDK Downloads**: Track weekly active developers
- **Documentation Views**: Most popular integration patterns
- **Community Contributions**: Issues, PRs, feature requests
- **Integration Ecosystem**: Third-party tools and plugins

## 🔄 Feedback Loop

### Automated Metrics
```python
# Track SDK usage patterns
client.track_usage('findings.list', {'filters': filters})
client.track_error('authentication_failed', {'context': context})
```

### Developer Surveys
- Quarterly NPS surveys for SDK users
- Specific pain point identification
- Feature request prioritization
- Competitive analysis vs other security platforms

This transforms Cerebro from a technical platform into a **developer-friendly ecosystem** that scales beyond individual hero engineers.
