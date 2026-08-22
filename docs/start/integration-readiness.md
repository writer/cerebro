# Integration Readiness

Cerebro separates catalog coverage from configured collection. A source name in the catalog is not proof that your tenant is collecting or projecting its records.

## Read The Current State

| State | What exists | What it proves | Next action |
| --- | --- | --- | --- |
| Catalog only | A source definition describes configuration and possible record families. | The source is discoverable and its contract can be inspected. | Review required configuration and supported records. |
| Preview available | The source can perform a bounded read without durable stores. | Current provider-shaped data can be validated without persistence. | Configure a read-only provider identity and run a preview. |
| Runtime configured | A tenant-scoped runtime and credential reference exist. | Cerebro can attempt scheduled collection for that tenant. | Run a bounded sync and inspect typed failures. |
| Collecting | A current sync receipt, checkpoint, and accepted records exist. | The runtime is receiving and admitting provider records. | Confirm restart behavior and zero unexplained rejects. |
| Product ready | Accepted records are projected and readable in the applicable product workflow. | A user can use the collected data in controls, evidence, risk, or graph workflows. | Monitor freshness, coverage gaps, and contract drift. |

## Check A Source

1. Open **Integrations** and select the source.
2. Read the required access, supported record families, and known coverage gaps.
3. Confirm the tenant runtime state and last successful sync.
4. Treat missing configuration, permission failure, stale data, and unsupported coverage as different operator actions.
5. Do not promote a source to product-ready based on catalog count, fixture output, or a successful connection test alone.

The generated [source catalog](../reference/sources.md) lists source definitions and required configuration. The application shows tenant-specific runtime health only when the API returns current receipts and coverage records.
