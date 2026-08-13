# Security operator benchmark

This benchmark measures the work Cerebro must complete before an Infosec
operator can act on a known risky condition:

1. Put the expected finding in the active-risk queue with severity, risk
   rationale, evidence, affected resources, and an accountable owner.
2. Return the exposure-to-privilege path with source provenance on each
   material edge.
3. Find the affected asset in inventory.
4. Return the asset investigation context with findings, evidence, and
   remediation actions.

The baseline and candidate must contain the same sanitized snapshot. Update a
private copy of `security-operator.json` with the expected finding rule and
resource URN. Do not commit tenant identifiers or environment data.

Run the comparison from the same host and network path:

```sh
SECURITY_BENCHMARK_BASELINE_URL=https://baseline.example \
SECURITY_BENCHMARK_CANDIDATE_URL=https://candidate.example \
SECURITY_BENCHMARK_SCENARIO=tmp/security-operator-scenario.json \
CEREBRO_BENCHMARK_BEARER_TOKEN="$TOKEN" \
make security-operator-benchmark
```

The JSON and Markdown receipts report:

- security-question coverage and actionable-investigation uplift;
- retention and semantic parity for every answer the baseline could provide;
- complete analyst-journey p50, p95, p99, and mean latency;
- p95 latency for risk inbox, attack path, asset lookup, and investigation
  context questions;
- successful and actionable answer rates;
- p95 time returned per investigation and projected operator minutes returned
  per day when both releases answer the same questions;
- explicit failures for lost baseline answers, changed security conclusions,
  incomplete candidate answers, or comparable latency regression.

When the candidate answers security questions that the baseline cannot, the
receipt marks end-to-end latency as not comparable. A fast error is not an
operator productivity improvement.

This is a decision-readiness benchmark. It does not claim source-event to
finding latency because the read-only harness does not inject provider events.
Measure detection latency separately with a controlled source fixture whose
event creation time and expected finding identity are both known.
