# Policy Candidate Control Loop

Cerebro stores policy discoveries as tenant-scoped drafts before they become repository changes. A candidate records a redacted hypothesis, a private origin reference, typed graph evidence, authored policy and test artifacts, proof receipts, and a bounded current-state shadow receipt.

The HTTP surface is intentionally small:

- `POST /policy-candidates` creates one grounded draft after Cerebro rehydrates every declared node, edge, relation, source, and risk-relevant attribute from the current tenant graph and confirms that no registered graph rule already covers the risky subpath.
- `GET /policy-candidates` lists safe summaries for one tenant.
- `GET /policy-candidates/{candidateID}` reads one safe summary.
- `POST /policy-candidates/{candidateID}/prove` revalidates current catalog coverage, authors exactly one rule and its paired tests, then runs the existing proof boundary.
- `POST /policy-candidates/{candidateID}/shadow` revalidates current catalog coverage and executes the proved rule as a bounded, read-only current-graph query.

The persisted lifecycle is `grounded -> proved -> ready_for_review`. Grounded evidence must contain at least three distinct nodes and a directed path of at least two connected hops that includes the declared critical edge. A failed dependency or validation leaves the last successful state intact. Optimistic revisions prevent concurrent proof or shadow requests from overwriting each other. Every successful revision appends an immutable Postgres transition record in the same transaction as the current-state update. Shadow execution keeps the candidate at `proved` with `pr_ready=false` when the current rule returns no matches or exceeds the bounded result limit.

Policy authoring uses the configured Graph Agent LLM provider. Bedrock and OpenRouter expose an optional schema-bound structured-JSON capability through the same model selection, credential, temperature, and telemetry configuration used by graph reasoning. Structured policy output uses the configured token limit with a 4,096-token floor so a complete `PolicyFindingRule` object is not silently truncated by the graph-question default. When the Graph Agent LLM is not configured, candidate creation and reads remain available while proof fails closed as unavailable.

`ready_for_review` means current catalog coverage was revalidated, proof completed, and current-state shadow execution completed. It does not mean approved, promoted, or merged. Cerebro does not create findings, write to the graph, change repository files, call GitHub, or promote candidate rules through this API.

## Data boundaries

- The create request rejects obvious AWS ARNs, account IDs, endpoints, and email addresses in the hypothesis.
- Graph node IDs are request-local handles. The authoring model receives newly assigned local references instead of those handles.
- Creation requires an ephemeral binding from every local handle to a tenant-scoped Cerebro entity URN. Cerebro executes server-authored, tenant-scoped read queries to verify the topology and attributes. The bindings and returned graph rows are not exposed to the model or public candidate view.
- Cerebro compares directed typed edge and risk-predicate signatures from registered graph rules against the grounded candidate. Registered requirements are matched as a subpath, so extra candidate context cannot bypass duplicate detection. Rules whose `EvaluateRows` semantics are not completely registered fail closed when their graph entity scope overlaps the candidate.
- The persisted coverage-gap receipt contains only a catalog digest, compared-rule count, candidate-signature digest, execution kind, and observation time. It does not expose rule identifiers or query text.
- The private origin reference and raw graph evidence are stored for provenance but omitted from API responses and model context.
- List and read responses expose only graph counts, entity types, relations, artifacts, and proof receipts.
- Shadow execution returns a random receipt ID and a bounded count. It does not return graph rows or hash raw provider identifiers. Review readiness requires at least one current match and an untruncated result.

The policy-candidate API is an application surface. It remains outside the `/platform/*` namespace because policies and findings are security application nouns, not shared platform vocabulary.
