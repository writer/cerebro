# Codegen proof pipeline

## Objective

Move connector generation from scaffold production to a compiler pipeline with verifiable inputs, owned outputs, executable capability claims, and promotion evidence.

The pipeline is:

1. Acquire a provider contract.
2. Normalize it into a connector definition.
3. Classify the definition against the executable grammar.
4. Generate runtime, projection, deploy, fixture, and documentation artifacts.
5. Produce a proof bundle for the generated output.
6. Promote only when the required proof gates pass.

## Executable gates

The repository currently enforces these parts of the pipeline:

- `make sourcegen-grammar-check` renders one witness for every declared grammar feature and a deterministic pairwise covering set.
- Every sourcegen run returns a pre-write change plan and writes `.sourcegen-proof.json` with normalized input, output, ownership, grammar, provider-contract, and remaining-obligation evidence.
- Connector onboarding writes `.provider-contract-lock.json`, classifies provider drift, and blocks selected-operation or auth changes until an operator records review.
- `make sourcegen-repro-check` verifies output-root, normalized-input, map-order, and repeat-run invariance, then confirms that missing credentials, unstable projection identities, and modified generated files are rejected.

## Proof bundle

Every generator run should produce one deterministic proof bundle with:

- generator family and version;
- normalized input digest;
- provider contract digest and selected operation digests;
- generated output paths and content digests;
- ownership mode for each output: generated, extension point, or operator-owned;
- grammar features used by the definition;
- feature and interaction witnesses executed for those features;
- fixture, projection, deploy, and provider-unavailable results;
- semantic differences from an existing reference runtime, when one exists;
- failed obligations and the action required for each failure.

The bundle should exclude timestamps from its signed content. CI can attach observation time as run metadata without making regeneration nondeterministic.

## Executable grammar

`connectordefinitions.DefaultGrammar` is a capability claim. A feature belongs in that grammar only when a witness connector can pass classification and render through sourcegen.

`make sourcegen-grammar-check` enforces two layers:

- one witness for every declared runtime, auth model, HTTP method, pagination type, incremental state, and projection template;
- a deterministic pairwise covering plan across those dimensions.

This catches capability drift in both directions:

- the grammar advertises a feature that sourcegen cannot render;
- sourcegen gains a feature that is not represented in the grammar and therefore cannot be selected or measured.

When an interaction fails, the report names the exact feature combination and witness source. The next step is to reduce the failing combination to a minimal counterexample and retain it as a regression case.

## Next experiments

### Provider contract locks

Normalize each imported OpenAPI document and record:

- full-document digest;
- digest for each selected operation;
- request and response schema digests;
- auth scheme digest;
- normalization version.

A refresh classifies changes as unchanged, additive, behavioral review, or breaking. Regeneration should remain blocked when a selected operation changes without a reviewed contract-lock update.

### Differential runtime replay

When a generated runtime replaces or supplements an existing runtime, replay the same provider-shaped fixtures through both implementations. Compare normalized results instead of raw serialization:

- event kinds and schema refs;
- stable event identifiers;
- required attributes and payload fields;
- checkpoint transitions;
- projected entity URNs and link identities;
- failure classification.

An empty semantic difference is stronger evidence than matching source text. Accepted differences should be recorded as scoped assertions in the proof bundle.

### Metamorphic fixtures

Generate related inputs whose outputs must preserve declared invariants:

- record order changes do not change stable identifiers;
- pagination boundaries do not duplicate or drop records;
- equivalent selector alternatives produce the same identity;
- optional provider fields do not remove required graph entities;
- retryable provider failures do not advance checkpoints;
- repeated fixture replay is idempotent.

These cases provide useful coverage when a complete provider response corpus is unavailable.

### Mutation gates

Mutate one contract property at a time and require the proof pipeline to reject the result:

- remove a required auth field;
- change a selected operation method or path;
- point a projection field at an absent payload path;
- use an ephemeral field in a stable URN;
- omit deploy coverage for one runtime family;
- advance a checkpoint after a partial read;
- modify a generated output outside an extension point.

The mutation score measures whether the gates detect realistic generator defects, not just whether the happy path passes.

### Counterexample corpus

Every production schema drift, replay mismatch, or generator failure should become a minimized connector definition plus provider-shaped fixture. Store the case by grammar feature and failure class. Run the corpus before changing the classifier, templates, or runtime engine.

The minimizer should remove families, fields, auth options, and pagination options until the failure no longer reproduces. Small cases keep failures diagnosable and make generator changes safer.

### Round-trip grammar discovery

Use mature hand-written sources as evidence for missing grammar features:

1. Extract provider requests, auth behavior, pagination, event contracts, and projections into a candidate connector definition.
2. Generate a candidate runtime from that definition.
3. Run differential replay against the hand-written source.
4. Classify each mismatch as a missing grammar feature, a source-specific exception, or an existing runtime defect.

This turns proven source behavior into bounded language improvements without copying implementation structure into templates.

### Coverage-directed connector selection

Rank the next connector or fixture by the grammar interactions it would prove. Prefer work that covers an unproven auth and pagination pair, projection and incremental pair, or provider response shape before adding another connector that repeats covered behavior.

The selection report should include:

- new feature interactions covered;
- provider-contract quality;
- expected runtime families;
- required extensions;
- estimated proof obligations;
- reusable counterexamples added.

### Typed intermediate representation

Keep provider parsing separate from emitted artifacts. The normalized connector definition should be the typed intermediate representation consumed by independent backends for:

- Source Runtime code;
- graph projection code;
- deploy manifests;
- fixture contracts;
- operator documentation;
- SDK and API types.

Backends must return unsupported feature identifiers instead of silently emitting generic placeholders. A backend can then evolve without changing provider import logic or weakening another backend's proof gates.

### Incremental build graph

Replace path-only regeneration triggers with content-addressed dependencies:

- provider operation -> resource family;
- resource family -> runtime, fixtures, deploy entry, and event contract;
- event contract -> projection and graph tests;
- API contract -> SDK types and clients.

A change plan can then list the exact affected outputs, required checks, stale receipts, and ownership conflicts before files are written.

### Shadow promotion

Generated runtimes should progress through explicit states:

1. renderable: grammar and interaction witnesses pass;
2. contract-locked: provider operation digests are reviewed;
3. replay-equivalent: provider fixtures and differential checks pass;
4. shadow-ready: generated runtime can run without publishing authoritative output;
5. promotable: shadow results meet the error, completeness, and identity thresholds;
6. reference: provider drift monitoring and counterexample coverage are active.

Promotion evidence belongs in the connector review and source-health surfaces already used by operators. A lifecycle label without its proof bundle is not sufficient evidence.

## Delivery phases

### Phase 0: capability truth

- Keep the executable feature and pairwise grammar checks required in sourcegen tests.
- Add minimized regression cases for every discovered interaction failure.
- Fail when a declared grammar feature has no generated witness.

Exit gate: every declared feature and pairwise interaction is proven by a rendered connector.

### Phase 1: deterministic provenance

- Generalize sourcegen manifests into proof bundles shared by codegen families.
- Add provider document and selected-operation locks.
- Add a change-plan command that reports affected outputs before regeneration.

Exit gate: every generated output can be traced to normalized inputs, generator version, owner, and required checks.

### Phase 2: semantic evidence

- Add differential runtime and projection replay.
- Add metamorphic fixtures and mutation gates.
- Start the minimized counterexample corpus.

Exit gate: promotion decisions use semantic results, not file presence or generated-code shape.

### Phase 3: controlled promotion

- Run generated candidates in shadow mode.
- Attach proof bundles to promotion requests.
- Block promotion on provider drift, replay differences, ownership conflicts, or stale receipts.

Exit gate: a generated connector can move to authoritative collection only through reviewed, reproducible evidence.

## Ownership boundaries

- Provider import owns normalized provider facts and contract locks.
- Connector definitions own selected operations, event contracts, coverage, and projection intent.
- Sourcegen owns files listed in its generation manifest.
- Extension files own provider-specific behavior that is outside the grammar.
- Runtime and projection validators own semantic acceptance.
- Connector review owns lifecycle state and human approval evidence.
- Operators own secrets, environment bindings, enablement, and rollback.

Generated files must not become informal extension points. If a provider behavior cannot be expressed in the typed definition, add a declared extension surface or classify the connector as requiring a bespoke runtime.

## Measures

Track these measures by generator version:

- declared features versus executable features;
- proven pairwise interactions versus required interactions;
- provider operation locks current versus drifted;
- generated connectors with complete proof bundles;
- differential replay mismatches by class;
- mutation detection rate;
- counterexamples added and regressions prevented;
- generated output ownership conflicts;
- regeneration time and unchanged outputs skipped;
- generated connectors promoted, rolled back, or converted to bespoke runtimes.
