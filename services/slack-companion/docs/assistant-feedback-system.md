# Assistant Feedback System

The feedback system keeps three different records because they answer different questions.

## Canonical records

### Interaction

One interaction represents one requester turn and Cerebro response. `interactionId` is the stable join key across the work loop, answer registration, context exposure, delivery outcome, and later feedback. The encrypted improvement record includes requester identity, channel and thread hashes, answer hash, execution metadata, and delivery state.

### Feedback event

Every submitted rating creates an immutable `assistant_feedback_event`. The event stores:

- `interactionId` and `answerId`
- requester identity and feedback-author identity as separate fields
- vote, reason, optional positive detail, positive outcome, expected result, and private comment
- `supersedesEventId` when the same author changes a rating
- event time and schema version

Source-specific reasons also carry the evidence id selected from that response's receipt. Wrong-source, outdated-source, and inaccessible-source feedback is rejected when no source is selected. Two distinct reporters are required before the source enters `needs_reverification`; repeated submissions from one reporter do not invalidate it. The invalidation propagates to every recorded thread that depends on that source.

The current per-author rating remains a projection for fast profile reads. A team signal keeps the positive category and a hashed thread key, but excludes the question, answer, expected result, positive outcome, and comment.

### Context exposure and outcome

Every feedback-context build records the selector version, treatment, candidate claim IDs, selected claim IDs, scope, relevance score, and prompt size. Exposure records contain hashes and typed claims, not Slack text.

Delivery and explicit feedback are outcome events joined by `interactionId`. This permits outcome analysis for interactions that did and did not receive feedback context.

## Claims Cerebro may receive

The prompt receives safe projections instead of raw feedback text:

- same-thread corrections
- corrections with topic overlap to the current request
- personal style preferences supported by at least two feedback events across two threads
- team style preferences supported by at least five feedback events, three contributors, and three threads
- personal successful patterns supported by at least two helpful ratings across two threads
- team successful patterns supported by at least five helpful ratings, three contributors, and three threads
- at most two topic-related or same-thread successful examples for the same requester
- aggregate helpful and needs-work counts
- same-thread evidence invalidations that require source re-verification

Task failures such as a wrong answer, weak evidence, a missed request, or an incomplete action remain task-scoped corrections. They do not become global user preferences. Only repeated length and clarity feedback can become a durable style preference. Successful patterns come only from a positive category selected by a person; Cerebro does not infer them from response features.

The selector does not include an unrelated correction or successful example because it came from the same channel. Prompt claims include stable IDs for attribution and evaluation. Team claims omit contributor identities, comments, positive outcomes, original requests, and prior Cerebro responses. A requester's own related positive note and outcome may enter that requester's prompt as quoted, untrusted text.

## Retention and privacy

- answer registration: 30 days
- current rating projection: 120 days
- immutable feedback events and context exposures: 365 days
- encrypted improvement artifacts follow the improvement corpus policy

Private feedback text stays in the canonical event and encrypted corpus. It is not copied into the team projection. A requester's own related positive note and outcome may enter that requester's prompt as quoted, untrusted text. Telemetry uses counts, booleans, bounded enums, and hashes.

## Measurement

Use `interactionId` to compare:

- selected claims and selector version
- helpful or needs-work feedback
- delivery completion
- correction closure in held-out replay
- outcomes by requester, reviewer, feedback reason, execution lane, and context treatment

Run a holdout only after exposure coverage and outcome volume are sufficient. The data model supports `context` and `holdout` treatments; the live selector currently records `context` for every eligible interaction.
