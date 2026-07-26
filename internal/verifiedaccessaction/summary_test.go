package verifiedaccessaction

import "testing"

func TestSummarizeKeepsProviderSuccessSeparateFromVerifiedClosure(t *testing.T) {
	t.Parallel()

	proposal := mustPropose(t)
	preflight := mustPreflight(t, proposal.Record)
	approval := mustApprove(t, proposal.Record.Digest, preflight.Record)
	execution := mustExecute(t, proposal.Record.Digest, approval.Record)

	summary, err := Summarize(execution.Record)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.ProviderSucceeded || summary.VerifiedClosed {
		t.Fatalf(
			"provider_succeeded=%t verified_closed=%t, want true and false",
			summary.ProviderSucceeded,
			summary.VerifiedClosed,
		)
	}
	if summary.BlockerCode != BlockerFreshVerification {
		t.Fatalf("blocker_code = %q, want %q", summary.BlockerCode, BlockerFreshVerification)
	}
	if summary.ProviderExternalID == "" || summary.ExecutedAt == nil {
		t.Fatalf("provider receipt fields are missing: %+v", summary)
	}

	closed := mustVerify(t, execution.Record)
	closedSummary, err := Summarize(closed.Record)
	if err != nil {
		t.Fatal(err)
	}
	if !closedSummary.ProviderSucceeded || !closedSummary.VerifiedClosed ||
		closedSummary.BlockerCode != "" || closedSummary.VerifiedAt == nil {
		t.Fatalf("closed summary = %+v", closedSummary)
	}
}

func TestSummarizeMarksUnknownSubmissionForAttention(t *testing.T) {
	t.Parallel()

	proposal := mustPropose(t)
	preflight := mustPreflight(t, proposal.Record)
	approval := mustApprove(t, proposal.Record.Digest, preflight.Record)
	claim := mustClaim(t, proposal.Record.Digest, approval.Record)
	unknown, err := RecordSubmissionUnknown(claim.Record, submissionUnknownInput(claim.Record))
	if err != nil {
		t.Fatal(err)
	}

	summary, err := Summarize(unknown.Record)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.AttentionRequired ||
		summary.BlockerCode != BlockerProviderReconcile ||
		summary.NextReconcileAt == nil ||
		summary.ProviderSucceeded ||
		summary.VerifiedClosed {
		t.Fatalf("unknown summary = %+v", summary)
	}
}
