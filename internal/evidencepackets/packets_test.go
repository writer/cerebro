package evidencepackets

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBuildUsesStableFrameworkIDAndRuleScopedTestResults(t *testing.T) {
	observedAt := time.Unix(90, 0).UTC()
	response := Build(grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "security-core", Name: "Security Core"},
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: time.Unix(100, 0).UTC(),
			Controls: []compliance.ControlEvidencePacketControl{{
				Control: compliance.ControlPostureControl{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				Evidence: compliance.ControlEvidencePacketEvidence{
					Expectations: []compliance.ControlEvidenceExpectationPosture{{
						ID:          "automated-proof",
						Status:      compliance.ControlEvidenceExpectationSatisfied,
						Quality:     compliance.ControlEvidenceQualityStrong,
						Reason:      "request evidence is current",
						EvidenceIDs: []string{"ev-1"},
					}},
					Items: []compliance.ControlEvidencePacketEvidenceItem{{
						ID:           "ev-1",
						RuleID:       "rule.fail",
						EvidenceType: "finding_evidence",
						Quality:      compliance.ControlEvidenceQualityStrong,
						Reason:       "packet evidence is current",
						ObservedAt:   observedAt,
					}},
				},
				Overrides: compliance.ControlPostureOverrides{ExceptionIDs: []string{"risk accepted"}},
			}},
		},
		Controls: []grccontrol.ControlItem{{
			FrameworkName: "SOC 2",
			FrameworkID:   "soc2",
			ControlID:     "CC6.1",
			Status:        "needs_attention",
			MappedRules:   []string{"rule.pass", "rule.fail"},
			Findings:      []grccontrol.FindingItem{{RuleID: "rule.fail", Status: "open"}},
		}},
		Evidence: []*cerebrov1.FindingEvidence{{
			Id:             "ev-1",
			RuntimeId:      "runtime-1",
			FindingId:      "finding-1",
			RuleId:         "rule.fail",
			RunId:          "run-1",
			ClaimIds:       []string{"claim-1"},
			EventIds:       []string{"event-1"},
			GraphRootUrns:  []string{"urn:cerebro:test:identity:admin"},
			LastObservedAt: timestamppb.New(observedAt),
		}},
		Runtimes: []*cerebrov1.SourceRuntime{{
			Id:           "runtime-1",
			SourceId:     "source-1",
			TenantId:     "tenant-1",
			LastSyncedAt: timestamppb.New(observedAt),
		}},
		SourceIDs: map[string]string{"runtime-1": "source-1"},
		Metadata: grccontrol.ReportMetadata{
			Readiness: grccontrol.ReportReadiness{Status: "needs_attention"},
			Scope: grccontrol.ReportScope{
				SourceIDs:  []string{"source-1"},
				RuntimeIDs: []string{"runtime-1"},
				IncrementalFetch: grccontrol.ReportIncrementalFetch{
					Status:                  "all_collected",
					PolicyAppliedBeforeRead: true,
				},
			},
			Provenance: grccontrol.ReportProvenance{ProfileID: "security-core"},
			Redaction:  grccontrol.ReportRedaction{DefaultMode: "share_safe"},
		},
	})

	if len(response.Controls) != 1 {
		t.Fatalf("controls = %d, want 1", len(response.Controls))
	}
	control := response.Controls[0]
	if control.FrameworkID != "soc2" {
		t.Fatalf("framework_id = %q, want stable framework id", control.FrameworkID)
	}
	results := map[string]string{}
	for _, result := range control.TestResults {
		results[result.RuleID] = result.Result
	}
	if results["rule.pass"] != "pass" || results["rule.fail"] != "fail" {
		t.Fatalf("test results = %#v, want per-rule pass/fail results", results)
	}
	if len(response.Sources) != 1 || response.Sources[0].Status != "collected" {
		t.Fatalf("sources = %#v, want collected source runtime", response.Sources)
	}
	if len(response.Items) != 1 || len(response.Lineage) != 1 || len(response.Resources) != 1 {
		t.Fatalf("expanded records items=%d lineage=%d resources=%d, want raw evidence records", len(response.Items), len(response.Lineage), len(response.Resources))
	}
	if response.Items[0].PacketIDs[0] == "" || response.Lineage[0].PacketIDs[0] == "" {
		t.Fatalf("lineage links item=%#v lineage=%#v, want packet links", response.Items[0], response.Lineage[0])
	}
	if len(control.ExceptionIDs) != 1 || len(response.Exceptions) != 1 || control.ExceptionIDs[0] != response.Exceptions[0].ID {
		t.Fatalf("exception links control=%#v exceptions=%#v, want stable exception cross-reference", control.ExceptionIDs, response.Exceptions)
	}
	reviewReasons := map[string]string{}
	for _, review := range response.Reviews {
		reviewReasons[review.SubjectID] = review.Reason
	}
	if reviewReasons[response.Requests[0].ID] != "request evidence is current" {
		t.Fatalf("request review reason = %q, want expectation reason", reviewReasons[response.Requests[0].ID])
	}
	if reviewReasons[response.Packets[0].ID] != "packet evidence is current" {
		t.Fatalf("packet review reason = %q, want evidence item reason", reviewReasons[response.Packets[0].ID])
	}
}

func TestBuildKeepsNotApplicableFrameworkReadyAndTrimsEvidenceKeys(t *testing.T) {
	response := Build(grccontrol.PacketResult{
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: time.Unix(200, 0).UTC(),
			Controls: []compliance.ControlEvidencePacketControl{{
				Control: compliance.ControlPostureControl{FrameworkName: "SOC 2", ControlID: "CC1.1"},
				Evidence: compliance.ControlEvidencePacketEvidence{
					Expectations: []compliance.ControlEvidenceExpectationPosture{{
						ID:          "automated-proof",
						Status:      compliance.ControlEvidenceExpectationSatisfied,
						EvidenceIDs: []string{"ev-space"},
					}},
					Items: []compliance.ControlEvidencePacketEvidenceItem{{
						ID:     "ev-space",
						RuleID: "rule.space",
					}},
				},
			}},
		},
		Controls: []grccontrol.ControlItem{{
			FrameworkName:   "SOC 2",
			FrameworkID:     "soc2",
			ControlID:       "CC1.1",
			Status:          "not_applicable",
			EvidenceScore:   100,
			MissingEvidence: 2,
			StaleEvidence:   1,
			Findings:        []grccontrol.FindingItem{{ID: "finding-space", RuntimeID: "runtime-1", Status: "open"}},
		}},
		Findings: []*ports.FindingRecord{{
			ID:           " finding-space ",
			PolicyID:     "policy-space",
			PolicyName:   "Policy Space",
			CheckID:      "check-space",
			CheckName:    "Check Space",
			FindingRisk:  ports.FindingRisk{RiskScore: 42, RiskReasons: []string{"trimmed finding"}},
			ResourceURNs: []string{"urn:cerebro:test:service:svc-space"},
		}},
		Evidence: []*cerebrov1.FindingEvidence{{
			Id:        " ev-space ",
			RuntimeId: " runtime-1 ",
			FindingId: " finding-space ",
			RuleId:    "rule.space",
			ClaimIds:  []string{"claim-space"},
			EventIds:  []string{"event-space"},
			RunId:     "run-space",
			GraphRows: []*cerebrov1.GraphEvidenceRow{{
				Label: "supporting_path",
				Paths: []*cerebrov1.GraphEvidencePath{{
					FromUrn:  "urn:cerebro:test:identity:user",
					Relation: "has_access",
					ToUrn:    "urn:cerebro:test:service:svc-space",
				}},
			}},
		}},
		SourceIDs: map[string]string{"runtime-1": "source-1"},
	})

	if len(response.Frameworks) != 1 {
		t.Fatalf("frameworks = %d, want 1", len(response.Frameworks))
	}
	framework := response.Frameworks[0]
	if framework.Status != "ready" || framework.PassingControls != 1 || framework.NeedsAttentionControls != 0 {
		t.Fatalf("framework = %#v, want not_applicable counted as ready", framework)
	}
	if framework.MissingEvidence != 0 || framework.StaleEvidence != 0 {
		t.Fatalf("framework evidence blockers = missing %d stale %d, want ignored for not_applicable", framework.MissingEvidence, framework.StaleEvidence)
	}
	if got := response.Items[0].ID; got != "ev-space" {
		t.Fatalf("evidence item id = %q, want trimmed id", got)
	}
	if len(response.Items[0].PacketIDs) != 1 {
		t.Fatalf("evidence item packet links = %#v, want trimmed key cross-reference", response.Items[0].PacketIDs)
	}
	if got := response.Packets[0].Citations.ClaimIDs; len(got) != 1 || got[0] != "claim-space" {
		t.Fatalf("packet claim citations = %#v, want raw evidence citation via trimmed lookup", got)
	}
	if len(response.Sources) != 1 || response.Sources[0].Status != "observed" || response.Sources[0].EvidenceItemCount != 1 {
		t.Fatalf("sources = %#v, want observed source from evidence runtime outside configured scope", response.Sources)
	}
	if len(response.Findings) != 1 || response.Findings[0].PolicyID != "policy-space" || response.Findings[0].RiskScore != 42 {
		t.Fatalf("finding workflow = %#v, want raw finding enrichment via trimmed ID", response.Findings)
	}
	if len(response.GraphRows) != 1 || response.GraphRows[0].EvidenceID != "ev-space" || response.GraphRows[0].FindingID != "finding-space" {
		t.Fatalf("graph rows = %#v, want trimmed evidence and finding IDs", response.GraphRows)
	}
	if len(response.GraphPaths) != 1 || response.GraphPaths[0].EvidenceID != "ev-space" || response.GraphPaths[0].FindingID != "finding-space" {
		t.Fatalf("graph paths = %#v, want trimmed evidence and finding IDs", response.GraphPaths)
	}
}

func TestStableIDEncodesUnsafePartsWithoutLossyCollisions(t *testing.T) {
	withSlash := stableID("control", "soc2", "CC6/1")
	withDash := stableID("control", "soc2", "CC6-1")
	if withSlash == withDash {
		t.Fatalf("stable IDs collided: slash=%q dash=%q", withSlash, withDash)
	}
	if want := "control:soc2:h_4343362f31"; withSlash != want {
		t.Fatalf("stable ID with slash = %q, want hex encoded unsafe part %q", withSlash, want)
	}
}

func TestAddGraphBackedAccessEvidenceBuildsReasoningReadySubject(t *testing.T) {
	generatedAt := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	response := Build(grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "access-review", Name: "Access Review"},
		Packet:  compliance.ControlEvidencePacket{GeneratedAt: generatedAt},
		Metadata: grccontrol.ReportMetadata{
			Readiness: grccontrol.ReportReadiness{Status: "ready"},
			Provenance: grccontrol.ReportProvenance{
				ProfileID: "access-review",
			},
			Redaction: grccontrol.ReportRedaction{DefaultMode: "share_safe"},
		},
	})

	enriched := AddGraphBackedAccessEvidence(response, GraphBackedAccessEvidenceInput{
		TenantID:       "tenant-1",
		PeriodStart:    time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:      time.Date(2026, 6, 30, 23, 59, 0, 0, time.UTC),
		ReviewerURN:    "urn:cerebro:tenant-1:person:reviewer",
		OwnerURN:       "urn:cerebro:tenant-1:person:app-owner",
		ExceptionState: "none",
		PolicyCitations: []string{
			"policies/identity/identity-privileged-access-review-overdue.yaml",
		},
		SourceFreshness: []AccessSourceFreshness{{
			SourceID:   "okta",
			RuntimeID:  "runtime-okta",
			ObservedAt: "2026-06-15T12:00:00Z",
			Status:     "fresh",
		}},
		EffectiveAccess: &graphquery.EffectiveAccessPathResult{
			TenantID: "tenant-1",
			Paths: []graphquery.EffectiveAccessPath{{
				Identity: graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:okta:user:00u123",
					EntityType: "okta.user",
					Label:      "Pat Finance",
				},
				Principal: graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:okta:principal:00u123",
					EntityType: "okta.principal",
					Label:      "pat@example.com",
				},
				Mediator: &graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:okta:group:finance-admins",
					EntityType: "okta.group",
					Label:      "Finance Admins",
				},
				AccessTarget: graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:okta:application:payroll",
					EntityType: "okta.application",
					Label:      "Payroll",
				},
				Entitlement: graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:okta:entitlement:payroll-admin",
					EntityType: "okta.entitlement",
					Label:      "Payroll Admin",
				},
				Capability: graphquery.GraphEntityRef{
					URN:        "urn:cerebro:tenant-1:capability:admin",
					EntityType: "access.capability",
					Label:      "Administer payroll",
				},
				AssignmentKind: "group_app_assignment",
				RelationChain:  []string{"member_of", "assigned_to", "grants_entitlement", "confers_capability"},
				Edges: []graphquery.EffectiveAccessPathEdge{{
					From:      graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:principal:00u123", EntityType: "okta.principal"},
					Relation:  "member_of",
					To:        graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:group:finance-admins", EntityType: "okta.group"},
					SourceID:  "okta",
					RuntimeID: "runtime-okta",
					EventID:   "event-group",
					At:        "2026-06-10T09:00:00Z",
					Attributes: map[string]string{
						"account_status":  "ACTIVE",
						"lifecycle_state": "active",
						"mfa_posture":     "not_enrolled",
					},
				}, {
					From:      graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:group:finance-admins", EntityType: "okta.group"},
					Relation:  "assigned_to",
					To:        graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:application:payroll", EntityType: "okta.application"},
					SourceID:  "okta",
					RuntimeID: "runtime-okta",
					EventID:   "event-app",
					At:        "2026-06-10T09:01:00Z",
				}},
			}},
		},
	})

	if len(enriched.Access) != 1 {
		t.Fatalf("access subjects = %d, want 1", len(enriched.Access))
	}
	subject := enriched.Access[0]
	if subject.EvidenceUse != AccessEvidenceUseOperationProof || subject.AccountStatus != "ACTIVE" || subject.MFAPosture != "not_enrolled" {
		t.Fatalf("subject posture = %#v, want operation proof with account and MFA posture", subject)
	}
	if !containsString(subject.IncludedBecause, "access_is_group_mediated") || !containsString(subject.IncludedBecause, "access_is_privileged") {
		t.Fatalf("included because = %#v, want graph-backed group and privileged reasons", subject.IncludedBecause)
	}
	if !containsString(subject.RiskSignals, "privileged_access") || !containsString(subject.RiskSignals, "mfa_not_enrolled") {
		t.Fatalf("risk signals = %#v, want privileged and MFA risk", subject.RiskSignals)
	}
	if !containsString(subject.ChangeSummary, "graph_access_edge_observed_during_review_period") {
		t.Fatalf("change summary = %#v, want period change explanation", subject.ChangeSummary)
	}
	if len(subject.AccessItems) != 1 || !subject.AccessItems[0].Privileged || !subject.AccessItems[0].ChangedDuringPeriod {
		t.Fatalf("access items = %#v, want privileged changed item", subject.AccessItems)
	}
	if len(subject.OperatingEffectivenessItemIDs) != 1 || len(subject.ReviewContextItemIDs) != 0 {
		t.Fatalf("proof/context split proof=%#v context=%#v, want operating proof item only", subject.OperatingEffectivenessItemIDs, subject.ReviewContextItemIDs)
	}
	if subject.Confidence.Level != "high" || subject.ManualReviewState != "ready_for_review" {
		t.Fatalf("confidence/manual state = %#v/%q, want high ready packet", subject.Confidence, subject.ManualReviewState)
	}
	if len(subject.SourceCitations) != 2 || len(subject.Freshness) != 1 || !containsString(subject.PolicyCitations, "policies/identity/identity-privileged-access-review-overdue.yaml") {
		t.Fatalf("citations/freshness policy=%#v source=%#v freshness=%#v, want packet-level source, policy, freshness", subject.PolicyCitations, subject.SourceCitations, subject.Freshness)
	}
	if !containsString(subject.OverclaimGuards, "Do not use review-context items as operating-effectiveness proof.") {
		t.Fatalf("overclaim guards = %#v, want proof/context guard", subject.OverclaimGuards)
	}
	if len(subject.Citations.EventIDs) != 2 || !containsString(subject.Citations.EventIDs, "event-group") || !containsString(subject.Citations.GraphRoots, "urn:cerebro:tenant-1:okta:application:payroll") {
		t.Fatalf("citations = %#v, want graph roots and event ids", subject.Citations)
	}
	if len(enriched.GraphPaths) != 2 || enriched.Program.GraphPathCount != len(enriched.GraphPaths) || enriched.Snapshot.GraphPathCount != len(enriched.GraphPaths) {
		t.Fatalf("graph path counts paths=%d program=%d snapshot=%d, want appended graph paths counted", len(enriched.GraphPaths), enriched.Program.GraphPathCount, enriched.Snapshot.GraphPathCount)
	}
	if len(enriched.Reasoning) != 5 {
		t.Fatalf("reasoning tasks = %d, want bounded access review questions", len(enriched.Reasoning))
	}
	if !containsString(enriched.Reasoning[0].Guards, "Do not infer access outside the cited graph paths.") {
		t.Fatalf("reasoning guards = %#v, want overclaim guard", enriched.Reasoning[0].Guards)
	}
}

func TestAddGraphBackedAccessEvidenceCoversOktaAccessShapesAndWeakStates(t *testing.T) {
	response := Build(grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "okta-access-review", Name: "Okta Access Review"},
		Packet:  compliance.ControlEvidencePacket{GeneratedAt: time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)},
	})
	input := GraphBackedAccessEvidenceInput{
		TenantID:    "tenant-1",
		PeriodStart: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 6, 30, 23, 59, 0, 0, time.UTC),
		SourceFreshness: []AccessSourceFreshness{{
			SourceID:   "okta",
			RuntimeID:  "runtime-okta",
			ObservedAt: "2026-05-01T00:00:00Z",
			Status:     "stale",
		}},
		EffectiveAccess: &graphquery.EffectiveAccessPathResult{
			TenantID: "tenant-1",
			Paths: []graphquery.EffectiveAccessPath{
				oktaPath("00u-direct", "direct_app_assignment", "", "timekeeping", "time_user", "use", []string{"assigned_to", "grants_entitlement", "confers_capability"}, map[string]string{
					"account_status":  "ACTIVE",
					"lifecycle_state": "active",
					"mfa_posture":     "enrolled",
				}),
				oktaPath("00u-direct", "admin_role_assignment", "", "okta_super_admin_role", "super_admin", "admin", []string{"can_admin", "grants_entitlement", "confers_capability"}, map[string]string{
					"account_status":  "ACTIVE",
					"lifecycle_state": "active",
					"mfa_posture":     "enrolled",
					"privileged":      "true",
				}),
				oktaPath("00u-dormant", "group_app_assignment", "external-contractors", "finance-reports", "finance_report_viewer", "read", []string{"member_of", "assigned_to", "grants_entitlement", "confers_capability"}, map[string]string{
					"account_status":  "dormant",
					"lifecycle_state": "dormant",
				}),
			},
		},
	}

	enriched := AddGraphBackedAccessEvidence(response, input)
	if len(enriched.Access) != 2 {
		t.Fatalf("access subjects = %d, want direct/admin subject plus dormant subject", len(enriched.Access))
	}
	byURN := map[string]AccessEvidenceSubject{}
	for _, subject := range enriched.Access {
		byURN[subject.SubjectURN] = subject
	}
	active := byURN["urn:cerebro:tenant-1:okta:user:00u-direct"]
	if len(active.AccessItems) != 2 {
		t.Fatalf("active access items = %#v, want direct app and admin role paths", active.AccessItems)
	}
	if !hasAssignmentKind(active.AccessItems, "direct_app_assignment") || !hasAssignmentKind(active.AccessItems, "admin_role_assignment") {
		t.Fatalf("active access items = %#v, want direct app and admin role assignment kinds", active.AccessItems)
	}
	if !containsString(active.RiskSignals, "privileged_access") || !containsString(active.RiskSignals, "source_freshness_stale") {
		t.Fatalf("active risk signals = %#v, want admin role and stale source risk", active.RiskSignals)
	}
	if active.Confidence.Level != "medium" || !containsString(active.Confidence.Reasons, "stale_source_freshness") {
		t.Fatalf("active confidence = %#v, want stale freshness medium confidence", active.Confidence)
	}

	dormant := byURN["urn:cerebro:tenant-1:okta:user:00u-dormant"]
	if dormant.AccountStatus != "dormant" || dormant.LifecycleState != "dormant" {
		t.Fatalf("dormant posture = account %q lifecycle %q, want dormant graph facts", dormant.AccountStatus, dormant.LifecycleState)
	}
	if !containsString(dormant.RiskSignals, "dormant_user_access") || !containsString(dormant.RiskSignals, "mfa_posture_unknown") {
		t.Fatalf("dormant risk signals = %#v, want dormant and unknown MFA risk", dormant.RiskSignals)
	}
	if dormant.ManualReviewState != "needs_manual_review" || !containsString(dormant.UnsupportedClaims, "mfa_enforced") {
		t.Fatalf("dormant manual state = %q unsupported=%#v, want manual review for unknown MFA", dormant.ManualReviewState, dormant.UnsupportedClaims)
	}
	if len(dormant.OperatingEffectivenessItemIDs) != 1 || len(dormant.ManualReviewOnlyItemIDs) != 0 {
		t.Fatalf("dormant proof/context split proof=%#v manual=%#v, want graph assignment as proof with missing context tracked separately", dormant.OperatingEffectivenessItemIDs, dormant.ManualReviewOnlyItemIDs)
	}
}

func TestGraphBackedAccessEvidenceUsesReviewContextForStandingAccess(t *testing.T) {
	path := oktaPath("00u-standing", "direct_app_assignment", "", "timekeeping", "time_user", "use", []string{"assigned_to", "grants_entitlement", "confers_capability"}, map[string]string{
		"account_status":  "ACTIVE",
		"lifecycle_state": "active",
		"mfa_posture":     "enrolled",
	})
	for index := range path.Edges {
		path.Edges[index].At = "2026-05-01T10:00:00Z"
	}
	enriched := AddGraphBackedAccessEvidence(Build(grccontrol.PacketResult{}), GraphBackedAccessEvidenceInput{
		TenantID:    "tenant-1",
		PeriodStart: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 6, 30, 23, 59, 0, 0, time.UTC),
		EffectiveAccess: &graphquery.EffectiveAccessPathResult{TenantID: "tenant-1", Paths: []graphquery.EffectiveAccessPath{
			path,
		}},
	})
	if len(enriched.Access) != 1 {
		t.Fatalf("access subjects = %d, want one", len(enriched.Access))
	}
	subject := enriched.Access[0]
	if subject.EvidenceUse != AccessEvidenceUseReviewContext || len(subject.OperatingEffectivenessItemIDs) != 0 || len(subject.ReviewContextItemIDs) != 1 {
		t.Fatalf("proof/context split = subject use %q proof=%#v context=%#v, want standing access as review context", subject.EvidenceUse, subject.OperatingEffectivenessItemIDs, subject.ReviewContextItemIDs)
	}
	if len(enriched.GraphPaths) == 0 || enriched.GraphPaths[0].Attributes["evidence_use"] != AccessEvidenceUseReviewContext {
		t.Fatalf("graph path evidence_use = %#v, want review context", enriched.GraphPaths)
	}
}

func oktaPath(userID string, assignmentKind string, groupID string, targetID string, entitlementID string, capabilityID string, chain []string, attrs map[string]string) graphquery.EffectiveAccessPath {
	principalURN := "urn:cerebro:tenant-1:okta:principal:" + userID
	path := graphquery.EffectiveAccessPath{
		Identity:       graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:user:" + userID, EntityType: "okta.user", Label: userID},
		Principal:      graphquery.GraphEntityRef{URN: principalURN, EntityType: "okta.principal", Label: userID + "@example.com"},
		AccessTarget:   graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:application:" + targetID, EntityType: "okta.application", Label: targetID},
		Entitlement:    graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:entitlement:" + entitlementID, EntityType: "okta.entitlement", Label: entitlementID},
		Capability:     graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:capability:" + capabilityID, EntityType: "access.capability", Label: capabilityID},
		AssignmentKind: assignmentKind,
		RelationChain:  chain,
	}
	nodes := []graphquery.GraphEntityRef{path.Principal}
	if groupID != "" {
		mediator := graphquery.GraphEntityRef{URN: "urn:cerebro:tenant-1:okta:group:" + groupID, EntityType: "okta.group", Label: groupID}
		path.Mediator = &mediator
		nodes = append(nodes, mediator)
	}
	nodes = append(nodes, path.AccessTarget, path.Entitlement, path.Capability)
	for index, relation := range chain {
		edgeAttrs := map[string]string{}
		if index == 0 {
			for key, value := range attrs {
				edgeAttrs[key] = value
			}
		}
		path.Edges = append(path.Edges, graphquery.EffectiveAccessPathEdge{
			From:       nodes[index],
			Relation:   relation,
			To:         nodes[index+1],
			SourceID:   "okta",
			RuntimeID:  "runtime-okta",
			EventID:    userID + "-" + relation,
			At:         "2026-06-05T10:00:00Z",
			Attributes: edgeAttrs,
		})
	}
	return path
}

func hasAssignmentKind(items []AccessEvidenceItem, want string) bool {
	for _, item := range items {
		if item.AssignmentKind == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
