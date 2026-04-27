package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	configpkg "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphquery"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceregistry"
)

const githubDependabotOpenAlertRuleID = "github-dependabot-open-alert"

func TestGitHubDependabotFindingsEndToEndWithGHCLI(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_GITHUB_FINDINGS_E2E") != "1" {
		t.Skip("set CEREBRO_RUN_GITHUB_FINDINGS_E2E=1 to run the live GitHub findings e2e flow")
	}

	ctx := context.Background()
	config := map[string]string{
		"family":   "dependabot_alert",
		"per_page": "5",
		"state":    "open",
	}
	if owner := strings.TrimSpace(os.Getenv("CEREBRO_GITHUB_FINDINGS_OWNER")); owner != "" {
		config["owner"] = owner
	}
	if repo := strings.TrimSpace(os.Getenv("CEREBRO_GITHUB_FINDINGS_REPO")); repo != "" {
		config["repo"] = repo
	}
	config, err := prepareSourceConfigWithCLI(ctx, githubSourceID, "read", config, execGitHubLocalCLI{})
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}

	registry, err := sourceregistry.Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	response, liveAlertState, synthesizedOpenState, err := readDependabotAlertsForLiveFinding(ctx, sourceops.New(registry), config)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(response.GetEvents()) == 0 {
		t.Skipf("no Dependabot alerts available for live GitHub findings e2e in %s/%s", config["owner"], config["repo"])
	}

	runtimeID := "live-github-dependabot"
	events := cloneEventsForRuntime(response.GetEvents(), runtimeID)
	if synthesizedOpenState {
		synthesizeOpenDependabotEvents(t, events, liveAlertState)
	}
	graphPath := t.TempDir() + "/graph"
	graphStore, err := graphstorekuzu.Open(configpkg.GraphStoreConfig{
		Driver:   configpkg.GraphStoreDriverKuzu,
		KuzuPath: graphPath,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := graphStore.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}()
	projector := sourceprojection.New(nil, graphStore)
	for _, event := range events {
		if _, err := projector.Project(ctx, event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	state := newGitHubFindingsE2EStore(&cerebrov1.SourceRuntime{
		Id:       runtimeID,
		SourceId: githubSourceID,
		TenantId: config["owner"],
		Config: map[string]string{
			"family": "dependabot_alert",
			"owner":  config["owner"],
			"repo":   config["repo"],
			"state":  "open",
		},
	})
	findingService := findings.New(
		state,
		&githubFindingsE2EReplayer{events: events},
		state,
		state,
		state,
		state,
	).WithGraphStore(graphStore).WithGraphQueryStore(graphStore)
	result, err := findingService.EvaluateSourceRuntime(ctx, findings.EvaluateRequest{
		RuntimeID: runtimeID,
		RuleID:    githubDependabotOpenAlertRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("EvaluateSourceRuntime().Findings = 0, want at least one finding")
	}
	finding := result.Findings[0]
	primaryResourceURN := strings.TrimSpace(finding.Attributes["primary_resource_urn"])
	if primaryResourceURN == "" {
		t.Fatal("finding primary_resource_urn is empty")
	}
	if _, err := findingService.AddFindingNote(ctx, finding.ID, "validated by live GitHub Dependabot findings e2e"); err != nil {
		t.Fatalf("AddFindingNote() error = %v", err)
	}
	ticketURL := "https://github.com/" + config["owner"] + "/" + config["repo"] + "/security/dependabot/" + strings.TrimSpace(finding.Attributes["alert_number"])
	if _, err := findingService.LinkFindingTicket(ctx, finding.ID, ticketURL, "Dependabot alert", strings.TrimSpace(finding.Attributes["alert_number"])); err != nil {
		t.Fatalf("LinkFindingTicket() error = %v", err)
	}
	resolved, err := findingService.ResolveFinding(ctx, finding.ID, "live Dependabot alert validated")
	if err != nil {
		t.Fatalf("ResolveFinding() error = %v", err)
	}
	if resolved.Status != "resolved" {
		t.Fatalf("ResolveFinding().Status = %q, want resolved", resolved.Status)
	}

	alertNeighborhood, err := graphquery.New(graphStore).GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
		RootURN: primaryResourceURN,
		Limit:   20,
	})
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(%q) error = %v", primaryResourceURN, err)
	}
	if alertNeighborhood.Root == nil {
		t.Fatal("graph neighborhood root = nil, want Dependabot alert root")
	}
	for _, relation := range []string{"affected_by", "affects", "annotated_with", "belongs_to", "has_finding", "tracked_by"} {
		if !neighborhoodHasRelation(alertNeighborhood, relation) {
			t.Fatalf("alert graph neighborhood missing relation %q: %#v", relation, alertNeighborhood.Relations)
		}
	}

	findingURN := "urn:cerebro:" + finding.TenantID + ":finding:" + finding.ID
	findingNeighborhood, err := graphquery.New(graphStore).GetEntityNeighborhood(ctx, graphquery.NeighborhoodRequest{
		RootURN: findingURN,
		Limit:   20,
	})
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(%q) error = %v", findingURN, err)
	}
	if !neighborhoodHasTypedRelation(findingNeighborhood, "decision", "targets", "finding") {
		t.Fatalf("finding graph neighborhood missing decision target relation: %#v", findingNeighborhood.Relations)
	}
	if !neighborhoodHasTypedRelation(findingNeighborhood, "outcome", "targets", "finding") {
		t.Fatalf("finding graph neighborhood missing outcome target relation: %#v", findingNeighborhood.Relations)
	}
	if !neighborhoodHasTypedRelation(findingNeighborhood, "github.dependabot_alert", "has_finding", "finding") {
		t.Fatalf("finding graph neighborhood missing alert finding relation: %#v", findingNeighborhood.Relations)
	}
	if len(alertNeighborhood.Relations) == 0 || len(findingNeighborhood.Relations) == 0 {
		t.Fatal("graph neighborhood relations = 0, want source/finding graph links")
	}
	if outputPath := strings.TrimSpace(os.Getenv("CEREBRO_GITHUB_FINDINGS_GRAPH_PREVIEW_OUT")); outputPath != "" {
		writeGitHubFindingsGraphPreview(t, outputPath, githubFindingsGraphPreview{
			Owner:                 config["owner"],
			Repo:                  config["repo"],
			RuntimeID:             runtimeID,
			LiveAlertState:        liveAlertState,
			SynthesizedOpenState:  synthesizedOpenState,
			EventsRead:            len(events),
			FindingsProjected:     len(result.Findings),
			PrimaryResourceURN:    primaryResourceURN,
			FindingURN:            findingURN,
			AlertNeighborhood:     newGraphPreviewNeighborhood(alertNeighborhood),
			FindingNeighborhood:   newGraphPreviewNeighborhood(findingNeighborhood),
			RequiredAlertEdges:    []string{"affected_by", "affects", "annotated_with", "belongs_to", "has_finding", "tracked_by"},
			RequiredWorkflowEdges: []string{"decision --targets--> finding", "outcome --targets--> finding", "github.dependabot_alert --has_finding--> finding"},
		})
	}
	t.Logf(
		"validated live github findings owner=%s repo=%s live_state=%s events=%d findings=%d primary_resource=%s alert_neighbors=%d alert_relations=%d finding_neighbors=%d finding_relations=%d",
		config["owner"],
		config["repo"],
		liveAlertState,
		len(events),
		len(result.Findings),
		primaryResourceURN,
		len(alertNeighborhood.Neighbors),
		len(alertNeighborhood.Relations),
		len(findingNeighborhood.Neighbors),
		len(findingNeighborhood.Relations),
	)
}

type githubFindingsE2EReplayer struct {
	events []*cerebrov1.EventEnvelope
}

type githubFindingsGraphPreview struct {
	Owner                 string                   `json:"owner"`
	Repo                  string                   `json:"repo"`
	RuntimeID             string                   `json:"runtime_id"`
	LiveAlertState        string                   `json:"live_alert_state"`
	SynthesizedOpenState  bool                     `json:"synthesized_open_state"`
	EventsRead            int                      `json:"events_read"`
	FindingsProjected     int                      `json:"findings_projected"`
	PrimaryResourceURN    string                   `json:"primary_resource_urn"`
	FindingURN            string                   `json:"finding_urn"`
	AlertNeighborhood     graphPreviewNeighborhood `json:"alert_neighborhood"`
	FindingNeighborhood   graphPreviewNeighborhood `json:"finding_neighborhood"`
	RequiredAlertEdges    []string                 `json:"required_alert_edges"`
	RequiredWorkflowEdges []string                 `json:"required_workflow_edges"`
}

type graphPreviewNeighborhood struct {
	Root      graphPreviewNode       `json:"root"`
	Neighbors []graphPreviewNode     `json:"neighbors"`
	Relations []graphPreviewRelation `json:"relations"`
}

type graphPreviewNode struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

type graphPreviewRelation struct {
	FromURN  string `json:"from_urn"`
	Relation string `json:"relation"`
	ToURN    string `json:"to_urn"`
	FromType string `json:"from_type"`
	ToType   string `json:"to_type"`
}

func (r *githubFindingsE2EReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	events := make([]*cerebrov1.EventEnvelope, 0, len(r.events))
	for _, event := range r.events {
		if request.RuntimeID != "" && event.GetAttributes()[ports.EventAttributeSourceRuntimeID] != request.RuntimeID {
			continue
		}
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
		if request.Limit != 0 && uint32(len(events)) >= request.Limit {
			break
		}
	}
	return events, nil
}

func writeGitHubFindingsGraphPreview(t *testing.T, outputPath string, preview githubFindingsGraphPreview) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatalf("create graph preview output directory: %v", err)
	}
	payload, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatalf("marshal graph preview: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(outputPath, payload, 0o644); err != nil {
		t.Fatalf("write graph preview: %v", err)
	}
}

func newGraphPreviewNeighborhood(neighborhood *ports.EntityNeighborhood) graphPreviewNeighborhood {
	nodeTypes := map[string]string{}
	preview := graphPreviewNeighborhood{}
	if neighborhood == nil {
		return preview
	}
	if neighborhood.Root != nil {
		preview.Root = newGraphPreviewNode(neighborhood.Root)
		nodeTypes[neighborhood.Root.URN] = neighborhood.Root.EntityType
	}
	preview.Neighbors = make([]graphPreviewNode, 0, len(neighborhood.Neighbors))
	for _, node := range neighborhood.Neighbors {
		if node == nil {
			continue
		}
		preview.Neighbors = append(preview.Neighbors, newGraphPreviewNode(node))
		nodeTypes[node.URN] = node.EntityType
	}
	preview.Relations = make([]graphPreviewRelation, 0, len(neighborhood.Relations))
	for _, relation := range neighborhood.Relations {
		if relation == nil {
			continue
		}
		preview.Relations = append(preview.Relations, graphPreviewRelation{
			FromURN:  relation.FromURN,
			Relation: relation.Relation,
			ToURN:    relation.ToURN,
			FromType: nodeTypes[relation.FromURN],
			ToType:   nodeTypes[relation.ToURN],
		})
	}
	return preview
}

func newGraphPreviewNode(node *ports.NeighborhoodNode) graphPreviewNode {
	if node == nil {
		return graphPreviewNode{}
	}
	return graphPreviewNode{
		URN:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func neighborhoodHasRelation(neighborhood *ports.EntityNeighborhood, relation string) bool {
	for _, graphRelation := range neighborhood.Relations {
		if graphRelation.Relation == relation {
			return true
		}
	}
	return false
}

func neighborhoodHasTypedRelation(neighborhood *ports.EntityNeighborhood, fromType string, relation string, toType string) bool {
	nodeTypes := map[string]string{}
	if root := neighborhood.Root; root != nil {
		nodeTypes[root.URN] = root.EntityType
	}
	for _, node := range neighborhood.Neighbors {
		nodeTypes[node.URN] = node.EntityType
	}
	for _, graphRelation := range neighborhood.Relations {
		if graphRelation.Relation != relation {
			continue
		}
		if nodeTypes[graphRelation.FromURN] == fromType && nodeTypes[graphRelation.ToURN] == toType {
			return true
		}
	}
	return false
}

type githubFindingsE2EStore struct {
	runtime  *cerebrov1.SourceRuntime
	findings map[string]*ports.FindingRecord
	runs     map[string]*cerebrov1.FindingEvaluationRun
	evidence map[string]*cerebrov1.FindingEvidence
}

func newGitHubFindingsE2EStore(runtime *cerebrov1.SourceRuntime) *githubFindingsE2EStore {
	return &githubFindingsE2EStore{
		runtime:  proto.Clone(runtime).(*cerebrov1.SourceRuntime),
		findings: map[string]*ports.FindingRecord{},
		runs:     map[string]*cerebrov1.FindingEvaluationRun{},
		evidence: map[string]*cerebrov1.FindingEvidence{},
	}
}

func (s *githubFindingsE2EStore) Ping(context.Context) error { return nil }

func (s *githubFindingsE2EStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	s.runtime = proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	return nil
}

func (s *githubFindingsE2EStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	if s.runtime == nil || s.runtime.GetId() != strings.TrimSpace(id) {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(s.runtime).(*cerebrov1.SourceRuntime), nil
}

func (s *githubFindingsE2EStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	cloned := cloneE2EFinding(finding)
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) GetFinding(_ context.Context, id string) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	return cloneE2EFinding(finding), nil
}

func (s *githubFindingsE2EStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	findings := make([]*ports.FindingRecord, 0, len(s.findings))
	for _, finding := range s.findings {
		if request.RuntimeID != "" && finding.RuntimeID != request.RuntimeID {
			continue
		}
		if request.RuleID != "" && finding.RuleID != request.RuleID {
			continue
		}
		findings = append(findings, cloneE2EFinding(finding))
	}
	sort.Slice(findings, func(i int, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings, nil
}

func (s *githubFindingsE2EStore) UpdateFindingStatus(_ context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneE2EFinding(finding)
	cloned.Status = strings.TrimSpace(request.Status)
	cloned.StatusReason = strings.TrimSpace(request.Reason)
	cloned.StatusUpdatedAt = request.UpdatedAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) UpdateFindingAssignee(_ context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneE2EFinding(finding)
	cloned.Assignee = strings.TrimSpace(request.Assignee)
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) UpdateFindingDueDate(_ context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneE2EFinding(finding)
	cloned.DueAt = request.DueAt.UTC()
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) AddFindingNote(_ context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneE2EFinding(finding)
	cloned.Notes = append(cloned.Notes, request.Note)
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) LinkFindingTicket(_ context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	finding, ok := s.findings[strings.TrimSpace(request.FindingID)]
	if !ok {
		return nil, ports.ErrFindingNotFound
	}
	cloned := cloneE2EFinding(finding)
	cloned.Tickets = append(cloned.Tickets, request.Ticket)
	s.findings[cloned.ID] = cloned
	return cloneE2EFinding(cloned), nil
}

func (s *githubFindingsE2EStore) PutFindingEvaluationRun(_ context.Context, run *cerebrov1.FindingEvaluationRun) error {
	s.runs[run.GetId()] = proto.Clone(run).(*cerebrov1.FindingEvaluationRun)
	return nil
}

func (s *githubFindingsE2EStore) GetFindingEvaluationRun(_ context.Context, id string) (*cerebrov1.FindingEvaluationRun, error) {
	run, ok := s.runs[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingEvaluationRunNotFound
	}
	return proto.Clone(run).(*cerebrov1.FindingEvaluationRun), nil
}

func (s *githubFindingsE2EStore) ListFindingEvaluationRuns(context.Context, ports.ListFindingEvaluationRunsRequest) ([]*cerebrov1.FindingEvaluationRun, error) {
	runs := make([]*cerebrov1.FindingEvaluationRun, 0, len(s.runs))
	for _, run := range s.runs {
		runs = append(runs, proto.Clone(run).(*cerebrov1.FindingEvaluationRun))
	}
	return runs, nil
}

func (s *githubFindingsE2EStore) PutFindingEvidence(_ context.Context, evidence *cerebrov1.FindingEvidence) error {
	s.evidence[evidence.GetId()] = proto.Clone(evidence).(*cerebrov1.FindingEvidence)
	return nil
}

func (s *githubFindingsE2EStore) GetFindingEvidence(_ context.Context, id string) (*cerebrov1.FindingEvidence, error) {
	evidence, ok := s.evidence[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrFindingEvidenceNotFound
	}
	return proto.Clone(evidence).(*cerebrov1.FindingEvidence), nil
}

func (s *githubFindingsE2EStore) ListFindingEvidence(context.Context, ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	evidence := make([]*cerebrov1.FindingEvidence, 0, len(s.evidence))
	for _, value := range s.evidence {
		evidence = append(evidence, proto.Clone(value).(*cerebrov1.FindingEvidence))
	}
	return evidence, nil
}

func (s *githubFindingsE2EStore) UpsertClaim(_ context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	return claim, nil
}

func (s *githubFindingsE2EStore) ListClaims(context.Context, ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	return nil, nil
}

func readDependabotAlertsForLiveFinding(ctx context.Context, ops *sourceops.Service, config map[string]string) (*cerebrov1.ReadSourceResponse, string, bool, error) {
	for _, state := range []string{"open", "fixed", "dismissed", "auto_dismissed"} {
		requestConfig := cloneStringMap(config)
		requestConfig["state"] = state
		response, err := ops.Read(ctx, &cerebrov1.ReadSourceRequest{
			SourceId: githubSourceID,
			Config:   requestConfig,
		})
		if err != nil {
			return nil, "", false, err
		}
		if len(response.GetEvents()) != 0 {
			return response, state, state != "open", nil
		}
	}
	return &cerebrov1.ReadSourceResponse{}, "", false, nil
}

func synthesizeOpenDependabotEvents(t *testing.T, events []*cerebrov1.EventEnvelope, liveState string) {
	t.Helper()
	for _, event := range events {
		if event == nil || event.GetKind() != "github.dependabot_alert" {
			continue
		}
		if event.Attributes == nil {
			event.Attributes = map[string]string{}
		}
		event.Attributes["live_state"] = strings.TrimSpace(liveState)
		event.Attributes["state"] = "open"
		payload := map[string]any{}
		if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
			t.Fatalf("unmarshal Dependabot alert payload for %q: %v", event.GetId(), err)
		}
		payload["live_state"] = strings.TrimSpace(liveState)
		payload["state"] = "open"
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal Dependabot alert payload for %q: %v", event.GetId(), err)
		}
		event.Payload = payloadBytes
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneEventsForRuntime(events []*cerebrov1.EventEnvelope, runtimeID string) []*cerebrov1.EventEnvelope {
	cloned := make([]*cerebrov1.EventEnvelope, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		value := proto.Clone(event).(*cerebrov1.EventEnvelope)
		if value.Attributes == nil {
			value.Attributes = map[string]string{}
		}
		value.Attributes[ports.EventAttributeSourceRuntimeID] = strings.TrimSpace(runtimeID)
		cloned = append(cloned, value)
	}
	return cloned
}

func cloneE2EFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := append([]string(nil), finding.ResourceURNs...)
	eventIDs := append([]string(nil), finding.EventIDs...)
	observedPolicyIDs := append([]string(nil), finding.ObservedPolicyIDs...)
	controlRefs := append([]ports.FindingControlRef(nil), finding.ControlRefs...)
	notes := append([]ports.FindingNote(nil), finding.Notes...)
	tickets := append([]ports.FindingTicket(nil), finding.Tickets...)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantID:          finding.TenantID,
		RuntimeID:         finding.RuntimeID,
		RuleID:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            finding.Status,
		Summary:           finding.Summary,
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       controlRefs,
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           notes,
			Tickets:         tickets,
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt.UTC(),
		LastObservedAt:  finding.LastObservedAt.UTC(),
	}
}

var _ ports.SourceRuntimeStore = (*githubFindingsE2EStore)(nil)
var _ ports.EventReplayer = (*githubFindingsE2EReplayer)(nil)
var _ ports.FindingStore = (*githubFindingsE2EStore)(nil)
var _ ports.FindingEvaluationRunStore = (*githubFindingsE2EStore)(nil)
var _ ports.FindingEvidenceStore = (*githubFindingsE2EStore)(nil)
var _ ports.ClaimStore = (*githubFindingsE2EStore)(nil)
