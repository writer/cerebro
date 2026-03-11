package graph

import "testing"

func TestAnalyzeMeetingInsights_DetectsMissingRedundantAndFragile(t *testing.T) {
	g := buildMeetingOptimizationFixtureGraph()
	report := AnalyzeMeetingInsights(g, "")

	if len(report.Meetings) != 3 {
		t.Fatalf("expected 3 meeting insights, got %d", len(report.Meetings))
	}

	var sprintPlanning *MeetingInsight
	for i := range report.Meetings {
		if report.Meetings[i].MeetingID == "activity:meeting-1" {
			sprintPlanning = &report.Meetings[i]
			break
		}
	}
	if sprintPlanning == nil {
		t.Fatal("expected activity:meeting-1 insight")
	}
	if !containsString(sprintPlanning.TopicSystems, "system:payments") {
		t.Fatalf("expected payments topic system, got %+v", sprintPlanning.TopicSystems)
	}
	if containsString(sprintPlanning.TopicSystems, "system:billing") {
		t.Fatalf("did not expect billing as dominant topic, got %+v", sprintPlanning.TopicSystems)
	}
	if !containsMissingPerson(sprintPlanning.MissingPeople, "person:carol@example.com") {
		t.Fatalf("expected carol to be suggested as missing participant, got %+v", sprintPlanning.MissingPeople)
	}
	if !containsString(sprintPlanning.UnnecessaryPeople, "person:eve@example.com") {
		t.Fatalf("expected eve to be marked unnecessary, got %+v (topics=%+v attendees=%+v)", sprintPlanning.UnnecessaryPeople, sprintPlanning.TopicSystems, sprintPlanning.Attendees)
	}

	if len(report.RedundantMeetings) == 0 {
		t.Fatalf("expected redundant meeting pairs")
	}
	if !hasPair(report.RedundantMeetings, "activity:meeting-1", "activity:meeting-2") {
		t.Fatalf("expected meeting-1 and meeting-2 to be redundant, got %+v", report.RedundantMeetings)
	}

	if len(report.FragileBridges) == 0 {
		t.Fatalf("expected fragile bridges")
	}
	if !containsFragileMeeting(report.FragileBridges, "activity:meeting-1") {
		t.Fatalf("expected meeting-1 fragile bridge signal, got %+v", report.FragileBridges)
	}

	if report.Metrics.RecoverableHours <= 0 {
		t.Fatalf("expected recoverable meeting hours, got %.2f", report.Metrics.RecoverableHours)
	}
	if report.Metrics.FragileBridgeMeetings <= 0 {
		t.Fatalf("expected fragile bridge meeting count, got %d", report.Metrics.FragileBridgeMeetings)
	}
}

func TestAnalyzeMeetingByID_ReturnsDetailedContext(t *testing.T) {
	g := buildMeetingOptimizationFixtureGraph()
	analysis := AnalyzeMeetingByID(g, "activity:meeting-1")
	if analysis == nil {
		t.Fatal("expected meeting analysis")
	}
	if analysis.Meeting.MeetingID != "activity:meeting-1" {
		t.Fatalf("unexpected meeting analysis id: %s", analysis.Meeting.MeetingID)
	}
	if len(analysis.RedundantWith) == 0 {
		t.Fatalf("expected redundant-with entries")
	}
	if len(analysis.FragileBridges) == 0 {
		t.Fatalf("expected fragile bridge entries")
	}

	missing := AnalyzeMeetingByID(g, "activity:missing")
	if missing != nil {
		t.Fatalf("expected nil analysis for unknown meeting")
	}
}

func TestAnalyzeMeetingInsights_TeamFilter(t *testing.T) {
	g := buildMeetingOptimizationFixtureGraph()
	report := AnalyzeMeetingInsights(g, "support")
	if len(report.Meetings) != 2 {
		t.Fatalf("expected 2 support meetings, got %d", len(report.Meetings))
	}
	for _, meeting := range report.Meetings {
		if meeting.MeetingID == "activity:meeting-3" {
			t.Fatalf("meeting-3 should be filtered out for support team")
		}
	}
}

func buildMeetingOptimizationFixtureGraph() *Graph {
	g := New()

	g.AddNode(&Node{ID: "department:support", Kind: NodeKindDepartment, Name: "Support"})
	g.AddNode(&Node{ID: "department:engineering", Kind: NodeKindDepartment, Name: "Engineering"})
	g.AddNode(&Node{ID: "department:product", Kind: NodeKindDepartment, Name: "Product"})

	g.AddNode(&Node{ID: "person:alice@example.com", Kind: NodeKindPerson, Name: "Alice", Properties: map[string]any{"department": "support"}})
	g.AddNode(&Node{ID: "person:bob@example.com", Kind: NodeKindPerson, Name: "Bob", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&Node{ID: "person:carol@example.com", Kind: NodeKindPerson, Name: "Carol", Properties: map[string]any{"department": "engineering"}})
	g.AddNode(&Node{ID: "person:dave@example.com", Kind: NodeKindPerson, Name: "Dave", Properties: map[string]any{"department": "product"}})
	g.AddNode(&Node{ID: "person:eve@example.com", Kind: NodeKindPerson, Name: "Eve", Properties: map[string]any{"department": "support"}})

	g.AddNode(&Node{ID: "system:payments", Kind: NodeKindApplication, Name: "payments"})
	g.AddNode(&Node{ID: "system:billing", Kind: NodeKindApplication, Name: "billing"})

	g.AddEdge(&Edge{ID: "m-alice", Source: "person:alice@example.com", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m-bob", Source: "person:bob@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m-carol", Source: "person:carol@example.com", Target: "department:engineering", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m-dave", Source: "person:dave@example.com", Target: "department:product", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "m-eve", Source: "person:eve@example.com", Target: "department:support", Kind: EdgeKindMemberOf, Effect: EdgeEffectAllow})

	g.AddEdge(&Edge{ID: "sys-a", Source: "person:alice@example.com", Target: "system:payments", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "sys-b", Source: "person:bob@example.com", Target: "system:payments", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "sys-c", Source: "person:carol@example.com", Target: "system:payments", Kind: EdgeKindOwns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "sys-d", Source: "person:dave@example.com", Target: "system:billing", Kind: EdgeKindManagedBy, Effect: EdgeEffectAllow})

	g.AddEdge(&Edge{ID: "i-ab", Source: "person:alice@example.com", Target: "person:bob@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 10}})
	g.AddEdge(&Edge{ID: "i-bd", Source: "person:bob@example.com", Target: "person:dave@example.com", Kind: EdgeKindInteractedWith, Effect: EdgeEffectAllow, Properties: map[string]any{"frequency": 6}})

	g.AddNode(&Node{ID: "activity:meeting-1", Kind: NodeKindActivity, Name: "Weekly Payments Sync", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 60, "attendees": []string{"person:alice@example.com", "person:bob@example.com", "person:dave@example.com", "person:eve@example.com"}}})
	g.AddNode(&Node{ID: "activity:meeting-2", Kind: NodeKindActivity, Name: "Payments Triage", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 45, "attendees": []string{"person:alice@example.com", "person:bob@example.com"}}})
	g.AddNode(&Node{ID: "activity:meeting-3", Kind: NodeKindActivity, Name: "Billing Product Review", Properties: map[string]any{"activity_type": "meeting", "duration_minutes": 30, "attendees": []string{"person:bob@example.com", "person:dave@example.com"}}})

	g.AddEdge(&Edge{ID: "meet1-a", Source: "activity:meeting-1", Target: "person:alice@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet1-b", Source: "activity:meeting-1", Target: "person:bob@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet1-d", Source: "activity:meeting-1", Target: "person:dave@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet1-e", Source: "activity:meeting-1", Target: "person:eve@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet2-a", Source: "activity:meeting-2", Target: "person:alice@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet2-b", Source: "activity:meeting-2", Target: "person:bob@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet3-b", Source: "activity:meeting-3", Target: "person:bob@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "meet3-d", Source: "activity:meeting-3", Target: "person:dave@example.com", Kind: EdgeKindAssignedTo, Effect: EdgeEffectAllow})

	return g
}

func containsMissingPerson(items []MissingParticipant, personID string) bool {
	for _, item := range items {
		if item.PersonID == personID {
			return true
		}
	}
	return false
}

func hasPair(items []RedundantMeetingPair, meetingA, meetingB string) bool {
	for _, item := range items {
		if (item.MeetingA == meetingA && item.MeetingB == meetingB) || (item.MeetingA == meetingB && item.MeetingB == meetingA) {
			return true
		}
	}
	return false
}

func containsFragileMeeting(items []FragileBridge, meetingID string) bool {
	for _, item := range items {
		if item.MeetingID == meetingID {
			return true
		}
	}
	return false
}
