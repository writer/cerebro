package graph

import (
	"math"
	"sort"
	"strings"
)

// MeetingInsight summarizes participant and topic quality for one meeting.
type MeetingInsight struct {
	MeetingID         string               `json:"meeting_id"`
	MissingPeople     []MissingParticipant `json:"missing_people,omitempty"`
	UnnecessaryPeople []string             `json:"unnecessary_people,omitempty"`
	TopicSystems      []string             `json:"topic_systems,omitempty"`
	DurationMinutes   int                  `json:"duration_minutes"`
	Attendees         []string             `json:"attendees,omitempty"`
}

// MissingParticipant is a person who should likely be in the room.
type MissingParticipant struct {
	PersonID   string  `json:"person_id"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

// RedundantMeetingPair captures two meetings that can likely be consolidated.
type RedundantMeetingPair struct {
	MeetingA         string  `json:"meeting_a"`
	MeetingB         string  `json:"meeting_b"`
	AttendeeOverlap  float64 `json:"attendee_overlap"`
	TopicOverlap     float64 `json:"topic_overlap"`
	CombinedDuration int     `json:"combined_duration"`
	Recommendation   string  `json:"recommendation"`
}

// FragileBridge identifies a meeting that is the only communication bridge between teams.
type FragileBridge struct {
	MeetingID        string `json:"meeting_id"`
	TeamA            string `json:"team_a"`
	TeamB            string `json:"team_b"`
	AlternativePaths int    `json:"alternative_paths"`
	Risk             string `json:"risk"`
}

// MeetingOptimizationMetrics provides aggregate metrics for meeting optimization.
type MeetingOptimizationMetrics struct {
	TotalMeetingHoursPerPerson map[string]float64 `json:"total_meeting_hours_per_person,omitempty"`
	ZeroTopicParticipantPct    float64            `json:"zero_topic_participant_pct"`
	FragileBridgeMeetings      int                `json:"fragile_bridge_meetings"`
	RecoverableHours           float64            `json:"recoverable_hours"`
}

// MeetingInsightsReport is the aggregate result for org meeting optimization analytics.
type MeetingInsightsReport struct {
	Meetings          []MeetingInsight           `json:"meetings,omitempty"`
	RedundantMeetings []RedundantMeetingPair     `json:"redundant_meetings,omitempty"`
	FragileBridges    []FragileBridge            `json:"fragile_bridges,omitempty"`
	Metrics           MeetingOptimizationMetrics `json:"metrics"`
}

// MeetingAnalysis is the per-meeting analysis payload.
type MeetingAnalysis struct {
	Meeting        MeetingInsight         `json:"meeting"`
	RedundantWith  []RedundantMeetingPair `json:"redundant_with,omitempty"`
	FragileBridges []FragileBridge        `json:"fragile_bridges,omitempty"`
}

type meetingRecord struct {
	ID          string
	DurationMin int
	AttendeeIDs []string
}

// AnalyzeMeetingInsights computes meeting optimization insights, optionally filtered by team.
func AnalyzeMeetingInsights(g *Graph, teamFilter string) MeetingInsightsReport {
	report := MeetingInsightsReport{
		Metrics: MeetingOptimizationMetrics{
			TotalMeetingHoursPerPerson: make(map[string]float64),
		},
	}
	if g == nil {
		return report
	}

	records := collectMeetingRecords(g)
	if len(records) == 0 {
		return report
	}
	if strings.TrimSpace(teamFilter) != "" {
		records = filterMeetingRecordsByTeam(g, records, teamFilter)
	}
	if len(records) == 0 {
		return report
	}

	insights := make([]MeetingInsight, 0, len(records))
	for _, record := range records {
		insights = append(insights, analyzeMeetingRecord(g, record))
	}
	redundant := detectRedundantMeetings(records, insights)
	fragile := detectFragileMeetingBridges(g, records)
	metrics := computeMeetingOptimizationMetrics(records, insights, redundant, fragile)

	report.Meetings = insights
	report.RedundantMeetings = redundant
	report.FragileBridges = fragile
	report.Metrics = metrics
	return report
}

// AnalyzeMeetingByID computes detailed analysis for one meeting ID.
func AnalyzeMeetingByID(g *Graph, meetingID string) *MeetingAnalysis {
	if g == nil {
		return nil
	}
	meetingID = strings.TrimSpace(meetingID)
	if meetingID == "" {
		return nil
	}

	records := collectMeetingRecords(g)
	if len(records) == 0 {
		return nil
	}
	var target meetingRecord
	found := false
	for _, record := range records {
		if record.ID == meetingID {
			target = record
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	insight := analyzeMeetingRecord(g, target)
	topicsByMeeting := make(map[string][]string, len(records))
	topicsByMeeting[target.ID] = append([]string(nil), insight.TopicSystems...)
	for _, record := range records {
		if record.ID == target.ID {
			continue
		}
		topicsByMeeting[record.ID] = inferMeetingTopicSystems(g, record.AttendeeIDs)
	}

	redundant := detectRedundantMeetingsForMeeting(records, topicsByMeeting, target.ID)
	membersByTeam, namesByTeam := departmentMembersByID(g)
	departments := departmentsByPerson(g)
	fragile := fragileMeetingBridgesForRecord(g, target, membersByTeam, namesByTeam, departments)

	return &MeetingAnalysis{
		Meeting:        insight,
		RedundantWith:  redundant,
		FragileBridges: fragile,
	}
}

func analyzeMeetingRecord(g *Graph, record meetingRecord) MeetingInsight {
	insight := MeetingInsight{
		MeetingID:       record.ID,
		DurationMinutes: record.DurationMin,
		Attendees:       append([]string(nil), record.AttendeeIDs...),
	}
	if g == nil {
		return insight
	}

	topicSystems := inferMeetingTopicSystems(g, record.AttendeeIDs)
	insight.TopicSystems = topicSystems
	insight.MissingPeople = inferMissingParticipants(g, topicSystems, record.AttendeeIDs)
	insight.UnnecessaryPeople = inferUnnecessaryParticipants(g, topicSystems, record.AttendeeIDs)
	return insight
}

func collectMeetingRecords(g *Graph) []meetingRecord {
	if g == nil {
		return nil
	}

	records := make([]meetingRecord, 0)
	for _, node := range g.GetNodesByKind(NodeKindActivity) {
		if node == nil || !isMeetingActivity(node) {
			continue
		}
		record := meetingRecord{
			ID:          node.ID,
			DurationMin: meetingDurationMinutes(node),
		}
		record.AttendeeIDs = meetingAttendees(g, node)
		if len(record.AttendeeIDs) == 0 {
			continue
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records
}

func filterMeetingRecordsByTeam(g *Graph, records []meetingRecord, teamFilter string) []meetingRecord {
	if g == nil || len(records) == 0 {
		return nil
	}
	filtered := make([]meetingRecord, 0, len(records))
	for _, record := range records {
		for _, attendee := range record.AttendeeIDs {
			if infoFlowPersonMatchesDepartment(g, attendee, teamFilter) {
				filtered = append(filtered, record)
				break
			}
		}
	}
	return filtered
}

func inferMeetingTopicSystems(g *Graph, attendees []string) []string {
	if g == nil || len(attendees) == 0 {
		return nil
	}

	support := make(map[string]int)
	for _, attendee := range attendees {
		for _, systemID := range personSystemTopics(g, attendee) {
			support[systemID]++
		}
	}
	if len(support) == 0 {
		return nil
	}

	threshold := int(math.Ceil(float64(len(attendees)) * 0.50))
	if threshold < 1 {
		threshold = 1
	}
	type scoredSystem struct {
		id    string
		score int
	}
	scored := make([]scoredSystem, 0, len(support))
	for systemID, score := range support {
		scored = append(scored, scoredSystem{id: systemID, score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].id < scored[j].id
		}
		return scored[i].score > scored[j].score
	})

	topics := make([]string, 0)
	for _, item := range scored {
		if item.score >= threshold {
			topics = append(topics, item.id)
		}
	}
	if len(topics) == 0 {
		topics = append(topics, scored[0].id)
	}
	if len(topics) > 6 {
		topics = topics[:6]
	}
	sort.Strings(topics)
	return topics
}

func personSystemTopics(g *Graph, personID string) []string {
	if g == nil || strings.TrimSpace(personID) == "" {
		return nil
	}
	topics := make(map[string]struct{})
	collect := func(otherID string, edge *Edge) {
		if edge == nil || strings.TrimSpace(otherID) == "" {
			return
		}
		other, ok := g.GetNode(otherID)
		if !ok || other == nil || !isSystemNodeKind(other.Kind) {
			return
		}
		if !isSystemKnowledgeEdge(edge.Kind) {
			return
		}
		topics[other.ID] = struct{}{}
	}
	for _, edge := range g.GetOutEdges(personID) {
		collect(edge.Target, edge)
	}
	for _, edge := range g.GetInEdges(personID) {
		collect(edge.Source, edge)
	}
	return sortedSet(topics)
}

func inferMissingParticipants(g *Graph, topicSystems []string, attendees []string) []MissingParticipant {
	if g == nil || len(topicSystems) == 0 {
		return nil
	}
	attendeeSet := make(map[string]struct{}, len(attendees))
	for _, attendee := range attendees {
		attendeeSet[attendee] = struct{}{}
	}

	byPerson := make(map[string]MissingParticipant)
	for _, systemID := range topicSystems {
		systemNode, _ := g.GetNode(systemID)
		systemName := systemID
		if systemNode != nil && strings.TrimSpace(systemNode.Name) != "" {
			systemName = systemNode.Name
		}
		bus := BusFactor(g, systemID)
		for _, personID := range bus.ActivePersonIDs {
			if _, exists := attendeeSet[personID]; exists {
				continue
			}
			conf := participantConfidenceForSystem(g, personID, systemID, bus)
			reason := "Has strong knowledge edge to " + systemName
			if bus.BusFactor <= 1 {
				reason = "Owns critical " + systemName + " knowledge (bus factor 1)"
			}
			current := byPerson[personID]
			if conf > current.Confidence {
				byPerson[personID] = MissingParticipant{PersonID: personID, Reason: reason, Confidence: conf}
			}
		}
	}

	missing := make([]MissingParticipant, 0, len(byPerson))
	for _, participant := range byPerson {
		missing = append(missing, participant)
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Confidence == missing[j].Confidence {
			return missing[i].PersonID < missing[j].PersonID
		}
		return missing[i].Confidence > missing[j].Confidence
	})
	if len(missing) > 8 {
		missing = missing[:8]
	}
	return missing
}

func participantConfidenceForSystem(g *Graph, personID, systemID string, bus BusFactorResult) float64 {
	if g == nil {
		return 0
	}
	confidence := 0.45
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Target != systemID || !isSystemKnowledgeEdge(edge.Kind) {
			continue
		}
		confidence += 0.25
		if edge.Kind == EdgeKindOwns || edge.Kind == EdgeKindManagedBy {
			confidence += 0.15
		}
		confidence += math.Min(readFloat(edge.Properties, "strength", "interaction_frequency")*0.1, 0.1)
	}
	for _, edge := range g.GetInEdges(personID) {
		if edge == nil || edge.Source != systemID || !isSystemKnowledgeEdge(edge.Kind) {
			continue
		}
		confidence += 0.15
	}
	if bus.BusFactor > 0 && bus.BusFactor <= 1 {
		confidence += 0.15
	}
	if confidence > 1 {
		confidence = 1
	}
	return confidence
}

func inferUnnecessaryParticipants(g *Graph, topicSystems []string, attendees []string) []string {
	if g == nil || len(attendees) == 0 {
		return nil
	}
	if len(topicSystems) == 0 {
		copyAttendees := append([]string(nil), attendees...)
		sort.Strings(copyAttendees)
		return copyAttendees
	}

	unnecessary := make([]string, 0)
	for _, attendee := range attendees {
		relevant := false
		for _, systemID := range topicSystems {
			if participantConfidenceForSystem(g, attendee, systemID, BusFactorResult{}) >= 0.55 {
				relevant = true
				break
			}
		}
		if !relevant {
			unnecessary = append(unnecessary, attendee)
		}
	}
	sort.Strings(unnecessary)
	return unnecessary
}

func detectRedundantMeetings(records []meetingRecord, insights []MeetingInsight) []RedundantMeetingPair {
	if len(records) == 0 || len(records) != len(insights) {
		return nil
	}
	byID := make(map[string]MeetingInsight, len(insights))
	recordByID := make(map[string]meetingRecord, len(records))
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
		recordByID[record.ID] = record
	}
	for _, insight := range insights {
		byID[insight.MeetingID] = insight
	}
	sort.Strings(ids)

	pairs := make([]RedundantMeetingPair, 0)
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			aID := ids[i]
			bID := ids[j]
			a := recordByID[aID]
			b := recordByID[bID]
			ai := byID[aID]
			bi := byID[bID]

			attendeeOverlap := overlapRatio(a.AttendeeIDs, b.AttendeeIDs)
			topicOverlap := overlapRatio(ai.TopicSystems, bi.TopicSystems)
			if attendeeOverlap < 0.70 || topicOverlap < 0.50 {
				continue
			}
			pairs = append(pairs, RedundantMeetingPair{
				MeetingA:         aID,
				MeetingB:         bID,
				AttendeeOverlap:  attendeeOverlap,
				TopicOverlap:     topicOverlap,
				CombinedDuration: a.DurationMin + b.DurationMin,
				Recommendation:   "Combine into single recurring sync",
			})
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].CombinedDuration == pairs[j].CombinedDuration {
			if pairs[i].MeetingA == pairs[j].MeetingA {
				return pairs[i].MeetingB < pairs[j].MeetingB
			}
			return pairs[i].MeetingA < pairs[j].MeetingA
		}
		return pairs[i].CombinedDuration > pairs[j].CombinedDuration
	})
	return pairs
}

func detectRedundantMeetingsForMeeting(
	records []meetingRecord,
	topicsByMeeting map[string][]string,
	meetingID string,
) []RedundantMeetingPair {
	if len(records) == 0 || strings.TrimSpace(meetingID) == "" {
		return nil
	}

	recordByID := make(map[string]meetingRecord, len(records))
	for _, record := range records {
		recordByID[record.ID] = record
	}
	target, ok := recordByID[meetingID]
	if !ok {
		return nil
	}

	meetingIDs := make([]string, 0, len(recordByID)-1)
	for id := range recordByID {
		if id == meetingID {
			continue
		}
		meetingIDs = append(meetingIDs, id)
	}
	sort.Strings(meetingIDs)

	pairs := make([]RedundantMeetingPair, 0)
	for _, otherID := range meetingIDs {
		other := recordByID[otherID]
		attendeeOverlap := overlapRatio(target.AttendeeIDs, other.AttendeeIDs)
		topicOverlap := overlapRatio(topicsByMeeting[meetingID], topicsByMeeting[otherID])
		if attendeeOverlap < 0.70 || topicOverlap < 0.50 {
			continue
		}
		meetingA := meetingID
		meetingB := otherID
		if meetingB < meetingA {
			meetingA, meetingB = meetingB, meetingA
		}
		pairs = append(pairs, RedundantMeetingPair{
			MeetingA:         meetingA,
			MeetingB:         meetingB,
			AttendeeOverlap:  attendeeOverlap,
			TopicOverlap:     topicOverlap,
			CombinedDuration: target.DurationMin + other.DurationMin,
			Recommendation:   "Combine into single recurring sync",
		})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].CombinedDuration == pairs[j].CombinedDuration {
			if pairs[i].MeetingA == pairs[j].MeetingA {
				return pairs[i].MeetingB < pairs[j].MeetingB
			}
			return pairs[i].MeetingA < pairs[j].MeetingA
		}
		return pairs[i].CombinedDuration > pairs[j].CombinedDuration
	})
	return pairs
}

func detectFragileMeetingBridges(g *Graph, records []meetingRecord) []FragileBridge {
	if g == nil || len(records) == 0 {
		return nil
	}
	membersByTeam, namesByTeam := departmentMembersByID(g)
	departments := departmentsByPerson(g)

	fragile := make([]FragileBridge, 0)
	for _, record := range records {
		fragile = append(fragile, fragileMeetingBridgesForRecord(g, record, membersByTeam, namesByTeam, departments)...)
	}

	sort.Slice(fragile, func(i, j int) bool {
		if fragile[i].MeetingID == fragile[j].MeetingID {
			if fragile[i].TeamA == fragile[j].TeamA {
				return fragile[i].TeamB < fragile[j].TeamB
			}
			return fragile[i].TeamA < fragile[j].TeamA
		}
		return fragile[i].MeetingID < fragile[j].MeetingID
	})
	return fragile
}

func fragileMeetingBridgesForRecord(
	g *Graph,
	record meetingRecord,
	membersByTeam map[string]map[string]struct{},
	namesByTeam map[string]string,
	departments map[string]map[string]struct{},
) []FragileBridge {
	if g == nil || strings.TrimSpace(record.ID) == "" || len(record.AttendeeIDs) == 0 {
		return nil
	}

	attendeeTeams := make(map[string]map[string]struct{})
	for _, attendee := range record.AttendeeIDs {
		for teamID := range departments[attendee] {
			if _, exists := attendeeTeams[teamID]; !exists {
				attendeeTeams[teamID] = make(map[string]struct{})
			}
			attendeeTeams[teamID][attendee] = struct{}{}
		}
	}
	teamIDs := make([]string, 0, len(attendeeTeams))
	for teamID := range attendeeTeams {
		teamIDs = append(teamIDs, teamID)
	}
	sort.Strings(teamIDs)
	if len(teamIDs) < 2 {
		return nil
	}

	fragile := make([]FragileBridge, 0)
	for i := 0; i < len(teamIDs); i++ {
		for j := i + 1; j < len(teamIDs); j++ {
			teamA := teamIDs[i]
			teamB := teamIDs[j]
			totalInteractions := interactionEdgesBetweenMemberSets(g, membersByTeam[teamA], membersByTeam[teamB])
			if totalInteractions == 0 {
				continue
			}
			meetingInteractions := interactionEdgesBetweenMemberSets(g, attendeeTeams[teamA], attendeeTeams[teamB])
			alternative := totalInteractions - meetingInteractions
			if alternative < 0 {
				alternative = 0
			}
			if alternative > 0 {
				continue
			}
			fragile = append(fragile, FragileBridge{
				MeetingID:        record.ID,
				TeamA:            firstNonEmpty(namesByTeam[teamA], teamA),
				TeamB:            firstNonEmpty(namesByTeam[teamB], teamB),
				AlternativePaths: alternative,
				Risk:             "Only communication channel between teams represented in this meeting",
			})
		}
	}
	return fragile
}

func computeMeetingOptimizationMetrics(
	records []meetingRecord,
	insights []MeetingInsight,
	redundant []RedundantMeetingPair,
	fragile []FragileBridge,
) MeetingOptimizationMetrics {
	metrics := MeetingOptimizationMetrics{TotalMeetingHoursPerPerson: make(map[string]float64)}
	if len(records) == 0 {
		return metrics
	}

	totalAttendeeSlots := 0
	zeroTopicSlots := 0
	for _, insight := range insights {
		recordDuration := 0
		for _, record := range records {
			if record.ID == insight.MeetingID {
				recordDuration = record.DurationMin
				break
			}
		}
		hours := float64(recordDuration) / 60.0
		for _, attendee := range insight.Attendees {
			metrics.TotalMeetingHoursPerPerson[attendee] += hours
			totalAttendeeSlots++
		}
		zeroTopicSlots += len(insight.UnnecessaryPeople)
	}

	if totalAttendeeSlots > 0 {
		metrics.ZeroTopicParticipantPct = float64(zeroTopicSlots) * 100 / float64(totalAttendeeSlots)
	}

	fragileMeetings := make(map[string]struct{})
	for _, bridge := range fragile {
		fragileMeetings[bridge.MeetingID] = struct{}{}
	}
	metrics.FragileBridgeMeetings = len(fragileMeetings)

	recoverableMinutes := 0
	for _, pair := range redundant {
		recoverableMinutes += pair.CombinedDuration
	}
	metrics.RecoverableHours = float64(recoverableMinutes) / 60.0
	return metrics
}

func overlapRatio(a []string, b []string) float64 {
	setA := make(map[string]struct{}, len(a))
	setB := make(map[string]struct{}, len(b))
	for _, item := range a {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		setA[item] = struct{}{}
	}
	for _, item := range b {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		setB[item] = struct{}{}
	}
	if len(setA) == 0 || len(setB) == 0 {
		return 0
	}
	intersection := 0
	for item := range setA {
		if _, ok := setB[item]; ok {
			intersection++
		}
	}
	smaller := len(setA)
	if len(setB) < smaller {
		smaller = len(setB)
	}
	if smaller == 0 {
		return 0
	}
	return float64(intersection) / float64(smaller)
}

func meetingAttendees(g *Graph, meeting *Node) []string {
	attendees := make(map[string]struct{})
	if g == nil || meeting == nil {
		return nil
	}

	for _, raw := range stringSliceFromValue(meeting.Properties["attendees"]) {
		if personID := resolveReorgPersonID(g, raw); personID != "" {
			attendees[personID] = struct{}{}
		}
	}
	for _, raw := range stringSliceFromValue(meeting.Properties["participants"]) {
		if personID := resolveReorgPersonID(g, raw); personID != "" {
			attendees[personID] = struct{}{}
		}
	}

	for _, edge := range g.GetOutEdges(meeting.ID) {
		if edge == nil {
			continue
		}
		if person, ok := g.GetNode(edge.Target); ok && person != nil && person.Kind == NodeKindPerson {
			attendees[person.ID] = struct{}{}
		}
	}
	for _, edge := range g.GetInEdges(meeting.ID) {
		if edge == nil {
			continue
		}
		if person, ok := g.GetNode(edge.Source); ok && person != nil && person.Kind == NodeKindPerson {
			attendees[person.ID] = struct{}{}
		}
	}

	return sortedSet(attendees)
}

func meetingDurationMinutes(meeting *Node) int {
	if meeting == nil {
		return 30
	}
	duration := readInt(meeting.Properties, "duration_minutes", "duration", "meeting_minutes", "length_minutes")
	if duration <= 0 {
		duration = 30
	}
	if duration > 24*60 {
		duration = 24 * 60
	}
	return duration
}

func isMeetingActivity(node *Node) bool {
	if node == nil || node.Kind != NodeKindActivity {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(readString(node.Properties, "activity_type", "type", "kind", "category")))
	name := strings.ToLower(strings.TrimSpace(firstNonEmpty(node.Name, readString(node.Properties, "title", "subject"))))
	if strings.Contains(kind, "meeting") || strings.Contains(kind, "calendar") || strings.Contains(kind, "sync") || strings.Contains(kind, "call") {
		return true
	}
	meetingHints := []string{"meeting", "sync", "standup", "retro", "review", "planning", "all-hands"}
	for _, hint := range meetingHints {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return len(stringSliceFromValue(node.Properties["attendees"])) > 0
}

func isSystemKnowledgeEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindOwns, EdgeKindManagedBy, EdgeKindAssignedTo, EdgeKindCanWrite, EdgeKindCanAdmin, EdgeKindCanRead:
		return true
	default:
		return false
	}
}
