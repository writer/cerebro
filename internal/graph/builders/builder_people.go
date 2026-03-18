package builders

import (
	"context"
	"sort"
	"strings"
	"unicode"
)

type personAggregate struct {
	Emails          map[string]struct{}
	SourceNodeIDs   map[string]struct{}
	Providers       map[string]struct{}
	ProviderIDs     map[string]string
	Name            string
	PrimaryEmail    string
	IsExternal      bool
	HasHRRecord     bool
	EmployeeID      string
	ManagerEmployee string
	Department      string
	Location        string
	Title           string
	Status          string
	StartDate       string
}

func newPersonAggregate(email string) *personAggregate {
	agg := &personAggregate{
		Emails:        make(map[string]struct{}),
		SourceNodeIDs: make(map[string]struct{}),
		Providers:     make(map[string]struct{}),
		ProviderIDs:   make(map[string]string),
		IsExternal:    true,
	}
	if email != "" {
		agg.Emails[email] = struct{}{}
		agg.PrimaryEmail = email
	}
	return agg
}

func (b *Builder) buildUnifiedPersonGraph(ctx context.Context) {
	b.clearUnifiedOrgNodes()

	baseEdges := b.graph.GetAllEdges()
	aggregates := make(map[*personAggregate]struct{})
	emailIndex := make(map[string]*personAggregate)
	sourceIndex := make(map[string]*personAggregate)

	getByEmail := func(email string) *personAggregate {
		email = normalizePersonEmail(email)
		if email == "" {
			return nil
		}
		if agg, ok := emailIndex[email]; ok && agg != nil {
			return agg
		}
		agg := newPersonAggregate(email)
		aggregates[agg] = struct{}{}
		emailIndex[email] = agg
		return agg
	}

	mergeAggregates := func(dst *personAggregate, src *personAggregate) *personAggregate {
		if dst == nil {
			return src
		}
		if src == nil || src == dst {
			return dst
		}

		for email := range src.Emails {
			dst.Emails[email] = struct{}{}
			emailIndex[email] = dst
		}
		for sourceID := range src.SourceNodeIDs {
			dst.SourceNodeIDs[sourceID] = struct{}{}
			sourceIndex[sourceID] = dst
		}
		for provider := range src.Providers {
			dst.Providers[provider] = struct{}{}
		}
		for key, value := range src.ProviderIDs {
			if _, exists := dst.ProviderIDs[key]; !exists && value != "" {
				dst.ProviderIDs[key] = value
			}
		}
		if dst.Name == "" && src.Name != "" {
			dst.Name = src.Name
		}
		if dst.PrimaryEmail == "" && src.PrimaryEmail != "" {
			dst.PrimaryEmail = src.PrimaryEmail
		}
		if src.HasHRRecord && !dst.HasHRRecord {
			dst.HasHRRecord = true
			dst.IsExternal = false
			dst.EmployeeID = src.EmployeeID
			dst.ManagerEmployee = src.ManagerEmployee
			dst.Department = src.Department
			dst.Location = src.Location
			dst.Title = src.Title
			dst.Status = src.Status
			dst.StartDate = src.StartDate
			if src.PrimaryEmail != "" {
				dst.PrimaryEmail = src.PrimaryEmail
			}
		}
		dst.IsExternal = dst.IsExternal && src.IsExternal
		delete(aggregates, src)
		return dst
	}

	for _, node := range b.graph.GetNodesByKind(NodeKindUser) {
		email := primaryPersonEmailFromNode(node)
		if email == "" || looksLikeServiceAccountEmail(email) {
			continue
		}

		agg := getByEmail(email)
		if agg == nil {
			continue
		}
		agg.SourceNodeIDs[node.ID] = struct{}{}
		sourceIndex[node.ID] = agg
		if node.Provider != "" {
			agg.Providers[node.Provider] = struct{}{}
		}
		if agg.Name == "" && strings.TrimSpace(node.Name) != "" {
			agg.Name = strings.TrimSpace(node.Name)
		}
		if agg.PrimaryEmail == "" {
			agg.PrimaryEmail = email
		}
		for key, value := range providerIdentityKeys(node) {
			if value == "" {
				continue
			}
			if _, exists := agg.ProviderIDs[key]; !exists {
				agg.ProviderIDs[key] = value
			}
		}
	}

	b.enrichPeopleFromRippling(ctx, aggregates, emailIndex, getByEmail, mergeAggregates)

	if len(aggregates) == 0 {
		return
	}

	personIDByAggregate := make(map[*personAggregate]string, len(aggregates))
	personIDBySource := make(map[string]string)
	personIDByEmployee := make(map[string]string)

	nodes := make([]*Node, 0, len(aggregates))
	departmentNodes := make(map[string]*Node)
	locationNodes := make(map[string]*Node)

	for agg := range aggregates {
		preferredEmail := agg.PrimaryEmail
		if preferredEmail == "" {
			preferredEmail = firstSortedEmail(agg.Emails)
		}
		if preferredEmail == "" {
			continue
		}

		personID := "person:" + preferredEmail
		personIDByAggregate[agg] = personID
		for sourceID := range agg.SourceNodeIDs {
			personIDBySource[sourceID] = personID
		}
		if agg.EmployeeID != "" {
			personIDByEmployee[agg.EmployeeID] = personID
		}

		name := strings.TrimSpace(agg.Name)
		if name == "" {
			name = preferredEmail
		}

		properties := map[string]any{
			"email":     preferredEmail,
			"emails":    sortedSet(agg.Emails),
			"external":  agg.IsExternal,
			"providers": sortedSet(agg.Providers),
		}
		for key, value := range agg.ProviderIDs {
			if value == "" {
				continue
			}
			properties[key] = value
		}
		if agg.EmployeeID != "" {
			properties["rippling_employee_id"] = agg.EmployeeID
		}
		if agg.Title != "" {
			properties["title"] = agg.Title
		}
		if agg.Department != "" {
			properties["department"] = agg.Department
			departmentID := "department:" + normalizeOrgKey(agg.Department)
			if _, exists := departmentNodes[departmentID]; !exists {
				departmentNodes[departmentID] = &Node{
					ID:       departmentID,
					Kind:     NodeKindDepartment,
					Name:     agg.Department,
					Provider: "org",
				}
			}
		}
		if agg.Location != "" {
			properties["location"] = agg.Location
			locationID := "location:" + normalizeOrgKey(agg.Location)
			if _, exists := locationNodes[locationID]; !exists {
				locationNodes[locationID] = &Node{
					ID:       locationID,
					Kind:     NodeKindLocation,
					Name:     agg.Location,
					Provider: "org",
				}
			}
		}
		if agg.Status != "" {
			properties["status"] = strings.ToLower(strings.TrimSpace(agg.Status))
		}
		if agg.StartDate != "" {
			properties["start_date"] = agg.StartDate
		}
		if len(agg.SourceNodeIDs) > 0 {
			properties["source_node_ids"] = sortedSet(agg.SourceNodeIDs)
		}

		nodes = append(nodes, &Node{
			ID:         personID,
			Kind:       NodeKindPerson,
			Name:       name,
			Provider:   "org",
			Properties: properties,
		})
	}

	for _, node := range departmentNodes {
		nodes = append(nodes, node)
	}
	for _, node := range locationNodes {
		nodes = append(nodes, node)
	}

	b.graph.AddNodesBatch(nodes)

	edges := make([]*Edge, 0)
	seenProjected := make(map[string]struct{})

	for sourceID, personID := range personIDBySource {
		edges = append(edges, &Edge{
			ID:     "resolve:" + sourceID + "->" + personID,
			Source: sourceID,
			Target: personID,
			Kind:   EdgeKindResolvesTo,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"cross_system": true,
			},
		})
	}

	for agg := range aggregates {
		personID := personIDByAggregate[agg]
		if personID == "" {
			continue
		}
		if agg.Department != "" {
			departmentID := "department:" + normalizeOrgKey(agg.Department)
			edges = append(edges, &Edge{
				ID:     personID + "->" + departmentID + ":member_of",
				Source: personID,
				Target: departmentID,
				Kind:   EdgeKindMemberOf,
				Effect: EdgeEffectAllow,
			})
		}
		if agg.Location != "" {
			locationID := "location:" + normalizeOrgKey(agg.Location)
			edges = append(edges, &Edge{
				ID:     personID + "->" + locationID + ":located_in",
				Source: personID,
				Target: locationID,
				Kind:   EdgeKindLocatedIn,
				Effect: EdgeEffectAllow,
			})
		}
		if agg.ManagerEmployee != "" {
			if managerPersonID := personIDByEmployee[agg.ManagerEmployee]; managerPersonID != "" && managerPersonID != personID {
				edges = append(edges, &Edge{
					ID:     personID + "->" + managerPersonID + ":reports_to",
					Source: personID,
					Target: managerPersonID,
					Kind:   EdgeKindReportsTo,
					Effect: EdgeEffectAllow,
				})
			}
		}
	}

	for _, edgeList := range baseEdges {
		for _, edge := range edgeList {
			if edge == nil {
				continue
			}
			sourceID := edge.Source
			targetID := edge.Target
			if mappedSource, ok := personIDBySource[sourceID]; ok {
				sourceID = mappedSource
			}
			if mappedTarget, ok := personIDBySource[targetID]; ok {
				targetID = mappedTarget
			}
			if sourceID == edge.Source && targetID == edge.Target {
				continue
			}
			if sourceID == "" || targetID == "" || sourceID == targetID {
				continue
			}

			dedupeKey := strings.Join([]string{string(edge.Kind), string(edge.Effect), sourceID, targetID}, "|")
			if _, exists := seenProjected[dedupeKey]; exists {
				continue
			}
			seenProjected[dedupeKey] = struct{}{}

			properties := cloneAnyMap(edge.Properties)
			if properties == nil {
				properties = make(map[string]any)
			}
			properties["person_projected"] = true
			if edge.ID != "" {
				properties["derived_from_edge"] = edge.ID
			}

			edges = append(edges, &Edge{
				ID:         "projected:" + dedupeKey,
				Source:     sourceID,
				Target:     targetID,
				Kind:       edge.Kind,
				Effect:     edge.Effect,
				Priority:   edge.Priority,
				Risk:       edge.Risk,
				Properties: properties,
			})
		}
	}

	b.graph.AddEdgesBatch(edges)
}

func (b *Builder) clearUnifiedOrgNodes() {
	for _, node := range b.graph.GetNodesByKind(NodeKindPerson, NodeKindDepartment, NodeKindLocation) {
		b.graph.RemoveNode(node.ID)
	}
}

func (b *Builder) enrichPeopleFromRippling(
	ctx context.Context,
	aggregates map[*personAggregate]struct{},
	emailIndex map[string]*personAggregate,
	getByEmail func(email string) *personAggregate,
	merge func(dst *personAggregate, src *personAggregate) *personAggregate,
) {

	rows, err := b.queryIfExists(ctx, "rippling_employees", `
		SELECT id, work_email, personal_email, display_name, first_name, last_name, employment_status,
		       department, title, manager_id, location, start_date
		FROM rippling_employees
	`)
	if err != nil {
		b.logger.Debug("failed to query rippling employees for person enrichment", "error", err)
		return
	}

	for _, row := range rows.Rows {
		workEmail := normalizePersonEmail(queryRowString(row, "work_email"))
		personalEmail := normalizePersonEmail(queryRowString(row, "personal_email"))
		if workEmail == "" && personalEmail == "" {
			continue
		}

		var agg *personAggregate
		if workEmail != "" {
			agg = emailIndex[workEmail]
		}
		if agg == nil && personalEmail != "" {
			agg = emailIndex[personalEmail]
		}
		if agg == nil {
			seed := workEmail
			if seed == "" {
				seed = personalEmail
			}
			agg = getByEmail(seed)
		}
		if agg == nil {
			continue
		}

		if workEmail != "" {
			if existing := emailIndex[workEmail]; existing != nil {
				agg = merge(agg, existing)
			}
			emailIndex[workEmail] = agg
			agg.Emails[workEmail] = struct{}{}
			agg.PrimaryEmail = workEmail
		}
		if personalEmail != "" {
			if existing := emailIndex[personalEmail]; existing != nil {
				agg = merge(agg, existing)
			}
			emailIndex[personalEmail] = agg
			agg.Emails[personalEmail] = struct{}{}
		}

		agg.HasHRRecord = true
		agg.IsExternal = false
		agg.EmployeeID = strings.TrimSpace(queryRowString(row, "id"))
		agg.ManagerEmployee = strings.TrimSpace(queryRowString(row, "manager_id"))
		agg.Department = strings.TrimSpace(queryRowString(row, "department"))
		agg.Location = strings.TrimSpace(queryRowString(row, "location"))
		agg.Title = strings.TrimSpace(queryRowString(row, "title"))
		agg.Status = strings.TrimSpace(queryRowString(row, "employment_status"))
		agg.StartDate = strings.TrimSpace(queryRowString(row, "start_date"))

		displayName := strings.TrimSpace(queryRowString(row, "display_name"))
		if displayName == "" {
			firstName := strings.TrimSpace(queryRowString(row, "first_name"))
			lastName := strings.TrimSpace(queryRowString(row, "last_name"))
			displayName = strings.TrimSpace(strings.Join([]string{firstName, lastName}, " "))
		}
		if displayName != "" {
			agg.Name = displayName
		}
		aggregates[agg] = struct{}{}
	}
}

func primaryPersonEmailFromNode(node *Node) string {
	if node == nil {
		return ""
	}
	keys := []string{"email", "mail", "primary_email", "upn", "login"}
	for _, key := range keys {
		value := normalizePersonEmail(queryRowString(node.Properties, key))
		if value == "" || !strings.Contains(value, "@") {
			continue
		}
		return value
	}
	if fallback := normalizePersonEmail(node.Name); strings.Contains(fallback, "@") {
		return fallback
	}
	return ""
}

func providerIdentityKeys(node *Node) map[string]string {
	ids := make(map[string]string)
	if node == nil {
		return ids
	}
	provider := strings.TrimSpace(strings.ToLower(node.Provider))
	switch provider {
	case "okta":
		ids["okta_id"] = node.ID
	case "azure":
		ids["azure_ad_id"] = node.ID
	default:
		if provider != "" {
			safeProvider := normalizeOrgKey(provider)
			if safeProvider != "" {
				ids[safeProvider+"_id"] = node.ID
			}
		}
	}
	return ids
}

func normalizePersonEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func firstSortedEmail(values map[string]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	emails := sortedSet(values)
	if len(emails) == 0 {
		return ""
	}
	return emails[0]
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func looksLikeServiceAccountEmail(email string) bool {
	email = normalizePersonEmail(email)
	if email == "" {
		return false
	}
	localPart := email
	if at := strings.Index(localPart, "@"); at > 0 {
		localPart = localPart[:at]
	}
	indicators := []string{"svc", "service", "bot", "noreply", "no-reply", "daemon", "automation"}
	for _, indicator := range indicators {
		if strings.Contains(localPart, indicator) {
			return true
		}
	}
	return false
}

func normalizeOrgKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if lastDash || builder.Len() == 0 {
			continue
		}
		builder.WriteByte('-')
		lastDash = true
	}
	return strings.Trim(builder.String(), "-")
}
