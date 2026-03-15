package builders

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type cdcEvent struct {
	EventID    string
	TableName  string
	ResourceID string
	ChangeType string
	Provider   string
	Region     string
	AccountID  string
	Payload    map[string]any
	EventTime  time.Time
	IngestedAt time.Time
}

type cdcWatermark struct {
	EventTime  time.Time
	IngestedAt time.Time
	EventID    string
}

func effectiveCDCWatermark(lastBuildTime time.Time, watermark cdcWatermark) cdcWatermark {
	if watermark.EventTime.IsZero() && !lastBuildTime.IsZero() {
		watermark.EventTime = lastBuildTime.UTC()
	}
	if !watermark.EventTime.IsZero() {
		watermark.EventTime = watermark.EventTime.UTC()
	}
	if !watermark.IngestedAt.IsZero() {
		watermark.IngestedAt = watermark.IngestedAt.UTC()
	}
	watermark.EventID = strings.TrimSpace(watermark.EventID)
	return watermark
}

func (w cdcWatermark) After(other cdcWatermark) bool {
	left := effectiveCDCWatermark(time.Time{}, w)
	right := effectiveCDCWatermark(time.Time{}, other)
	if left.EventTime.After(right.EventTime) {
		return true
	}
	if left.EventTime.Before(right.EventTime) {
		return false
	}
	if left.IngestedAt.After(right.IngestedAt) {
		return true
	}
	if left.IngestedAt.Before(right.IngestedAt) {
		return false
	}
	return strings.Compare(left.EventID, right.EventID) > 0
}

func cdcWatermarkFromEvent(event cdcEvent) cdcWatermark {
	return cdcWatermark{
		EventTime:  event.EventTime,
		IngestedAt: event.IngestedAt,
		EventID:    event.EventID,
	}
}

func queryCDCWatermark(current cdcWatermark, since time.Time) cdcWatermark {
	if since.IsZero() {
		return effectiveCDCWatermark(time.Time{}, current)
	}
	queryWatermark := cdcWatermark{EventTime: since.UTC()}
	current = effectiveCDCWatermark(time.Time{}, current)
	if !current.EventTime.IsZero() && queryWatermark.EventTime.Equal(current.EventTime) {
		return current
	}
	return queryWatermark
}

// ApplyChanges updates the current graph from CDC_EVENTS without full node reload.
func (b *Builder) ApplyChanges(ctx context.Context, since time.Time) (GraphMutationSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return GraphMutationSummary{}, err
	}

	b.updateMu.Lock()
	defer b.updateMu.Unlock()

	b.stateMu.RLock()
	currentWatermark := effectiveCDCWatermark(b.lastBuildTime, b.lastCDCWatermark)
	if since.IsZero() {
		since = currentWatermark.EventTime
	}
	queryWatermark := queryCDCWatermark(currentWatermark, since)
	currentGraph := b.graph
	availableTables := cloneAvailableTables(b.availableTables)
	b.stateMu.RUnlock()

	if currentGraph == nil {
		return GraphMutationSummary{}, fmt.Errorf("graph not initialized")
	}

	start := time.Now()
	summary := GraphMutationSummary{
		Mode:  GraphMutationModeIncremental,
		Since: since,
	}

	working := &Builder{
		source:          b.source,
		logger:          b.logger,
		availableTables: availableTables,
	}

	// Refresh table discovery so incremental edge rebuilds see newly populated tables.
	working.discoverTables(ctx)

	events, err := working.queryCDCEvents(ctx, queryWatermark)
	if err != nil {
		return GraphMutationSummary{}, err
	}
	summary.EventsProcessed = len(events)
	if len(events) == 0 {
		until := currentWatermark.EventTime
		if until.IsZero() {
			until = since
		}
		summary.Tables = []string{}
		summary.Until = until
		summary.NodeCount = currentGraph.NodeCount()
		summary.EdgeCount = currentGraph.EdgeCount()
		summary.Duration = time.Since(start)
		b.stateMu.Lock()
		b.availableTables = working.availableTables
		b.lastBuildTime = until
		b.lastCDCWatermark = effectiveCDCWatermark(until, currentWatermark)
		b.lastMutation = summary
		b.stateMu.Unlock()
		return summary, nil
	}

	working.graph = currentGraph.Clone()

	tableSet := make(map[string]struct{}, len(events))
	latest := effectiveCDCWatermark(time.Time{}, currentWatermark)

	for _, event := range events {
		table := strings.ToLower(strings.TrimSpace(event.TableName))
		if table != "" {
			tableSet[table] = struct{}{}
		}
		eventWatermark := cdcWatermarkFromEvent(event)
		if eventWatermark.After(latest) {
			latest = eventWatermark
		}

		switch normalizeCDCChangeType(event.ChangeType) {
		case "removed":
			nodeID := strings.TrimSpace(event.ResourceID)
			if nodeID == "" {
				nodeID = cdcNodeID(table, event.Payload, "")
			}
			if nodeID == "" {
				continue
			}
			if working.graph.RemoveNode(nodeID) {
				summary.NodesRemoved++
			}
		case "added", "modified":
			node := cdcEventToNode(table, event)
			if node == nil {
				continue
			}
			if existing, ok := working.graph.GetNodeIncludingDeleted(node.ID); ok && existing != nil {
				summary.NodesUpdated++
			} else {
				summary.NodesAdded++
			}
			working.graph.AddNode(node)
		}
	}

	if _, ok := working.graph.GetNodeIncludingDeleted("internet"); !ok {
		working.addInternetNode()
	}

	if err := working.rebuildEdges(ctx); err != nil {
		return GraphMutationSummary{}, err
	}

	tables := make([]string, 0, len(tableSet))
	for table := range tableSet {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	summary.Tables = tables

	now := time.Now().UTC()
	if latest.EventTime.IsZero() {
		latest.EventTime = now
	}
	if latest.IngestedAt.IsZero() {
		latest.IngestedAt = latest.EventTime
	}
	summary.Until = latest.EventTime
	summary.Duration = time.Since(start)
	summary.NodeCount = working.graph.NodeCount()
	summary.EdgeCount = working.graph.EdgeCount()

	working.graph.SetMetadata(Metadata{
		BuiltAt:       now,
		NodeCount:     summary.NodeCount,
		EdgeCount:     summary.EdgeCount,
		BuildDuration: summary.Duration,
	})

	b.stateMu.Lock()
	b.graph = working.graph
	b.availableTables = working.availableTables
	b.lastBuildTime = latest.EventTime
	b.lastCDCWatermark = latest
	b.lastMutation = summary
	b.stateMu.Unlock()

	b.logger.Info("graph platform incrementally updated",
		"events", summary.EventsProcessed,
		"nodes_added", summary.NodesAdded,
		"nodes_updated", summary.NodesUpdated,
		"nodes_removed", summary.NodesRemoved,
		"nodes", summary.NodeCount,
		"edges", summary.EdgeCount,
		"duration", summary.Duration,
	)

	return summary, nil
}

func (b *Builder) queryCDCEvents(ctx context.Context, since cdcWatermark) ([]cdcEvent, error) {
	query := `
		SELECT event_id, table_name, resource_id, change_type, provider, region, account_id, payload, event_time,
		       COALESCE(ingested_at, event_time) AS ingested_at
		FROM CDC_EVENTS`
	args := make([]any, 0, 6)
	since = effectiveCDCWatermark(time.Time{}, since)
	if !since.EventTime.IsZero() {
		sinceIngestedAt := since.IngestedAt
		if sinceIngestedAt.IsZero() {
			sinceIngestedAt = since.EventTime
		}
		query += `
		WHERE (
			event_time > ?
			OR (event_time = ? AND COALESCE(ingested_at, event_time) > ?)
			OR (event_time = ? AND COALESCE(ingested_at, event_time) = ? AND event_id > ?)
		)`
		args = append(args,
			since.EventTime,
			since.EventTime,
			sinceIngestedAt,
			since.EventTime,
			sinceIngestedAt,
			since.EventID,
		)
	}
	query += " ORDER BY event_time ASC, ingested_at ASC, event_id ASC"

	result, err := b.source.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	events := make([]cdcEvent, 0, len(result.Rows))
	for _, row := range result.Rows {
		events = append(events, cdcEvent{
			EventID:    queryRowString(row, "event_id"),
			TableName:  queryRowString(row, "table_name"),
			ResourceID: queryRowString(row, "resource_id"),
			ChangeType: queryRowString(row, "change_type"),
			Provider:   queryRowString(row, "provider"),
			Region:     queryRowString(row, "region"),
			AccountID:  queryRowString(row, "account_id"),
			Payload:    decodeCDCPayload(queryRow(row, "payload")),
			EventTime:  parseCDCEventTime(queryRow(row, "event_time")),
			IngestedAt: parseCDCEventTime(queryRow(row, "ingested_at")),
		})
	}

	return events, nil
}

func (b *Builder) queryLatestCDCWatermark(ctx context.Context) (cdcWatermark, error) {
	result, err := b.source.Query(ctx, `
		SELECT event_time, COALESCE(ingested_at, event_time) AS ingested_at, event_id
		FROM CDC_EVENTS
		ORDER BY event_time DESC, ingested_at DESC, event_id DESC
		LIMIT 1
	`)
	if err != nil || len(result.Rows) == 0 {
		return cdcWatermark{}, err
	}
	row := result.Rows[0]
	return cdcWatermark{
		EventTime:  parseCDCEventTime(queryRow(row, "event_time")),
		IngestedAt: parseCDCEventTime(queryRow(row, "ingested_at")),
		EventID:    queryRowString(row, "event_id"),
	}, nil
}

func removeNodesBySourceSystems(g *Graph, sourceSystems ...string) int {
	if g == nil || len(sourceSystems) == 0 {
		return 0
	}
	allowed := make(map[string]struct{}, len(sourceSystems))
	for _, sourceSystem := range sourceSystems {
		sourceSystem = strings.TrimSpace(sourceSystem)
		if sourceSystem == "" {
			continue
		}
		allowed[sourceSystem] = struct{}{}
	}
	removed := 0
	for _, node := range g.Nodes() {
		if node == nil {
			continue
		}
		sourceSystem := strings.TrimSpace(readString(node.Properties, "source_system"))
		if _, ok := allowed[sourceSystem]; !ok {
			continue
		}
		if g.RemoveNode(node.ID) {
			removed++
		}
	}
	return removed
}

func (b *Builder) rebuildEdges(ctx context.Context) error {
	b.graph.ClearEdges()
	removeNodesBySourceSystems(b.graph,
		awsIAMPermissionUsageSourceSystem,
		gcpIAMPermissionUsageSourceSystem,
		entityAssetNormalizerSourceSystem,
	)
	b.graph.BuildIndex()

	eg, ectx := errgroup.WithContext(ctx)
	eg.Go(func() error { b.buildAWSEdges(ectx); return nil })
	eg.Go(func() error { b.buildGCPEdges(ectx); return nil })
	eg.Go(func() error { b.buildAzureEdges(ectx); return nil })
	eg.Go(func() error { b.buildKubernetesEdges(ectx); return nil })
	eg.Go(func() error { b.buildRelationshipEdges(ectx); return nil })
	_ = eg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	b.buildIAMPermissionUsageKnowledge(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	b.buildUnifiedPersonGraph(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	b.buildPersonInteractionEdges(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	b.buildExposureEdges(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	b.buildSCMInference()
	if err := ctx.Err(); err != nil {
		return err
	}
	NormalizeEntityAssetSupport(b.graph, temporalNowUTC())
	if err := ctx.Err(); err != nil {
		return err
	}

	b.graph.BuildIndex()
	return nil
}

func cdcEventToNode(table string, event cdcEvent) *Node {
	payload := event.Payload
	if len(payload) == 0 {
		return nil
	}

	table = strings.ToLower(strings.TrimSpace(table))
	provider := strings.TrimSpace(event.Provider)
	account := strings.TrimSpace(event.AccountID)
	region := strings.TrimSpace(event.Region)

	switch table {
	case "aws_iam_users":
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindUser,
			Name:     firstNonEmpty(queryRowString(payload, "user_name"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Properties: map[string]any{
				"last_login": queryRow(payload, "password_last_used"),
			},
		}
	case "aws_iam_roles":
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindRole,
			Name:     firstNonEmpty(queryRowString(payload, "role_name"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Properties: map[string]any{
				"trust_policy": queryRow(payload, "assume_role_policy_document"),
				"description":  queryRow(payload, "description"),
			},
		}
	case "aws_iam_groups":
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindGroup,
			Name:     firstNonEmpty(queryRowString(payload, "group_name"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
		}
	case "aws_s3_buckets":
		isPublic := !toBool(queryRow(payload, "block_public_acls")) || !toBool(queryRow(payload, "block_public_policy"))
		risk := RiskNone
		if isPublic {
			risk = RiskHigh
		}
		name := firstNonEmpty(queryRowString(payload, "name"), cdcNodeID(table, payload, event.ResourceID))
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindBucket,
			Name:     name,
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Risk:     risk,
			Properties: map[string]any{
				"public":              isPublic,
				"block_public_acls":   queryRow(payload, "block_public_acls"),
				"block_public_policy": queryRow(payload, "block_public_policy"),
				"versioning":          queryRow(payload, "versioning_status"),
				"versioning_status":   queryRow(payload, "versioning_status"),
			},
		}
	case "aws_ec2_instances":
		hasPublicIP := strings.TrimSpace(queryRowString(payload, "public_ip_address")) != ""
		risk := RiskNone
		if hasPublicIP {
			risk = RiskMedium
		}
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindInstance,
			Name:     firstNonEmpty(queryRowString(payload, "instance_id"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Risk:     risk,
			Properties: map[string]any{
				"public_ip":            queryRow(payload, "public_ip_address"),
				"iam_instance_profile": queryRow(payload, "iam_instance_profile"),
			},
		}
	case "aws_rds_instances":
		isPublic := toBool(queryRow(payload, "publicly_accessible"))
		risk := RiskNone
		if isPublic {
			risk = RiskCritical
		}
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindDatabase,
			Name:     firstNonEmpty(queryRowString(payload, "db_instance_identifier"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Risk:     risk,
			Properties: map[string]any{
				"public":    isPublic,
				"encrypted": queryRow(payload, "storage_encrypted"),
			},
		}
	case "aws_lambda_functions":
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindFunction,
			Name:     firstNonEmpty(queryRowString(payload, "function_name"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Properties: map[string]any{
				"execution_role": queryRow(payload, "role"),
			},
		}
	case "aws_secretsmanager_secrets":
		return &Node{
			ID:       cdcNodeID(table, payload, event.ResourceID),
			Kind:     NodeKindSecret,
			Name:     firstNonEmpty(queryRowString(payload, "name"), cdcNodeID(table, payload, event.ResourceID)),
			Provider: firstNonEmpty(provider, "aws"),
			Account:  firstNonEmpty(queryRowString(payload, "account_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Risk:     RiskHigh,
		}
	case "aws_ec2_security_groups":
		return nodeWithResolvedID(
			awsSecurityGroupNodeFromRecord(payload, firstNonEmpty(provider, "aws"), account, region),
			cdcNodeID(table, payload, event.ResourceID),
		)

	case "gcp_iam_service_accounts":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindServiceAccount,
			Name:     firstNonEmpty(queryRowString(payload, "email"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Properties: map[string]any{
				"email":        queryRow(payload, "email"),
				"display_name": queryRow(payload, "display_name"),
			},
		}
	case "gcp_compute_instances":
		saEmail := extractGCPServiceAccountEmail(queryRow(payload, "service_accounts"))
		isDefaultSA := strings.HasSuffix(saEmail, "-compute@developer.gserviceaccount.com")
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindInstance,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "zone"), region),
			Properties: map[string]any{
				"status":                queryRow(payload, "status"),
				"service_accounts":      queryRow(payload, "service_accounts"),
				"service_account_email": saEmail,
				"uses_default_sa":       isDefaultSA,
			},
		}
	case "gcp_storage_buckets":
		iamStr := queryRowString(payload, "iam_policy")
		allUsers := strings.Contains(iamStr, "allUsers")
		allAuthUsers := strings.Contains(iamStr, "allAuthenticatedUsers")
		isPublic := allUsers || allAuthUsers
		risk := RiskNone
		if isPublic {
			risk = RiskCritical
		}
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindBucket,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Risk:     risk,
			Properties: map[string]any{
				"iam_policy":                     queryRow(payload, "iam_policy"),
				"public":                         isPublic,
				"public_access":                  isPublic,
				"all_users_access":               allUsers,
				"all_authenticated_users_access": allAuthUsers,
				"public_access_prevention":       queryRow(payload, "public_access_prevention"),
			},
		}
	case "gcp_sql_instances":
		ipStr := queryRowString(payload, "ip_addresses")
		settingsStr := queryRowString(payload, "settings")
		hasPublicIP := strings.Contains(ipStr, "PRIMARY")
		hasOpenAuthNetwork := strings.Contains(settingsStr, "0.0.0.0/0")
		isPublic := hasPublicIP && hasOpenAuthNetwork
		risk := RiskNone
		if isPublic {
			risk = RiskCritical
		}
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindDatabase,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "region"), region),
			Risk:     risk,
			Properties: map[string]any{
				"database_version": queryRow(payload, "database_version"),
				"ip_addresses":     queryRow(payload, "ip_addresses"),
				"public":           isPublic,
			},
		}
	case "gcp_cloudfunctions_functions":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindFunction,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"service_config": queryRow(payload, "service_config"),
				"build_config":   queryRow(payload, "build_config"),
			},
		}
	case "gcp_cloudrun_services":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindFunction,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "gcp"),
			Account:  firstNonEmpty(queryRowString(payload, "project_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"ingress": queryRow(payload, "ingress"),
				"uri":     queryRow(payload, "uri"),
			},
		}
	case "gcp_compute_firewalls":
		return nodeWithResolvedID(
			gcpFirewallNodeFromRecord(payload, firstNonEmpty(provider, "gcp"), account, region),
			cdcNodeID(table, payload, event.ResourceID),
		)

	case "azure_ad_service_principals":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindServiceAccount,
			Name:     firstNonEmpty(queryRowString(payload, "display_name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"app_id": queryRow(payload, "app_id"),
				"type":   queryRow(payload, "service_principal_type"),
			},
		}
	case "azure_ad_users":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindUser,
			Name:     firstNonEmpty(queryRowString(payload, "display_name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"upn":  queryRow(payload, "user_principal_name"),
				"mail": queryRow(payload, "mail"),
			},
		}
	case "azure_compute_virtual_machines":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindInstance,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"resource_group": queryRow(payload, "resource_group"),
				"identity":       queryRow(payload, "identity"),
			},
		}
	case "azure_storage_accounts":
		isPublic := toBool(queryRow(payload, "allow_blob_public_access"))
		risk := RiskNone
		if isPublic {
			risk = RiskHigh
		}
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindBucket,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Risk:     risk,
			Properties: map[string]any{
				"resource_group": queryRow(payload, "resource_group"),
				"public":         isPublic,
			},
		}
	case "azure_sql_databases":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindDatabase,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"resource_group": queryRow(payload, "resource_group"),
				"server":         queryRow(payload, "server_name"),
			},
		}
	case "azure_keyvault_vaults":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindSecret,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Risk:     RiskHigh,
			Properties: map[string]any{
				"resource_group": queryRow(payload, "resource_group"),
			},
		}
	case "azure_functions_apps":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindFunction,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "azure"),
			Account:  firstNonEmpty(queryRowString(payload, "subscription_id"), account),
			Region:   firstNonEmpty(queryRowString(payload, "location"), region),
			Properties: map[string]any{
				"resource_group": queryRow(payload, "resource_group"),
				"identity":       queryRow(payload, "identity"),
			},
		}
	case "azure_network_security_groups":
		return nodeWithResolvedID(
			azureNetworkSecurityGroupNodeFromRecord(payload, firstNonEmpty(provider, "azure"), account, region),
			cdcNodeID(table, payload, event.ResourceID),
		)

	case "okta_users":
		id := cdcNodeID(table, payload, event.ResourceID)
		name := firstNonEmpty(queryRowString(payload, "login"), queryRowString(payload, "email"), id)
		return &Node{
			ID:       id,
			Kind:     NodeKindUser,
			Name:     name,
			Provider: firstNonEmpty(provider, "okta"),
			Properties: map[string]any{
				"email":        queryRow(payload, "email"),
				"status":       queryRow(payload, "status"),
				"last_login":   queryRow(payload, "last_login"),
				"mfa_enrolled": queryRow(payload, "mfa_enrolled"),
				"is_admin":     queryRow(payload, "is_admin"),
			},
		}
	case "okta_groups":
		id := cdcNodeID(table, payload, event.ResourceID)
		return &Node{
			ID:       id,
			Kind:     NodeKindGroup,
			Name:     firstNonEmpty(queryRowString(payload, "name"), id),
			Provider: firstNonEmpty(provider, "okta"),
			Properties: map[string]any{
				"description": queryRow(payload, "description"),
				"type":        queryRow(payload, "type"),
			},
		}
	case "okta_applications":
		id := cdcNodeID(table, payload, event.ResourceID)
		name := firstNonEmpty(queryRowString(payload, "label"), queryRowString(payload, "name"), id)
		return &Node{
			ID:       id,
			Kind:     NodeKindApplication,
			Name:     name,
			Provider: firstNonEmpty(provider, "okta"),
			Properties: map[string]any{
				"status":       queryRow(payload, "status"),
				"sign_on_mode": queryRow(payload, "sign_on_mode"),
			},
		}
	case "okta_admin_roles":
		roleType := strings.TrimSpace(queryRowString(payload, "role_type"))
		roleID := strings.TrimSpace(event.ResourceID)
		if roleID == "" {
			if roleType == "" {
				return nil
			}
			roleID = "okta_admin_role:" + strings.ToLower(roleType)
		}
		if !strings.HasPrefix(roleID, "okta_admin_role:") {
			roleID = "okta_admin_role:" + strings.ToLower(roleID)
		}
		name := firstNonEmpty(queryRowString(payload, "role_label"), roleType, roleID)
		return &Node{
			ID:       roleID,
			Kind:     NodeKindRole,
			Name:     name,
			Provider: firstNonEmpty(provider, "okta"),
			Properties: map[string]any{
				"role_type": roleType,
			},
		}
	case "k8s_core_pods",
		"k8s_core_namespaces",
		"k8s_core_service_accounts",
		"k8s_apps_deployments",
		"k8s_rbac_cluster_roles",
		"k8s_rbac_roles",
		"k8s_rbac_cluster_role_bindings",
		"k8s_rbac_role_bindings",
		"k8s_core_configmaps",
		"k8s_core_persistent_volumes":
		return k8sNodeFromRecord(table, payload, event.ResourceID)
	}

	return nil
}

func cdcNodeID(table string, payload map[string]any, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(table)) {
	case "aws_ec2_security_groups":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return awsSecurityGroupNodeID(payload)
	case "aws_iam_users", "aws_iam_roles", "aws_iam_groups", "aws_s3_buckets", "aws_ec2_instances", "aws_rds_instances", "aws_lambda_functions", "aws_secretsmanager_secrets":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return firstNonEmpty(queryRowString(payload, "arn"), queryRowString(payload, "id"), queryRowString(payload, "name"))
	case "gcp_iam_service_accounts":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return firstNonEmpty(queryRowString(payload, "unique_id"), queryRowString(payload, "email"), queryRowString(payload, "name"), queryRowString(payload, "id"))
	case "gcp_compute_firewalls":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return gcpFirewallNodeID(payload)
	case "gcp_compute_instances", "gcp_storage_buckets", "gcp_sql_instances", "gcp_cloudfunctions_functions", "gcp_cloudrun_services":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return firstNonEmpty(queryRowString(payload, "id"), queryRowString(payload, "name"))
	case "azure_network_security_groups":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return azureNetworkSecurityGroupNodeID(payload)
	case "azure_ad_service_principals", "azure_ad_users", "azure_compute_virtual_machines", "azure_storage_accounts", "azure_sql_databases", "azure_keyvault_vaults", "azure_functions_apps", "okta_users", "okta_groups", "okta_applications":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return firstNonEmpty(queryRowString(payload, "id"), queryRowString(payload, "name"))
	case "okta_admin_roles":
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		roleType := strings.TrimSpace(queryRowString(payload, "role_type"))
		if roleType == "" {
			return ""
		}
		return "okta_admin_role:" + strings.ToLower(roleType)
	case "k8s_core_pods",
		"k8s_core_namespaces",
		"k8s_core_service_accounts",
		"k8s_apps_deployments",
		"k8s_rbac_cluster_roles",
		"k8s_rbac_roles",
		"k8s_rbac_cluster_role_bindings",
		"k8s_rbac_role_bindings",
		"k8s_core_configmaps",
		"k8s_core_persistent_volumes":
		return k8sNodeID(table, payload, fallback)
	default:
		if id := strings.TrimSpace(fallback); id != "" {
			return id
		}
		return firstNonEmpty(queryRowString(payload, "arn"), queryRowString(payload, "id"), queryRowString(payload, "unique_id"), queryRowString(payload, "name"))
	}
}

func CDCResourceIDForTable(table string, payload map[string]any) string {
	return cdcNodeID(table, payload, "")
}

func nodeWithResolvedID(node *Node, resolvedID string) *Node {
	if node == nil {
		return nil
	}
	resolvedID = strings.TrimSpace(resolvedID)
	if resolvedID == "" || node.ID == resolvedID {
		return node
	}
	previousID := node.ID
	node.ID = resolvedID
	if strings.TrimSpace(node.Name) == "" || node.Name == previousID {
		node.Name = resolvedID
	}
	return node
}

func normalizeCDCChangeType(changeType string) string {
	normalized := strings.ToLower(strings.TrimSpace(changeType))
	switch normalized {
	case "added", "add", "created", "inserted":
		return "added"
	case "modified", "modify", "updated", "update", "upserted", "upsert":
		return "modified"
	case "removed", "remove", "deleted", "delete":
		return "removed"
	default:
		return normalized
	}
}

func decodeCDCPayload(value any) map[string]any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		return cloneAnyMap(typed)
	case []byte:
		return decodeCDCPayloadJSON(typed)
	case string:
		return decodeCDCPayloadJSON([]byte(strings.TrimSpace(typed)))
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return nil
		}
		return decodeCDCPayloadJSON(encoded)
	}
}

func decodeCDCPayloadJSON(raw []byte) map[string]any {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return nil
	}
	payload := make(map[string]any)
	if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
		return payload
	}
	return nil
}

func parseCDCEventTime(value any) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		if ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(typed)); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(typed)); err == nil {
			return ts.UTC()
		}
	case []byte:
		if ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(typed))); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(string(typed))); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
