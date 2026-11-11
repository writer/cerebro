package sourceprojection

import (
	"net/url"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// vulnViewFindingProjections joins one standardized VulnView finding
// (Contract C8, event vulnview.finding, replacing the removed
// vulnerability/dns_alert/cloud_identity_finding/cloud_identity_assessment
// families) into the graph: a strictly-versioned vulnview.finding entity;
// external attack-surface findings (VulnViewExternalAttackSurfaceSource)
// link from the existing VulnView external.asset entity via has_evidence;
// cloud_identity findings link from the canonical AWS role / GCP service
// account URN via has_evidence (and, via the separate
// vulnViewFindingLinkSetProjections C9 link-set projector, to consumer
// Kubernetes service accounts via associated_with -- complete when the
// export marks the consumer list consumersComplete, otherwise an
// Incomplete observation with no links). Other sources' assets (cloud
// resource IDs, repositories, principals) are not network hosts, so they
// stay finding attributes rather than minting external.asset nodes. No
// run/assessment entities: VulnView is the sole detection authority for
// cloud-identity posture and Cerebro's rule engine never re-derives it.
func vulnViewFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	findingID := firstAttribute(attrs, "finding_id")
	if findingID == "" {
		return nil, nil, nil
	}
	findingURN := projectionURN(tenantID, "vulnview_finding", findingID)
	if findingURN == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sourceID := event.GetSourceId()

	findingAttrs, findingRetracted := vulnViewFindingAttributes(attrs, event)
	addEntity(entities, &ports.ProjectedEntity{
		URN:                 findingURN,
		TenantID:            tenantID,
		SourceID:            sourceID,
		EntityType:          "vulnview.finding",
		Label:               firstAttribute(attrs, "title", "check_id", "finding_id"),
		Attributes:          findingAttrs,
		RetractedAttributes: findingRetracted,
	})

	if assetURN := vulnViewAssetURN(tenantID, attrs); assetURN != "" && VulnViewExternalAttackSurfaceSource(firstAttribute(attrs, "source")) {
		addEntity(entities, vulnViewAssetEntity(tenantID, sourceID, assetURN, attrs))
		hostRaw := vulnViewAssetHostRaw(attrs)
		addInternetHostLink(entities, links, tenantID, sourceID, event, assetURN, relationRepresents, hostRaw, "vulnview_asset_host", "0.95")
		addInternetHostDomainLink(entities, links, tenantID, sourceID, event, hostRaw, "vulnview_asset_domain", "0.85")
		addLink(links, projectedLink(tenantID, sourceID, assetURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, sourceID, findingURN, assetURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}

	if strings.EqualFold(strings.TrimSpace(firstAttribute(attrs, "source")), "cloud_identity") {
		vulnViewFindingAddCloudIdentityLinks(entities, links, tenantID, sourceID, event, findingURN, attrs)
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// VulnViewExternalAttackSurfaceSource reports whether a VulnView finding
// source scans network-reachable external targets (nuclei, caido, port,
// dns): the only sources whose finding asset is an external host, and the
// only ones the VulnView external attack-surface finding rules consider.
func VulnViewExternalAttackSurfaceSource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "nuclei", "caido", "port", "dns":
		return true
	}
	return false
}

// vulnViewFindingAttributesOwnedKeys lists every optional Contract C7
// field vulnViewFindingAttributes can emit on the finding entity (every
// key below except the identity key "finding_id"/"source" and the
// observation-metadata keys "event_id"/"at"/"observation_precedence"/
// "observation_version", which are never retracted). F10: these are the
// owned keys a newer accepted finding version retracts when this
// observation no longer carries them -- triage.state is ALWAYS present
// ("none" when untriaged) so triage_state itself is never retracted, but
// an untriage clears triage_reason/triage_by/triage_at/triage_expires_at,
// and a finding reopen or re-evaluation can likewise drop
// lifecycle/context fields the durable model intentionally removed.
var vulnViewFindingAttributesOwnedKeys = []string{
	"check_id", "description", "severity", "source_severity", "status",
	"asset", "location", "resource_provider", "resource_account",
	"resource_account_name", "resource_project", "resource_region",
	"resource_type", "resource_name", "resource_kind", "resource_port",
	"resource_protocol", "remediation", "references",
	"triage_state", "triage_reason", "triage_by", "triage_at", "triage_expires_at",
	"first_seen_at", "last_seen_at", "last_evaluated_at", "fixed_at",
	"reopened_at", "reopen_count", "last_scan_id", "last_run_id",
	"last_site_id", "principal_id", "principal_kind", "cohort_scope",
	"check_version", "detector_version", "side", "drift",
	"consumers_complete", "consumers", "gap_codes", "evidence_bundle_key",
	"evidence_bundle_sha256", "evidence_principal_evidence_sha256",
	"evidence_collected_at", "matcher", "template_path",
	"excess_declared", "excess_observed", "sharing_services", "sharing_consumer_ids",
	"detail_truncated", "excess_declared_count", "excess_observed_count",
	"sharing_services_count", "sharing_consumer_ids_count",
	"provenance_integrations", "provenance_repository_integrations",
	"provenance_integration_attribution",
}

// vulnViewFindingAttributes flattens the Contract C7 export fields the
// source already bound to bounded event attributes (see
// sources/vulnview/records.go attributesFor) onto the projected finding
// entity, plus the strict version-ordering attributes: VulnView's
// per-finding version orders writes (observation_version), so a replayed
// older finding version never regresses the stored one. The second return
// value is RetractedAttributes (F10, ports.ProjectedEntity): every key in
// vulnViewFindingAttributesOwnedKeys this observation does not carry
// (after blank filtering), so a store removes a stale optional field
// (cleared triage, fixed lifecycle timestamps the finding later reopened
// past, etc.) instead of indefinitely keeping an older observation's
// value.
func vulnViewFindingAttributes(attrs map[string]string, event *cerebrov1.EventEnvelope) (map[string]string, []string) {
	out := map[string]string{
		"finding_id":                         firstAttribute(attrs, "finding_id"),
		"source":                             firstAttribute(attrs, "source"),
		"check_id":                           firstAttribute(attrs, "check_id"),
		"description":                        firstAttribute(attrs, "description"),
		"severity":                           firstAttribute(attrs, "severity"),
		"source_severity":                    firstAttribute(attrs, "source_severity", "severity"),
		"status":                             firstAttribute(attrs, "status"),
		"asset":                              firstAttribute(attrs, "asset"),
		"location":                           firstAttribute(attrs, "location"),
		"resource_provider":                  firstAttribute(attrs, "resource_provider"),
		"resource_account":                   firstAttribute(attrs, "resource_account"),
		"resource_account_name":              firstAttribute(attrs, "resource_account_name"),
		"resource_project":                   firstAttribute(attrs, "resource_project"),
		"resource_region":                    firstAttribute(attrs, "resource_region"),
		"resource_type":                      firstAttribute(attrs, "resource_type"),
		"resource_name":                      firstAttribute(attrs, "resource_name"),
		"resource_kind":                      firstAttribute(attrs, "resource_kind"),
		"resource_port":                      firstAttribute(attrs, "resource_port"),
		"resource_protocol":                  firstAttribute(attrs, "resource_protocol"),
		"remediation":                        firstAttribute(attrs, "remediation"),
		"references":                         firstAttribute(attrs, "references"),
		"triage_state":                       firstAttribute(attrs, "triage_state"),
		"triage_reason":                      firstAttribute(attrs, "triage_reason"),
		"triage_by":                          firstAttribute(attrs, "triage_by"),
		"triage_at":                          firstAttribute(attrs, "triage_at"),
		"triage_expires_at":                  firstAttribute(attrs, "triage_expires_at"),
		"first_seen_at":                      firstAttribute(attrs, "first_seen_at"),
		"last_seen_at":                       firstAttribute(attrs, "last_seen_at"),
		"last_evaluated_at":                  firstAttribute(attrs, "last_evaluated_at"),
		"fixed_at":                           firstAttribute(attrs, "fixed_at"),
		"reopened_at":                        firstAttribute(attrs, "reopened_at"),
		"reopen_count":                       firstAttribute(attrs, "reopen_count"),
		"last_scan_id":                       firstAttribute(attrs, "last_scan_id"),
		"last_run_id":                        firstAttribute(attrs, "last_run_id"),
		"last_site_id":                       firstAttribute(attrs, "last_site_id"),
		"principal_id":                       firstAttribute(attrs, "principal_id"),
		"principal_kind":                     firstAttribute(attrs, "principal_kind"),
		"cohort_scope":                       firstAttribute(attrs, "cohort_scope"),
		"check_version":                      firstAttribute(attrs, "check_version"),
		"detector_version":                   firstAttribute(attrs, "detector_version"),
		"side":                               firstAttribute(attrs, "side"),
		"drift":                              firstAttribute(attrs, "drift"),
		"consumers_complete":                 firstAttribute(attrs, "consumers_complete"),
		"consumers":                          firstAttribute(attrs, "consumers"),
		"gap_codes":                          firstAttribute(attrs, "gap_codes"),
		"evidence_bundle_key":                firstAttribute(attrs, "evidence_bundle_key"),
		"evidence_bundle_sha256":             firstAttribute(attrs, "evidence_bundle_sha256"),
		"evidence_principal_evidence_sha256": firstAttribute(attrs, "evidence_principal_evidence_sha256"),
		"evidence_collected_at":              firstAttribute(attrs, "evidence_collected_at"),
		"matcher":                            firstAttribute(attrs, "matcher"),
		"template_path":                      firstAttribute(attrs, "template_path"),
		"excess_declared":                    firstAttribute(attrs, "excess_declared"),
		"excess_observed":                    firstAttribute(attrs, "excess_observed"),
		"sharing_services":                   firstAttribute(attrs, "sharing_services"),
		"sharing_consumer_ids":               firstAttribute(attrs, "sharing_consumer_ids"),
		"detail_truncated":                   firstAttribute(attrs, "detail_truncated"),
		"excess_declared_count":              firstAttribute(attrs, "excess_declared_count"),
		"excess_observed_count":              firstAttribute(attrs, "excess_observed_count"),
		"sharing_services_count":             firstAttribute(attrs, "sharing_services_count"),
		"sharing_consumer_ids_count":         firstAttribute(attrs, "sharing_consumer_ids_count"),
		"provenance_integrations":            firstAttribute(attrs, "provenance_integrations"),
		"provenance_repository_integrations": firstAttribute(attrs, "provenance_repository_integrations"),
		"provenance_integration_attribution": firstAttribute(attrs, "provenance_integration_attribution"),
		"event_id":                           event.GetId(),
		"at":                                 vulnViewFindingVersionAt(attrs, event),
		"observation_precedence":             "strict",
		"observation_version":                firstAttribute(attrs, "version"),
	}
	final := vulnViewAttributes(out)
	retracted := make([]string, 0, len(vulnViewFindingAttributesOwnedKeys))
	for _, key := range vulnViewFindingAttributesOwnedKeys {
		if _, ok := final[key]; !ok {
			retracted = append(retracted, key)
		}
	}
	return final, retracted
}

// vulnViewFindingVersionAt is the finding version's own write time:
// VulnView sets updatedAt on every version bump (observation, miss,
// triage), while OccurredAt can stay on an unchanged evaluation time
// across versions. It does not order versions -- VulnView samples
// updatedAt before its conditional write commits, so a concurrent writer
// can commit a higher version with an earlier updatedAt --
// observation_version does.
func vulnViewFindingVersionAt(attrs map[string]string, event *cerebrov1.EventEnvelope) string {
	at := event.GetOccurredAt().AsTime()
	if updatedAt, err := time.Parse(time.RFC3339Nano, firstAttribute(attrs, "updated_at")); err == nil {
		at = updatedAt
	}
	return at.UTC().Format(time.RFC3339Nano)
}

// vulnViewFindingAddCloudIdentityLinks joins a cloud_identity-sourced
// finding to its canonical AWS role / GCP service account principal via
// has_evidence, materializing the minimal principal endpoint entity so the
// join is never silently dropped by a missing node. A missing or
// unrecognized provider/principal subject never fabricates a canonical
// join; it is already surfaced as a gap_codes attribute on the finding
// entity. The consumer Kubernetes service account stubs are NOT
// materialized here (R06): they are CreateOnly counterparts of the
// separate Contract C9 associated_with link set
// (vulnViewFindingLinkSetProjections) and must only ever be created
// inside that set's own guarded store operation -- as its Endpoints --
// so a stale or losing observation's consumer stubs can never leak into
// the graph ahead of or instead of the winning observation's decision.
func vulnViewFindingAddCloudIdentityLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, findingURN string, attrs map[string]string) {
	provider := firstAttribute(attrs, "resource_provider")
	principalKind := firstAttribute(attrs, "principal_kind")
	principalID := firstAttribute(attrs, "principal_id")
	if vulnViewCloudIdentityUnresolvedPrincipalSubject(provider, principalKind, principalID) {
		return
	}
	principalURN := vulnViewCloudIdentityCanonicalPrincipalURN(tenantID, provider, principalID)
	if principalURN == "" {
		return
	}
	cloudIdentityUpsertCanonicalPrincipalEntity(entities, tenantID, sourceID, provider, principalID, firstAttribute(attrs, "resource_account", "resource_project"), principalURN)
	addLink(links, projectedLink(tenantID, sourceID, principalURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
}

// vulnViewFindingLinkSetProjections builds the complete desired
// associated_with set (Contract C9) from one cloud_identity finding to the
// consumer Kubernetes service accounts it currently names. When the export
// marks the consumer list consumersComplete AND every member canonicalizes
// (R04: decodeVulnViewFindingConsumers itself enforces this -- a
// malformed/unusable member downgrades the whole observation to
// Incomplete rather than silently authorizing a reduced set), the set
// carries exactly those links as an authoritative (possibly empty) set,
// plus each link's consumer Kubernetes service account as a CreateOnly
// Endpoints stub (R06): the store creates an absent endpoint only inside
// the same guarded operation that accepts this exact set, before
// asserting Links, so a stale or losing observation can never
// materialize a consumer node the graph otherwise never heard of.
// Otherwise -- a partial/unavailable/malformed list must never retract
// previously observed consumers -- this still emits a set, but with
// Incomplete set and no links or endpoints: the store advances its
// ordering guard for this finding's observation without touching the
// stored links (F04). Projecting no set at all would let a store compare
// a later complete set only against an older complete one, skipping the
// guard a newer-but-incomplete observation already passed. The finding
// owns the set because its own strict version orders it: a principal
// carries several findings (one per check), each with an independent
// version sequence, so a principal-owned set could never order them. The
// store applies the returned set atomically only if the finding's stored
// set observation is not newer, retracting this tenant/source/runtime's
// other associated_with assertions from the finding and asserting
// exactly these links -- so a consumer VulnView no longer reports is
// dropped instead of accumulating forever (B2).
func vulnViewFindingLinkSetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedLinkSet, error) {
	attrs := event.GetAttributes()
	if !strings.EqualFold(strings.TrimSpace(firstAttribute(attrs, "source")), "cloud_identity") {
		return nil, nil
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, err
	}
	findingURN := projectionURN(tenantID, "vulnview_finding", firstAttribute(attrs, "finding_id"))
	if findingURN == "" {
		return nil, nil
	}

	sourceID := strings.TrimSpace(event.GetSourceId())
	runtimeID := strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID])
	observation := map[string]string{
		"observation_precedence": "strict",
		"observation_version":    firstAttribute(attrs, "version"),
		"at":                     vulnViewFindingVersionAt(attrs, event),
	}

	consumers, complete := decodeVulnViewFindingConsumers(tenantID, event.GetPayload())
	if !complete {
		return []*ports.ProjectedLinkSet{{
			TenantID:    tenantID,
			SourceID:    sourceID,
			RuntimeID:   runtimeID,
			OwnerURN:    findingURN,
			Relation:    relationAssociatedWith,
			Outgoing:    true,
			Incomplete:  true,
			Observation: observation,
		}}, nil
	}

	eventID := strings.TrimSpace(event.GetId())
	seen := map[string]struct{}{}
	desired := make([]*ports.ProjectedLink, 0, len(consumers))
	endpoints := make([]*ports.ProjectedEntity, 0, len(consumers))
	for _, canonical := range consumers {
		ksaURN := canonical.KSAURN
		if _, dup := seen[ksaURN]; dup {
			continue
		}
		seen[ksaURN] = struct{}{}
		desired = append(desired, &ports.ProjectedLink{
			TenantID:   tenantID,
			SourceID:   sourceID,
			RuntimeID:  runtimeID,
			FromURN:    findingURN,
			ToURN:      ksaURN,
			Relation:   relationAssociatedWith,
			Attributes: map[string]string{"event_id": eventID},
		})
		endpoints = append(endpoints, vulnViewFindingConsumerKSAEntity(tenantID, sourceID, runtimeID, canonical.Consumer, canonical.K8sAttrs, ksaURN))
	}

	return []*ports.ProjectedLinkSet{{
		TenantID:    tenantID,
		SourceID:    sourceID,
		RuntimeID:   runtimeID,
		OwnerURN:    findingURN,
		Relation:    relationAssociatedWith,
		Outgoing:    true,
		Links:       desired,
		Endpoints:   endpoints,
		Observation: observation,
	}}, nil
}

func vulnViewAssetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if assetURN := vulnViewAssetURN(tenantID, attrs); assetURN != "" {
		addEntity(entities, vulnViewAssetEntity(tenantID, event.GetSourceId(), assetURN, attrs))
		hostRaw := vulnViewAssetHostRaw(attrs)
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, assetURN, relationRepresents, hostRaw, "vulnview_asset_host", "0.95")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, hostRaw, "vulnview_asset_domain", "0.85")
		vulnViewAddSiteAndScanContext(entities, links, tenantID, event.GetSourceId(), event, assetURN, "")
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func vulnViewSiteProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entities := map[string]*ports.ProjectedEntity{}
	for _, site := range vulnViewSiteRefs(event.GetAttributes()) {
		addEntity(entities, vulnViewSiteEntity(tenantID, event.GetSourceId(), site))
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func vulnViewScanProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, scan := range vulnViewScanRefs(event.GetAttributes()) {
		scanEntity := vulnViewScanEntity(tenantID, event.GetSourceId(), scan, event.GetAttributes())
		addEntity(entities, scanEntity)
		for _, site := range vulnViewSiteRefs(event.GetAttributes()) {
			siteEntity := vulnViewSiteEntity(tenantID, event.GetSourceId(), site)
			addEntity(entities, siteEntity)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), scanEntity.URN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		vulnViewAddCloudAccountContext(entities, links, tenantID, event.GetSourceId(), event, scanEntity.URN, event.GetAttributes())
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func vulnViewAssetURN(tenantID string, attrs map[string]string) string {
	assetID := vulnViewAssetID(attrs)
	if assetID == "" {
		return ""
	}
	return projectionURN(tenantID, "external_asset", assetID)
}

func vulnViewAssetHostRaw(attrs map[string]string) string {
	return firstAttribute(attrs, "asset_id", "host", "target_id", "matched_at", "target_name", "asset_name")
}

func vulnViewAssetID(attrs map[string]string) string {
	raw := firstAttribute(attrs, "asset_id", "target_id", "host", "matched_at", "target_name")
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		if parsed.Port() != "" {
			return strings.ToLower(parsed.Hostname() + ":" + parsed.Port())
		}
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")))
}

func vulnViewAssetEntity(tenantID string, sourceID string, urn string, attrs map[string]string) *ports.ProjectedEntity {
	assetID := vulnViewAssetID(attrs)
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "external.asset",
		Label:      firstNonEmpty(firstAttribute(attrs, "asset_name", "target_name", "host"), assetID),
		Attributes: map[string]string{
			"asset_id":         assetID,
			"asset_type":       "external_asset",
			"findings_count":   firstAttribute(attrs, "findings_count"),
			"highest_severity": firstAttribute(attrs, "highest_severity", "severity"),
			"source_system":    "vulnview",
			"sites":            firstAttribute(attrs, "sites", "site_name", "site_id"),
		},
	}
}

type vulnViewRef struct {
	URN   string
	ID    string
	Name  string
	Label string
}

func vulnViewAddSiteAndScanContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, assetURN string, evidenceURN string) {
	attrs := event.GetAttributes()
	sites := vulnViewSiteRefs(attrs)
	scans := vulnViewScanRefs(attrs)
	for _, site := range sites {
		siteEntity := vulnViewSiteEntity(tenantID, sourceID, site)
		addEntity(entities, siteEntity)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, assetURN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if evidenceURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, evidenceURN, siteEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	for _, scan := range scans {
		scanEntity := vulnViewScanEntity(tenantID, sourceID, scan, attrs)
		addEntity(entities, scanEntity)
		vulnViewAddCloudAccountContext(entities, links, tenantID, sourceID, event, scanEntity.URN, attrs)
		if assetURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, assetURN, scanEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if evidenceURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, evidenceURN, scanEntity.URN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
}

func vulnViewAddCloudAccountContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, attrs map[string]string) {
	addCloudAccountLink(entities, links, tenantID, sourceID, event, fromURN, firstAttribute(attrs, "cloud_account_id"), firstAttribute(attrs, "cloud_provider"))
}

func vulnViewSiteRefs(attrs map[string]string) []vulnViewRef {
	refs := []vulnViewRef{}
	seen := map[string]struct{}{}
	add := func(id string, name string) {
		id = strings.TrimSpace(id)
		name = strings.TrimSpace(name)
		key := firstNonEmpty(id, name)
		if key == "" {
			return
		}
		dedupe := normalizeIdentifier(firstNonEmpty(id, name))
		if _, ok := seen[dedupe]; ok {
			return
		}
		seen[dedupe] = struct{}{}
		refs = append(refs, vulnViewRef{ID: id, Name: name, Label: firstNonEmpty(name, id)})
	}
	siteNameKeys := []string{"site_name"}
	if strings.EqualFold(strings.TrimSpace(attrs["family"]), "site") {
		siteNameKeys = append(siteNameKeys, "name")
	}
	add(firstAttribute(attrs, "site_id"), firstAttribute(attrs, siteNameKeys...))
	for _, name := range splitVulnViewList(firstAttribute(attrs, "sites")) {
		add("", name)
	}
	return refs
}

func vulnViewScanRefs(attrs map[string]string) []vulnViewRef {
	refs := []vulnViewRef{}
	seen := map[string]struct{}{}
	add := func(id string, name string) {
		id = strings.TrimSpace(id)
		name = strings.TrimSpace(name)
		key := firstNonEmpty(id, name)
		if key == "" {
			return
		}
		dedupe := normalizeIdentifier(key)
		if _, ok := seen[dedupe]; ok {
			return
		}
		seen[dedupe] = struct{}{}
		refs = append(refs, vulnViewRef{ID: id, Name: name, Label: firstNonEmpty(name, id)})
	}
	scanNameKeys := []string{"scan_name"}
	if strings.EqualFold(strings.TrimSpace(attrs["family"]), "scan") {
		scanNameKeys = append(scanNameKeys, "name")
	}
	add(firstAttribute(attrs, "scan_id"), firstAttribute(attrs, scanNameKeys...))
	for _, name := range splitVulnViewList(firstAttribute(attrs, "scan_names")) {
		add("", name)
	}
	return refs
}

func vulnViewSiteEntity(tenantID string, sourceID string, ref vulnViewRef) *ports.ProjectedEntity {
	ref.URN = projectionURN(tenantID, "vulnview_site", firstNonEmpty(ref.Name, ref.ID))
	return &ports.ProjectedEntity{
		URN:        ref.URN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.site",
		Label:      ref.Label,
		Attributes: vulnViewAttributes(map[string]string{
			"site_id":       ref.ID,
			"site_name":     ref.Name,
			"source_system": "vulnview",
		}),
	}
}

func vulnViewScanEntity(tenantID string, sourceID string, ref vulnViewRef, attrs map[string]string) *ports.ProjectedEntity {
	ref.URN = projectionURN(tenantID, "vulnview_scan", firstNonEmpty(ref.Name, ref.ID))
	return &ports.ProjectedEntity{
		URN:        ref.URN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "vulnview.scan",
		Label:      ref.Label,
		Attributes: vulnViewAttributes(map[string]string{
			"cloud_account_id": firstAttribute(attrs, "cloud_account_id"),
			"completed_at":     firstAttribute(attrs, "completed_at"),
			"created_at":       firstAttribute(attrs, "created_at"),
			"findings_count":   firstAttribute(attrs, "findings_count"),
			"results_key":      firstAttribute(attrs, "results_key"),
			"scan_id":          ref.ID,
			"scan_name":        ref.Name,
			"scan_type":        firstAttribute(attrs, "scan_type"),
			"source_system":    "vulnview",
			"started_at":       firstAttribute(attrs, "started_at"),
			"status":           firstAttribute(attrs, "status"),
			"target":           firstAttribute(attrs, "target"),
		}),
	}
}

func vulnViewAttributes(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func splitVulnViewList(raw string) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' }) {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		key := normalizeIdentifier(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, value)
	}
	return values
}
