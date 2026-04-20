package endpointvuln

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/warehouse"
)

const (
	endpointsTableName         = "endpoints"
	endpointSoftwareTableName  = "endpoint_software_inventory"
	vulnerabilitiesTableName   = "vulnerabilities"
	defaultBatchInsertRowCount = 200
)

type threatIntelLookup interface {
	LookupCVE(cve string) (*threatintel.Indicator, bool)
	IsKEV(cve string) bool
}

type advisoryLookup interface {
	LookupCVE(cve string) (*scanner.CVEInfo, bool)
	IsKEV(cve string) bool
}

type Refresher struct {
	Warehouse   warehouse.DataWarehouse
	ThreatIntel threatIntelLookup
	Advisories  advisoryLookup
	Logger      *slog.Logger
	Now         func() time.Time
}

type tableRefresh struct {
	spec tableSpec
	rows []map[string]any
}

type endpointSourceRecord struct {
	Provider                 string
	ProviderAssetID          string
	Hostname                 string
	DisplayName              string
	SerialNumber             string
	OSType                   string
	OSVersion                string
	UserName                 string
	UserEmail                string
	LastSeenAt               time.Time
	MDMEnrolled              *bool
	EDRInstalled             *bool
	MalwareProtectionEnabled *bool
	AntimalwareInstalled     *bool
	FirewallEnabled          *bool
	DiskEncryptionEnabled    *bool
}

type softwareSourceRecord struct {
	Provider        string
	ProviderAssetID string
	Name            string
	Version         string
	Publisher       string
	BundleID        string
	InstalledAt     time.Time
}

type vulnerabilitySourceRecord struct {
	Provider          string
	ProviderAssetID   string
	CVEID             string
	SoftwareName      string
	SoftwareVersion   string
	Severity          string
	Status            string
	CVSSScore         float64
	ExploitedInWild   bool
	DetectedAt        time.Time
	LastDetectedAt    time.Time
	DaysSinceDetected int
	RemediationAction string
	Description       string
	Reference         string
}

type endpointAggregate struct {
	ID                       string
	Hostname                 string
	DisplayName              string
	SerialNumber             string
	OSType                   string
	OSVersion                string
	UserName                 string
	UserEmail                string
	LastSeenAt               time.Time
	CorrelationBasis         string
	CorrelationConfidence    string
	Providers                map[string]struct{}
	ProviderRecords          map[string]struct{}
	MDMEnrolled              bool
	EDRInstalled             bool
	MalwareProtectionEnabled bool
	AntimalwareInstalled     bool
	FirewallEnabled          bool
	DiskEncryptionEnabled    bool
}

type softwareAggregate struct {
	ID                     string
	EndpointID             string
	Hostname               string
	SoftwareName           string
	SoftwareNameNormalized string
	SoftwareVersion        string
	Publisher              string
	BundleID               string
	InstalledAt            time.Time
	LastSeenAt             time.Time
	CorrelationBasis       string
	CorrelationConfidence  string
	Providers              map[string]struct{}
	ProviderRecords        map[string]struct{}
}

type vulnerabilityAggregate struct {
	ID                     string
	CVEID                  string
	AssetID                string
	EndpointID             string
	Hostname               string
	UserEmail              string
	OSType                 string
	SoftwareName           string
	SoftwareNameNormalized string
	SoftwareVersion        string
	Publisher              string
	BundleID               string
	Severity               string
	CVSSScore              float64
	EPSSScore              float64
	EPSSPercentile         float64
	IsKEV                  bool
	KEVDueDate             string
	ExploitedInWild        bool
	HasPublicExploit       bool
	Priority               string
	PriorityScore          float64
	Status                 string
	DetectedAt             time.Time
	LastDetectedAt         time.Time
	DaysOpen               int
	CorrelationBasis       string
	CorrelationConfidence  string
	Providers              map[string]struct{}
	ProviderRecords        map[string]struct{}
	RemediationAction      string
	FixedVersion           string
	Description            string
	References             map[string]struct{}
}

type softwareLookup struct {
	byExact    map[string]*softwareAggregate
	byEndpoint map[string][]*softwareAggregate
}

type tableSpec struct {
	Name    string
	Create  string
	Columns []string
}

var endpointTableSpec = tableSpec{
	Name: endpointsTableName,
	Create: `
CREATE TABLE IF NOT EXISTS endpoints (
	id TEXT,
	hostname TEXT,
	display_name TEXT,
	serial_number TEXT,
	os_type TEXT,
	os_version TEXT,
	user_name TEXT,
	user_email TEXT,
	last_seen_at TIMESTAMP_TZ,
	provider_count INTEGER,
	providers TEXT,
	provider_records TEXT,
	correlation_basis TEXT,
	correlation_confidence TEXT,
	mdm_enrolled BOOLEAN,
	edr_installed BOOLEAN,
	malware_protection_enabled BOOLEAN,
	antimalware_installed BOOLEAN,
	firewall_enabled BOOLEAN,
	disk_encryption_enabled BOOLEAN,
	refreshed_at TIMESTAMP_TZ
)`,
	Columns: []string{
		"id",
		"hostname",
		"display_name",
		"serial_number",
		"os_type",
		"os_version",
		"user_name",
		"user_email",
		"last_seen_at",
		"provider_count",
		"providers",
		"provider_records",
		"correlation_basis",
		"correlation_confidence",
		"mdm_enrolled",
		"edr_installed",
		"malware_protection_enabled",
		"antimalware_installed",
		"firewall_enabled",
		"disk_encryption_enabled",
		"refreshed_at",
	},
}

var endpointSoftwareTableSpec = tableSpec{
	Name: endpointSoftwareTableName,
	Create: `
CREATE TABLE IF NOT EXISTS endpoint_software_inventory (
	id TEXT,
	endpoint_id TEXT,
	hostname TEXT,
	software_name TEXT,
	software_name_normalized TEXT,
	software_version TEXT,
	publisher TEXT,
	bundle_id TEXT,
	installed_at TIMESTAMP_TZ,
	last_seen_at TIMESTAMP_TZ,
	provider_count INTEGER,
	providers TEXT,
	provider_records TEXT,
	correlation_basis TEXT,
	correlation_confidence TEXT,
	refreshed_at TIMESTAMP_TZ
)`,
	Columns: []string{
		"id",
		"endpoint_id",
		"hostname",
		"software_name",
		"software_name_normalized",
		"software_version",
		"publisher",
		"bundle_id",
		"installed_at",
		"last_seen_at",
		"provider_count",
		"providers",
		"provider_records",
		"correlation_basis",
		"correlation_confidence",
		"refreshed_at",
	},
}

var vulnerabilityTableSpec = tableSpec{
	Name: vulnerabilitiesTableName,
	Create: `
CREATE TABLE IF NOT EXISTS vulnerabilities (
	id TEXT,
	cve_id TEXT,
	asset_id TEXT,
	endpoint_id TEXT,
	hostname TEXT,
	user_email TEXT,
	os_type TEXT,
	software_name TEXT,
	software_name_normalized TEXT,
	software_version TEXT,
	publisher TEXT,
	bundle_id TEXT,
	severity TEXT,
	cvss_score FLOAT,
	epss_score FLOAT,
	epss_percentile FLOAT,
	is_kev BOOLEAN,
	kev_due_date TEXT,
	exploited_in_wild BOOLEAN,
	has_public_exploit BOOLEAN,
	priority TEXT,
	priority_score FLOAT,
	status TEXT,
	detected_at TIMESTAMP_TZ,
	last_detected_at TIMESTAMP_TZ,
	days_open INTEGER,
	provider_count INTEGER,
	providers TEXT,
	provider_records TEXT,
	correlation_basis TEXT,
	correlation_confidence TEXT,
	remediation_action TEXT,
	fixed_version TEXT,
	description TEXT,
	references_json TEXT,
	refreshed_at TIMESTAMP_TZ
)`,
	Columns: []string{
		"id",
		"cve_id",
		"asset_id",
		"endpoint_id",
		"hostname",
		"user_email",
		"os_type",
		"software_name",
		"software_name_normalized",
		"software_version",
		"publisher",
		"bundle_id",
		"severity",
		"cvss_score",
		"epss_score",
		"epss_percentile",
		"is_kev",
		"kev_due_date",
		"exploited_in_wild",
		"has_public_exploit",
		"priority",
		"priority_score",
		"status",
		"detected_at",
		"last_detected_at",
		"days_open",
		"provider_count",
		"providers",
		"provider_records",
		"correlation_basis",
		"correlation_confidence",
		"remediation_action",
		"fixed_version",
		"description",
		"references_json",
		"refreshed_at",
	},
}

func (r Refresher) Refresh(ctx context.Context) error {
	if r.Warehouse == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}

	available, err := r.availableTables(ctx)
	if err != nil {
		return fmt.Errorf("list available tables: %w", err)
	}

	endpoints, software, vulnerabilities, err := r.loadSourceData(ctx, available)
	if err != nil {
		return err
	}

	endpointAggs, endpointIDs := correlateEndpoints(endpoints)
	softwareAggs, softwareIndex := correlateSoftware(software, endpointAggs, endpointIDs)
	vulnerabilityAggs := correlateVulnerabilities(vulnerabilities, endpointAggs, endpointIDs, softwareIndex, r.ThreatIntel, r.Advisories, now)

	refreshes := []tableRefresh{
		{spec: endpointTableSpec, rows: endpointRows(endpointAggs, now)},
		{spec: endpointSoftwareTableSpec, rows: softwareRows(softwareAggs, now)},
		{spec: vulnerabilityTableSpec, rows: vulnerabilityRows(vulnerabilityAggs, now)},
	}
	if err := r.replaceRowsAtomically(ctx, refreshes); err != nil {
		return err
	}

	if r.Logger != nil {
		r.Logger.Info("refreshed normalized endpoint vulnerability tables",
			"endpoints", len(endpointAggs),
			"software", len(softwareAggs),
			"vulnerabilities", len(vulnerabilityAggs),
		)
	}

	return nil
}

func (r Refresher) availableTables(ctx context.Context) (map[string]struct{}, error) {
	tables, err := r.Warehouse.ListAvailableTables(ctx)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(tables))
	for _, table := range tables {
		normalized := strings.ToLower(strings.TrimSpace(table))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set, nil
}

func (r Refresher) loadSourceData(ctx context.Context, available map[string]struct{}) ([]endpointSourceRecord, []softwareSourceRecord, []vulnerabilitySourceRecord, error) {
	var (
		endpoints       []endpointSourceRecord
		software        []softwareSourceRecord
		vulnerabilities []vulnerabilitySourceRecord
	)

	loadRows := func(table string) ([]map[string]interface{}, error) {
		if _, ok := available[table]; !ok {
			return nil, nil
		}
		result, err := r.Warehouse.Query(ctx, "SELECT * FROM "+table)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", table, err)
		}
		if result == nil {
			return nil, nil
		}
		return result.Rows, nil
	}

	if rows, err := loadRows("kandji_devices"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := endpointSourceRecord{
				Provider:                 "kandji",
				ProviderAssetID:          rowString(row, "device_id"),
				Hostname:                 firstNonEmpty(rowString(row, "device_name"), rowString(row, "serial_number")),
				DisplayName:              rowString(row, "device_name"),
				SerialNumber:             rowString(row, "serial_number"),
				OSType:                   normalizeOSType(firstNonEmpty(rowString(row, "platform"), rowString(row, "os_type"))),
				OSVersion:                rowString(row, "os_version"),
				UserName:                 rowString(row, "user_name"),
				UserEmail:                rowString(row, "user_email"),
				LastSeenAt:               rowTime(row, "last_check_in"),
				MDMEnrolled:              boolPtr(true),
				EDRInstalled:             rowBoolPointer(row, "agent_installed"),
				MalwareProtectionEnabled: rowBoolPointer(row, "agent_installed"),
				AntimalwareInstalled:     rowBoolPointer(row, "agent_installed"),
				FirewallEnabled:          rowBoolPointer(row, "firewall_enabled"),
				DiskEncryptionEnabled:    rowBoolPointer(row, "filevault_enabled"),
			}
			if record.ProviderAssetID != "" {
				endpoints = append(endpoints, record)
			}
		}
	}

	if rows, err := loadRows("sentinelone_agents"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := endpointSourceRecord{
				Provider:                 "sentinelone",
				ProviderAssetID:          rowString(row, "id"),
				Hostname:                 firstNonEmpty(rowString(row, "computer_name"), rowString(row, "uuid")),
				DisplayName:              rowString(row, "computer_name"),
				SerialNumber:             rowString(row, "serial_number"),
				OSType:                   normalizeOSType(firstNonEmpty(rowString(row, "os_type"), rowString(row, "os_name"))),
				OSVersion:                rowString(row, "os_version"),
				LastSeenAt:               rowTime(row, "last_active_date", "registered_at"),
				EDRInstalled:             boolPtr(true),
				MalwareProtectionEnabled: boolPtr(rowBool(row, "is_active")),
				AntimalwareInstalled:     boolPtr(rowBool(row, "is_active")),
				FirewallEnabled:          rowBoolPointer(row, "firewall_enabled"),
			}
			if record.ProviderAssetID != "" {
				endpoints = append(endpoints, record)
			}
		}
	}

	if rows, err := loadRows("crowdstrike_hosts"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := endpointSourceRecord{
				Provider:                 "crowdstrike",
				ProviderAssetID:          rowString(row, "device_id"),
				Hostname:                 firstNonEmpty(rowString(row, "hostname"), rowString(row, "device_name")),
				DisplayName:              firstNonEmpty(rowString(row, "hostname"), rowString(row, "device_name")),
				OSType:                   normalizeOSType(firstNonEmpty(rowString(row, "platform_name"), rowString(row, "os_name"), rowString(row, "platform"))),
				OSVersion:                rowString(row, "os_version"),
				LastSeenAt:               rowTime(row, "last_seen"),
				EDRInstalled:             boolPtr(true),
				MalwareProtectionEnabled: boolPtr(true),
				AntimalwareInstalled:     boolPtr(true),
			}
			if record.ProviderAssetID != "" {
				endpoints = append(endpoints, record)
			}
		}
	}

	if rows, err := loadRows("kandji_device_apps"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := softwareSourceRecord{
				Provider:        "kandji",
				ProviderAssetID: rowString(row, "device_id"),
				Name:            rowString(row, "app_name"),
				Version:         rowString(row, "version"),
				BundleID:        rowString(row, "bundle_id"),
			}
			if record.ProviderAssetID != "" && record.Name != "" {
				software = append(software, record)
			}
		}
	}

	if rows, err := loadRows("sentinelone_applications"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := softwareSourceRecord{
				Provider:        "sentinelone",
				ProviderAssetID: rowString(row, "agent_id"),
				Name:            firstNonEmpty(rowString(row, "name"), rowString(row, "application_name")),
				Version:         firstNonEmpty(rowString(row, "version"), rowString(row, "application_version")),
				Publisher:       rowString(row, "publisher"),
				BundleID:        rowString(row, "bundle_id"),
				InstalledAt:     rowTime(row, "installed_date"),
			}
			if record.ProviderAssetID != "" && record.Name != "" {
				software = append(software, record)
			}
		}
	}

	if rows, err := loadRows("kandji_vulnerabilities"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := vulnerabilitySourceRecord{
				Provider:        "kandji",
				ProviderAssetID: rowString(row, "device_id"),
				CVEID:           rowString(row, "cve_id"),
				SoftwareName:    firstNonEmpty(rowString(row, "software_name"), rowString(row, "app_name")),
				SoftwareVersion: firstNonEmpty(rowString(row, "software_version"), rowString(row, "version")),
				Severity:        rowString(row, "cvss_severity"),
				CVSSScore:       rowFloat(row, "cvss_score"),
				DetectedAt:      rowTime(row, "first_detection_date"),
				LastDetectedAt:  rowTime(row, "latest_detection_date"),
				Reference:       rowString(row, "cve_link"),
			}
			if record.ProviderAssetID != "" && record.CVEID != "" {
				vulnerabilities = append(vulnerabilities, record)
			}
		}
	}

	if rows, err := loadRows("sentinelone_vulnerabilities"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := vulnerabilitySourceRecord{
				Provider:          "sentinelone",
				ProviderAssetID:   rowString(row, "agent_id"),
				CVEID:             rowString(row, "cve_id"),
				SoftwareName:      firstNonEmpty(rowString(row, "application_name"), rowString(row, "name")),
				SoftwareVersion:   firstNonEmpty(rowString(row, "application_version"), rowString(row, "version")),
				Severity:          rowString(row, "severity"),
				Status:            rowString(row, "status"),
				CVSSScore:         rowFloat(row, "cvss_score"),
				ExploitedInWild:   rowBool(row, "exploited_in_wild"),
				DetectedAt:        rowTime(row, "detected_at"),
				DaysSinceDetected: rowInt(row, "days_since_detection"),
				RemediationAction: rowString(row, "remediation_action"),
			}
			if record.ProviderAssetID != "" && record.CVEID != "" {
				vulnerabilities = append(vulnerabilities, record)
			}
		}
	}

	if rows, err := loadRows("crowdstrike_vulnerabilities"); err != nil {
		return nil, nil, nil, err
	} else {
		for _, row := range rows {
			record := vulnerabilitySourceRecord{
				Provider:          "crowdstrike",
				ProviderAssetID:   firstNonEmpty(rowString(row, "host_id"), rowString(row, "device_id")),
				CVEID:             rowString(row, "cve_id"),
				SoftwareName:      rowString(row, "app_name"),
				SoftwareVersion:   rowString(row, "app_version"),
				Severity:          rowString(row, "severity"),
				Status:            rowString(row, "status"),
				ExploitedInWild:   rowBool(row, "exploit_available"),
				DetectedAt:        rowTime(row, "created_at", "first_found"),
				LastDetectedAt:    rowTime(row, "updated_at", "last_found"),
				RemediationAction: rowString(row, "remediation_action", "solution"),
			}
			if record.ProviderAssetID != "" && record.CVEID != "" {
				vulnerabilities = append(vulnerabilities, record)
			}
		}
	}

	return endpoints, software, vulnerabilities, nil
}

func correlateEndpoints(records []endpointSourceRecord) (map[string]*endpointAggregate, map[string]string) {
	hostToSerial := make(map[string]string)
	ambiguousHosts := make(map[string]struct{})

	for _, record := range records {
		hostKey := endpointHostKey(record)
		serialKey := endpointSerialKey(record)
		if hostKey == "" || serialKey == "" {
			continue
		}
		if existing, ok := hostToSerial[hostKey]; ok && existing != serialKey {
			ambiguousHosts[hostKey] = struct{}{}
			continue
		}
		hostToSerial[hostKey] = serialKey
	}
	for hostKey := range ambiguousHosts {
		delete(hostToSerial, hostKey)
	}

	aggregates := make(map[string]*endpointAggregate)
	endpointIDs := make(map[string]string)

	for _, record := range records {
		if strings.TrimSpace(record.ProviderAssetID) == "" {
			continue
		}
		identityKey, basis, confidence := endpointIdentity(record, hostToSerial)
		aggregateID := "endpoint-" + stableHash(identityKey)
		endpointIDs[providerRecordKey(record.Provider, record.ProviderAssetID)] = aggregateID

		aggregate, ok := aggregates[aggregateID]
		if !ok {
			aggregate = &endpointAggregate{
				ID:                    aggregateID,
				CorrelationBasis:      basis,
				CorrelationConfidence: confidence,
				Providers:             make(map[string]struct{}),
				ProviderRecords:       make(map[string]struct{}),
			}
			aggregates[aggregateID] = aggregate
		}

		aggregate.Hostname = preferLongerString(aggregate.Hostname, normalizeDisplayName(record.Hostname))
		aggregate.DisplayName = preferLongerString(aggregate.DisplayName, normalizeDisplayName(record.DisplayName))
		aggregate.SerialNumber = firstNonEmpty(aggregate.SerialNumber, record.SerialNumber)
		aggregate.OSType = firstNonEmpty(aggregate.OSType, normalizeOSType(record.OSType))
		aggregate.OSVersion = firstNonEmpty(aggregate.OSVersion, record.OSVersion)
		aggregate.UserName = firstNonEmpty(aggregate.UserName, record.UserName)
		aggregate.UserEmail = firstNonEmpty(aggregate.UserEmail, record.UserEmail)
		if record.LastSeenAt.After(aggregate.LastSeenAt) {
			aggregate.LastSeenAt = record.LastSeenAt.UTC()
		}
		if confidenceRank(confidence) > confidenceRank(aggregate.CorrelationConfidence) {
			aggregate.CorrelationConfidence = confidence
			aggregate.CorrelationBasis = basis
		}
		aggregate.Providers[record.Provider] = struct{}{}
		aggregate.ProviderRecords[providerRecordKey(record.Provider, record.ProviderAssetID)] = struct{}{}
		aggregate.MDMEnrolled = aggregate.MDMEnrolled || derefBool(record.MDMEnrolled)
		aggregate.EDRInstalled = aggregate.EDRInstalled || derefBool(record.EDRInstalled)
		aggregate.MalwareProtectionEnabled = aggregate.MalwareProtectionEnabled || derefBool(record.MalwareProtectionEnabled)
		aggregate.AntimalwareInstalled = aggregate.AntimalwareInstalled || derefBool(record.AntimalwareInstalled)
		aggregate.FirewallEnabled = aggregate.FirewallEnabled || derefBool(record.FirewallEnabled)
		aggregate.DiskEncryptionEnabled = aggregate.DiskEncryptionEnabled || derefBool(record.DiskEncryptionEnabled)
	}

	return aggregates, endpointIDs
}

func correlateSoftware(records []softwareSourceRecord, endpoints map[string]*endpointAggregate, endpointIDs map[string]string) ([]*softwareAggregate, softwareLookup) {
	aggregates := make(map[string]*softwareAggregate)
	for _, record := range records {
		endpointID := endpointIDs[providerRecordKey(record.Provider, record.ProviderAssetID)]
		if endpointID == "" {
			continue
		}

		name := strings.TrimSpace(record.Name)
		version := strings.TrimSpace(record.Version)
		canonicalName := canonicalSoftwareName(record.Name, record.BundleID)
		if canonicalName == "" {
			continue
		}
		key := strings.Join([]string{endpointID, canonicalName, normalizeVersion(version)}, "|")
		aggregateID := "software-" + stableHash(key)

		aggregate, ok := aggregates[aggregateID]
		if !ok {
			aggregate = &softwareAggregate{
				ID:                     aggregateID,
				EndpointID:             endpointID,
				SoftwareNameNormalized: normalizeSoftwareName(name),
				SoftwareVersion:        version,
				Providers:              make(map[string]struct{}),
				ProviderRecords:        make(map[string]struct{}),
			}
			if endpoint := endpoints[endpointID]; endpoint != nil {
				aggregate.Hostname = endpoint.Hostname
				aggregate.LastSeenAt = endpoint.LastSeenAt
				aggregate.CorrelationBasis = endpoint.CorrelationBasis
				aggregate.CorrelationConfidence = endpoint.CorrelationConfidence
			}
			aggregates[aggregateID] = aggregate
		}

		aggregate.SoftwareName = preferLongerString(aggregate.SoftwareName, name)
		aggregate.SoftwareNameNormalized = firstNonEmpty(aggregate.SoftwareNameNormalized, normalizeSoftwareName(name))
		aggregate.SoftwareVersion = firstNonEmpty(aggregate.SoftwareVersion, version)
		aggregate.Publisher = firstNonEmpty(aggregate.Publisher, record.Publisher)
		aggregate.BundleID = firstNonEmpty(aggregate.BundleID, record.BundleID)
		if !record.InstalledAt.IsZero() && (aggregate.InstalledAt.IsZero() || record.InstalledAt.Before(aggregate.InstalledAt)) {
			aggregate.InstalledAt = record.InstalledAt.UTC()
		}
		if record.InstalledAt.After(aggregate.LastSeenAt) {
			aggregate.LastSeenAt = record.InstalledAt.UTC()
		}
		aggregate.Providers[record.Provider] = struct{}{}
		aggregate.ProviderRecords[providerRecordKey(record.Provider, record.ProviderAssetID)] = struct{}{}
	}

	list := make([]*softwareAggregate, 0, len(aggregates))
	lookup := softwareLookup{
		byExact:    make(map[string]*softwareAggregate, len(aggregates)),
		byEndpoint: make(map[string][]*softwareAggregate),
	}
	for _, aggregate := range aggregates {
		list = append(list, aggregate)
		exactKey := strings.Join([]string{aggregate.EndpointID, aggregate.SoftwareNameNormalized, normalizeVersion(aggregate.SoftwareVersion)}, "|")
		lookup.byExact[exactKey] = aggregate
		lookup.byEndpoint[aggregate.EndpointID] = append(lookup.byEndpoint[aggregate.EndpointID], aggregate)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	for endpointID := range lookup.byEndpoint {
		sort.Slice(lookup.byEndpoint[endpointID], func(i, j int) bool {
			return lookup.byEndpoint[endpointID][i].ID < lookup.byEndpoint[endpointID][j].ID
		})
	}
	return list, lookup
}

func correlateVulnerabilities(records []vulnerabilitySourceRecord, endpoints map[string]*endpointAggregate, endpointIDs map[string]string, softwareIndex softwareLookup, intel threatIntelLookup, advisories advisoryLookup, now time.Time) []*vulnerabilityAggregate {
	aggregates := make(map[string]*vulnerabilityAggregate)

	for _, record := range records {
		endpointID := endpointIDs[providerRecordKey(record.Provider, record.ProviderAssetID)]
		if endpointID == "" {
			continue
		}
		cveID := normalizeCVE(record.CVEID)
		if cveID == "" {
			continue
		}

		endpoint := endpoints[endpointID]
		matchedSoftware := softwareIndex.match(endpointID, record.SoftwareName, record.SoftwareVersion)

		softwareName := strings.TrimSpace(record.SoftwareName)
		softwareVersion := strings.TrimSpace(record.SoftwareVersion)
		softwareNameNormalized := normalizeSoftwareName(softwareName)
		publisher := ""
		bundleID := ""
		if matchedSoftware != nil {
			softwareName = firstNonEmpty(matchedSoftware.SoftwareName, softwareName)
			softwareVersion = firstNonEmpty(matchedSoftware.SoftwareVersion, softwareVersion)
			softwareNameNormalized = firstNonEmpty(matchedSoftware.SoftwareNameNormalized, softwareNameNormalized)
			publisher = matchedSoftware.Publisher
			bundleID = matchedSoftware.BundleID
		}
		if softwareNameNormalized == "" {
			softwareNameNormalized = normalizeSoftwareName(softwareName)
		}
		if softwareNameNormalized == "" {
			softwareNameNormalized = "unknown"
		}

		key := strings.Join([]string{
			endpointID,
			cveID,
			softwareNameNormalized,
			normalizeVersion(softwareVersion),
		}, "|")
		aggregateID := "vuln-" + stableHash(key)

		aggregate, ok := aggregates[aggregateID]
		if !ok {
			aggregate = &vulnerabilityAggregate{
				ID:                    aggregateID,
				CVEID:                 cveID,
				AssetID:               endpointID,
				EndpointID:            endpointID,
				Hostname:              "",
				Status:                "",
				Providers:             make(map[string]struct{}),
				ProviderRecords:       make(map[string]struct{}),
				CorrelationBasis:      "provider_id",
				CorrelationConfidence: "low",
				References:            make(map[string]struct{}),
			}
			if endpoint != nil {
				aggregate.Hostname = endpoint.Hostname
				aggregate.UserEmail = endpoint.UserEmail
				aggregate.OSType = endpoint.OSType
				aggregate.CorrelationBasis = endpoint.CorrelationBasis
				aggregate.CorrelationConfidence = endpoint.CorrelationConfidence
			}
			aggregates[aggregateID] = aggregate
		}

		aggregate.SoftwareName = preferLongerString(aggregate.SoftwareName, softwareName)
		aggregate.SoftwareNameNormalized = firstNonEmpty(aggregate.SoftwareNameNormalized, softwareNameNormalized)
		aggregate.SoftwareVersion = firstNonEmpty(aggregate.SoftwareVersion, softwareVersion)
		aggregate.Publisher = firstNonEmpty(aggregate.Publisher, publisher)
		aggregate.BundleID = firstNonEmpty(aggregate.BundleID, bundleID)
		aggregate.Status = mergeVulnerabilityStatus(aggregate.Status, record.Status)
		aggregate.Severity = chooseHigherSeverity(aggregate.Severity, record.Severity)
		if record.CVSSScore > aggregate.CVSSScore {
			aggregate.CVSSScore = record.CVSSScore
		}
		aggregate.ExploitedInWild = aggregate.ExploitedInWild || record.ExploitedInWild
		aggregate.RemediationAction = firstNonEmpty(aggregate.RemediationAction, record.RemediationAction)
		aggregate.Description = firstNonEmpty(aggregate.Description, record.Description)
		if reference := strings.TrimSpace(record.Reference); reference != "" {
			aggregate.References[reference] = struct{}{}
		}

		detectedAt, lastDetectedAt := detectionWindow(record, endpoint, now)
		if aggregate.DetectedAt.IsZero() || (!detectedAt.IsZero() && detectedAt.Before(aggregate.DetectedAt)) {
			aggregate.DetectedAt = detectedAt
		}
		if lastDetectedAt.After(aggregate.LastDetectedAt) {
			aggregate.LastDetectedAt = lastDetectedAt
		}

		aggregate.Providers[record.Provider] = struct{}{}
		aggregate.ProviderRecords[providerRecordKey(record.Provider, record.ProviderAssetID)] = struct{}{}
	}

	list := make([]*vulnerabilityAggregate, 0, len(aggregates))
	for _, aggregate := range aggregates {
		if aggregate.Status == "" {
			aggregate.Status = "open"
		}
		enrichVulnerability(aggregate, intel, advisories, now)
		list = append(list, aggregate)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return list
}

func endpointRows(aggregates map[string]*endpointAggregate, refreshedAt time.Time) []map[string]any {
	keys := make([]string, 0, len(aggregates))
	for key := range aggregates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	rows := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		aggregate := aggregates[key]
		rows = append(rows, map[string]any{
			"id":                         aggregate.ID,
			"hostname":                   nullableString(aggregate.Hostname),
			"display_name":               nullableString(firstNonEmpty(aggregate.DisplayName, aggregate.Hostname)),
			"serial_number":              nullableString(aggregate.SerialNumber),
			"os_type":                    nullableString(aggregate.OSType),
			"os_version":                 nullableString(aggregate.OSVersion),
			"user_name":                  nullableString(aggregate.UserName),
			"user_email":                 nullableString(aggregate.UserEmail),
			"last_seen_at":               nullableTime(aggregate.LastSeenAt),
			"provider_count":             len(aggregate.Providers),
			"providers":                  providersString(aggregate.Providers),
			"provider_records":           jsonString(sortedKeys(aggregate.ProviderRecords)),
			"correlation_basis":          aggregate.CorrelationBasis,
			"correlation_confidence":     aggregate.CorrelationConfidence,
			"mdm_enrolled":               aggregate.MDMEnrolled,
			"edr_installed":              aggregate.EDRInstalled,
			"malware_protection_enabled": aggregate.MalwareProtectionEnabled,
			"antimalware_installed":      aggregate.AntimalwareInstalled,
			"firewall_enabled":           aggregate.FirewallEnabled,
			"disk_encryption_enabled":    aggregate.DiskEncryptionEnabled,
			"refreshed_at":               refreshedAt.UTC(),
		})
	}
	return rows
}

func softwareRows(aggregates []*softwareAggregate, refreshedAt time.Time) []map[string]any {
	rows := make([]map[string]any, 0, len(aggregates))
	for _, aggregate := range aggregates {
		rows = append(rows, map[string]any{
			"id":                       aggregate.ID,
			"endpoint_id":              aggregate.EndpointID,
			"hostname":                 nullableString(aggregate.Hostname),
			"software_name":            nullableString(aggregate.SoftwareName),
			"software_name_normalized": aggregate.SoftwareNameNormalized,
			"software_version":         nullableString(aggregate.SoftwareVersion),
			"publisher":                nullableString(aggregate.Publisher),
			"bundle_id":                nullableString(aggregate.BundleID),
			"installed_at":             nullableTime(aggregate.InstalledAt),
			"last_seen_at":             nullableTime(aggregate.LastSeenAt),
			"provider_count":           len(aggregate.Providers),
			"providers":                providersString(aggregate.Providers),
			"provider_records":         jsonString(sortedKeys(aggregate.ProviderRecords)),
			"correlation_basis":        aggregate.CorrelationBasis,
			"correlation_confidence":   aggregate.CorrelationConfidence,
			"refreshed_at":             refreshedAt.UTC(),
		})
	}
	return rows
}

func vulnerabilityRows(aggregates []*vulnerabilityAggregate, refreshedAt time.Time) []map[string]any {
	rows := make([]map[string]any, 0, len(aggregates))
	for _, aggregate := range aggregates {
		rows = append(rows, map[string]any{
			"id":                       aggregate.ID,
			"cve_id":                   aggregate.CVEID,
			"asset_id":                 aggregate.AssetID,
			"endpoint_id":              aggregate.EndpointID,
			"hostname":                 nullableString(aggregate.Hostname),
			"user_email":               nullableString(aggregate.UserEmail),
			"os_type":                  nullableString(aggregate.OSType),
			"software_name":            nullableString(aggregate.SoftwareName),
			"software_name_normalized": aggregate.SoftwareNameNormalized,
			"software_version":         nullableString(aggregate.SoftwareVersion),
			"publisher":                nullableString(aggregate.Publisher),
			"bundle_id":                nullableString(aggregate.BundleID),
			"severity":                 aggregate.Severity,
			"cvss_score":               aggregate.CVSSScore,
			"epss_score":               aggregate.EPSSScore,
			"epss_percentile":          aggregate.EPSSPercentile,
			"is_kev":                   aggregate.IsKEV,
			"kev_due_date":             nullableString(aggregate.KEVDueDate),
			"exploited_in_wild":        aggregate.ExploitedInWild,
			"has_public_exploit":       aggregate.HasPublicExploit,
			"priority":                 aggregate.Priority,
			"priority_score":           aggregate.PriorityScore,
			"status":                   aggregate.Status,
			"detected_at":              nullableTime(aggregate.DetectedAt),
			"last_detected_at":         nullableTime(aggregate.LastDetectedAt),
			"days_open":                aggregate.DaysOpen,
			"provider_count":           len(aggregate.Providers),
			"providers":                providersString(aggregate.Providers),
			"provider_records":         jsonString(sortedKeys(aggregate.ProviderRecords)),
			"correlation_basis":        aggregate.CorrelationBasis,
			"correlation_confidence":   aggregate.CorrelationConfidence,
			"remediation_action":       nullableString(aggregate.RemediationAction),
			"fixed_version":            nullableString(aggregate.FixedVersion),
			"description":              nullableString(aggregate.Description),
			"references_json":          jsonString(sortedKeys(aggregate.References)),
			"refreshed_at":             refreshedAt.UTC(),
		})
	}
	return rows
}

func (r Refresher) replaceRowsAtomically(ctx context.Context, refreshes []tableRefresh) error {
	db := r.Warehouse.DB()
	if db == nil {
		return fmt.Errorf("warehouse database is not initialized")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin normalized table refresh: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	dialect := warehouse.DialectFor(r.Warehouse)
	for _, refresh := range refreshes {
		if err := execWarehouseTx(ctx, tx, dialect, refresh.spec.Create); err != nil {
			return fmt.Errorf("ensure %s: %w", refresh.spec.Name, err)
		}
		if err := r.replaceRowsTx(ctx, tx, dialect, refresh.spec, refresh.rows); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit normalized table refresh: %w", err)
	}
	committed = true
	return nil
}

func (r Refresher) replaceRowsTx(ctx context.Context, tx *sql.Tx, dialect string, spec tableSpec, rows []map[string]any) error {
	if err := execWarehouseTx(ctx, tx, dialect, "DELETE FROM "+spec.Name); err != nil {
		return fmt.Errorf("clear %s: %w", spec.Name, err)
	}
	if len(rows) == 0 {
		return nil
	}

	insertQuery := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		spec.Name,
		strings.Join(spec.Columns, ", "),
		strings.TrimRight(strings.Repeat("?, ", len(spec.Columns)), ", "),
	)

	for start := 0; start < len(rows); start += defaultBatchInsertRowCount {
		end := start + defaultBatchInsertRowCount
		if end > len(rows) {
			end = len(rows)
		}
		for _, row := range rows[start:end] {
			args := make([]any, 0, len(spec.Columns))
			for _, column := range spec.Columns {
				args = append(args, row[column])
			}
			if err := execWarehouseTx(ctx, tx, dialect, insertQuery, args...); err != nil {
				return fmt.Errorf("insert into %s: %w", spec.Name, err)
			}
		}
	}

	return nil
}

func execWarehouseTx(ctx context.Context, tx *sql.Tx, dialect string, query string, args ...any) error {
	if tx == nil {
		return fmt.Errorf("warehouse transaction is not initialized")
	}
	if _, err := tx.ExecContext(ctx, warehouse.RewriteQueryForDialect(query, dialect), args...); err != nil {
		return err
	}
	return nil
}

func enrichVulnerability(aggregate *vulnerabilityAggregate, intel threatIntelLookup, advisories advisoryLookup, now time.Time) {
	if aggregate == nil {
		return
	}

	if advisories != nil {
		if advisory, ok := advisories.LookupCVE(aggregate.CVEID); ok && advisory != nil {
			aggregate.CVSSScore = maxFloat(aggregate.CVSSScore, advisory.CVSS)
			aggregate.EPSSScore = maxFloat(aggregate.EPSSScore, advisory.EPSSScore)
			aggregate.EPSSPercentile = maxFloat(aggregate.EPSSPercentile, advisory.EPSSPercentile)
			aggregate.IsKEV = aggregate.IsKEV || advisory.InKEV || advisories.IsKEV(aggregate.CVEID)
			aggregate.ExploitedInWild = aggregate.ExploitedInWild || advisory.Exploitable || aggregate.IsKEV
			aggregate.Severity = chooseHigherSeverity(aggregate.Severity, advisory.Severity)
			aggregate.Description = firstNonEmpty(aggregate.Description, advisory.Description)
			for _, reference := range advisory.References {
				if trimmed := strings.TrimSpace(reference); trimmed != "" {
					aggregate.References[trimmed] = struct{}{}
				}
			}
		}
	}

	if intel != nil {
		if indicator, ok := intel.LookupCVE(aggregate.CVEID); ok && indicator != nil {
			aggregate.IsKEV = aggregate.IsKEV || intel.IsKEV(aggregate.CVEID)
			aggregate.Description = firstNonEmpty(aggregate.Description, indicator.Description)
			if dueDate := strings.TrimSpace(indicator.Metadata["due_date"]); dueDate != "" {
				aggregate.KEVDueDate = dueDate
			}
		}
	}

	if aggregate.CVSSScore > 0 {
		aggregate.Severity = chooseHigherSeverity(aggregate.Severity, severityFromScore(aggregate.CVSSScore))
	}
	if aggregate.Severity == "" {
		aggregate.Severity = "UNKNOWN"
	}

	aggregate.HasPublicExploit = aggregate.HasPublicExploit || aggregate.ExploitedInWild || aggregate.IsKEV
	aggregate.ExploitedInWild = aggregate.ExploitedInWild || aggregate.IsKEV

	if aggregate.DetectedAt.IsZero() && !aggregate.LastDetectedAt.IsZero() {
		aggregate.DetectedAt = aggregate.LastDetectedAt
	}
	if aggregate.LastDetectedAt.IsZero() && !aggregate.DetectedAt.IsZero() {
		aggregate.LastDetectedAt = aggregate.DetectedAt
	}
	if !aggregate.DetectedAt.IsZero() {
		aggregate.DaysOpen = int(now.Sub(aggregate.DetectedAt).Hours() / 24)
		if aggregate.DaysOpen < 0 {
			aggregate.DaysOpen = 0
		}
	}

	var epss *threatintel.EPSSScore
	if aggregate.EPSSScore > 0 || aggregate.EPSSPercentile > 0 {
		epss = &threatintel.EPSSScore{
			CVE:        aggregate.CVEID,
			EPSS:       aggregate.EPSSScore,
			Percentile: aggregate.EPSSPercentile,
		}
	}
	risk := threatintel.CalculateVulnerabilityRisk(aggregate.CVSSScore, epss, aggregate.IsKEV, aggregate.HasPublicExploit)
	if risk != nil {
		aggregate.Priority = firstNonEmpty(aggregate.Priority, strings.TrimSpace(risk.Priority))
		aggregate.PriorityScore = maxFloat(aggregate.PriorityScore, risk.CompositeScore)
	}
	if aggregate.Priority == "" {
		aggregate.Priority = strings.ToLower(strings.TrimSpace(aggregate.Severity))
	}
}

func (l softwareLookup) match(endpointID, name, version string) *softwareAggregate {
	nameKey := normalizeSoftwareName(name)
	versionKey := normalizeVersion(version)
	if endpointID == "" || nameKey == "" {
		return nil
	}
	if exact, ok := l.byExact[strings.Join([]string{endpointID, nameKey, versionKey}, "|")]; ok {
		return exact
	}
	for _, candidate := range l.byEndpoint[endpointID] {
		if candidate == nil {
			continue
		}
		if versionKey != "" && normalizeVersion(candidate.SoftwareVersion) != versionKey {
			continue
		}
		candidateName := candidate.SoftwareNameNormalized
		if candidateName == "" {
			candidateName = normalizeSoftwareName(candidate.SoftwareName)
		}
		if candidateName == nameKey || strings.Contains(candidateName, nameKey) || strings.Contains(nameKey, candidateName) {
			return candidate
		}
	}
	return nil
}

func endpointIdentity(record endpointSourceRecord, hostToSerial map[string]string) (string, string, string) {
	if serialKey := endpointSerialKey(record); serialKey != "" {
		return serialKey, "serial_number", "high"
	}
	if hostKey := endpointHostKey(record); hostKey != "" {
		if serialKey, ok := hostToSerial[hostKey]; ok && serialKey != "" {
			return serialKey, "hostname_os", "medium"
		}
		return hostKey, "hostname_os", "medium"
	}
	return "provider:" + providerRecordKey(record.Provider, record.ProviderAssetID), "provider_id", "low"
}

func endpointSerialKey(record endpointSourceRecord) string {
	serial := normalizeIdentifier(record.SerialNumber)
	if serial == "" {
		return ""
	}
	return "serial:" + serial
}

func endpointHostKey(record endpointSourceRecord) string {
	host := normalizeHostname(firstNonEmpty(record.Hostname, record.DisplayName))
	if host == "" {
		return ""
	}
	osType := normalizeOSType(record.OSType)
	if osType == "" {
		return ""
	}
	return "host:" + host + "|os:" + osType
}

func canonicalSoftwareName(name, bundleID string) string {
	if normalizedName := normalizeSoftwareName(name); normalizedName != "" {
		return "name:" + normalizedName
	}
	if normalizedBundle := strings.ToLower(strings.TrimSpace(bundleID)); normalizedBundle != "" {
		return "bundle:" + normalizedBundle
	}
	return ""
}

func detectionWindow(record vulnerabilitySourceRecord, endpoint *endpointAggregate, now time.Time) (time.Time, time.Time) {
	detectedAt := record.DetectedAt
	lastDetectedAt := record.LastDetectedAt
	if detectedAt.IsZero() && record.DaysSinceDetected > 0 {
		detectedAt = now.AddDate(0, 0, -record.DaysSinceDetected)
	}
	if detectedAt.IsZero() && endpoint != nil && !endpoint.LastSeenAt.IsZero() {
		detectedAt = endpoint.LastSeenAt
	}
	if detectedAt.IsZero() {
		detectedAt = now
	}
	if lastDetectedAt.IsZero() {
		lastDetectedAt = detectedAt
	}
	return detectedAt.UTC(), lastDetectedAt.UTC()
}

func rowValue(row map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			return value, true
		}
		lower := strings.ToLower(key)
		if value, ok := row[lower]; ok {
			return value, true
		}
		for existingKey, value := range row {
			if strings.EqualFold(existingKey, key) {
				return value, true
			}
		}
	}
	return nil, false
}

func rowString(row map[string]interface{}, keys ...string) string {
	value, ok := rowValue(row, keys...)
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func rowBoolPointer(row map[string]interface{}, keys ...string) *bool {
	value, ok := rowValue(row, keys...)
	if !ok {
		return nil
	}
	parsed := boolPtr(parseBool(value))
	return parsed
}

func rowBool(row map[string]interface{}, keys ...string) bool {
	value, ok := rowValue(row, keys...)
	if !ok {
		return false
	}
	return parseBool(value)
}

func rowFloat(row map[string]interface{}, keys ...string) float64 {
	value, ok := rowValue(row, keys...)
	if !ok {
		return 0
	}
	return parseFloat(value)
}

func rowInt(row map[string]interface{}, keys ...string) int {
	value, ok := rowValue(row, keys...)
	if !ok {
		return 0
	}
	return int(parseFloat(value))
}

func rowTime(row map[string]interface{}, keys ...string) time.Time {
	value, ok := rowValue(row, keys...)
	if !ok || value == nil {
		return time.Time{}
	}
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		return parseTimeString(typed)
	case []byte:
		return parseTimeString(string(typed))
	case int64:
		return time.Unix(typed, 0).UTC()
	case float64:
		return time.Unix(int64(typed), 0).UTC()
	default:
		return parseTimeString(fmt.Sprintf("%v", value))
	}
}

func parseBool(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	case []byte:
		switch strings.ToLower(strings.TrimSpace(string(typed))) {
		case "1", "true", "t", "yes", "y":
			return true
		default:
			return false
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "t", "yes", "y":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func parseFloat(value interface{}) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case int32:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	case []byte:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(string(typed)), 64)
		return parsed
	default:
		return 0
	}
}

func parseTimeString(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		time.DateOnly,
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func normalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "."); idx > 0 {
		value = value[:idx]
	}
	return value
}

func normalizeDisplayName(value string) string {
	return strings.TrimSpace(value)
}

func normalizeOSType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "":
		return ""
	case strings.Contains(value, "mac"):
		return "macos"
	case strings.Contains(value, "windows"):
		return "windows"
	case strings.Contains(value, "linux"):
		return "linux"
	default:
		return value
	}
}

func normalizeSoftwareName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	prevSpace := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace && builder.Len() > 0 {
				builder.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "v")
	return value
}

func normalizeIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	prevDash := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_' || r == '.' || r == '/':
			if builder.Len() > 0 && !prevDash {
				builder.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func normalizeCVE(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return value
}

func normalizeSeverity(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "":
		return "UNKNOWN"
	case "MODERATE":
		return "MEDIUM"
	case "INFO", "INFORMATIONAL", "NEGLIGIBLE":
		return "LOW"
	default:
		return value
	}
}

func normalizeVulnerabilityStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "":
		return ""
	case "new", "open", "active", "reopened", "unresolved", "in_progress":
		return "open"
	case "closed", "resolved", "fixed", "remediated":
		return "resolved"
	default:
		return value
	}
}

func mergeVulnerabilityStatus(current, candidate string) string {
	current = normalizeVulnerabilityStatus(current)
	candidate = normalizeVulnerabilityStatus(candidate)
	switch {
	case current == "":
		return candidate
	case candidate == "":
		return current
	case current == "open" || candidate == "open":
		return "open"
	default:
		return candidate
	}
}

func chooseHigherSeverity(current, candidate string) string {
	current = normalizeSeverity(current)
	candidate = normalizeSeverity(candidate)
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

func severityRank(value string) int {
	switch normalizeSeverity(value) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func providerRecordKey(provider, id string) string {
	return strings.TrimSpace(provider) + ":" + strings.TrimSpace(id)
}

func providersString(values map[string]struct{}) string {
	return strings.Join(sortedKeys(values), ",")
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stableHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func jsonString(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

func nullableString(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func preferLongerString(current, candidate string) string {
	current = strings.TrimSpace(current)
	candidate = strings.TrimSpace(candidate)
	switch {
	case current == "":
		return candidate
	case candidate == "":
		return current
	case len(candidate) > len(current):
		return candidate
	default:
		return current
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func maxFloat(current, candidate float64) float64 {
	if candidate > current {
		return candidate
	}
	return current
}

func boolPtr(value bool) *bool {
	return &value
}

func derefBool(value *bool) bool {
	return value != nil && *value
}
