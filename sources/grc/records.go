package grc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type grcRecord struct {
	Raw    json.RawMessage
	Values map[string]any
	ID     string
}

func parseRecord(family grcFamily, raw json.RawMessage) (grcRecord, error) {
	values := map[string]any{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return grcRecord{}, fmt.Errorf("decode grc %s record: %w", string(family), err)
	}
	id := recordID(family, values, raw)
	return grcRecord{
		Raw:    append(json.RawMessage(nil), raw...),
		Values: values,
		ID:     id,
	}, nil
}

func urnsFor(settings settings, family grcFamily, records []grcRecord) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:grc_%s:%s:%s", settings.tenantID, string(family), settings.provider, record.ID))
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords(settings settings, family grcFamily, records []grcRecord, next string) (sourcecdk.Pull, error) {
	return sourcecdk.PullFromRecords(records, next,
		func(rec grcRecord) (*primitives.Event, error) {
			return eventFromRecord(settings, family, rec), nil
		},
		func(rec grcRecord) string { return strings.TrimSpace(rec.ID) },
	)
}

func eventFromRecord(settings settings, family grcFamily, record grcRecord) *primitives.Event {
	occurredAt := occurredAtFor(family, record.Values)
	payload := append([]byte(nil), record.Raw...)
	return &primitives.Event{
		Id:         grcEventID(settings, family, record.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       "grc." + string(family),
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "grc/" + string(family) + "/v1",
		Payload:    payload,
		Attributes: attributesFor(settings, family, record),
	}
}

func grcEventID(settings settings, family grcFamily, recordID string) string {
	return strings.Join([]string{
		"grc",
		normalizeID(settings.provider),
		normalizeID(settings.tenantID),
		grcRuntimeScope(settings),
		normalizeID(string(family)),
		normalizeID(recordID),
	}, "-")
}

func grcRuntimeScope(settings settings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		settings.baseURL,
		settings.clientID,
		settings.scope,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func recordID(family grcFamily, values map[string]any, raw json.RawMessage) string {
	for _, key := range recordIDKeys(family) {
		if value := fieldString(values, key); value != "" {
			return normalizeID(value)
		}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func recordIDKeys(family grcFamily) []string {
	switch family {
	case familyRiskScenario:
		return []string{"riskId", "id"}
	case familyIntegration:
		return []string{"integrationId", "id"}
	case familyPerson:
		return []string{"id", "userId", "emailAddress"}
	case familyUser:
		return []string{"id", "email"}
	case familyVulnerableAsset:
		return []string{"id", "assetId", "targetId", "externalId", "name"}
	case familyMonitoredComputer:
		return []string{"id", "serialNumber", "udid"}
	case familyRegulatoryNotification:
		return []string{"id", "notificationId", "externalId"}
	case familyRecoveryObjective:
		return []string{"id", "objectiveId", "biaId", "externalId", "name"}
	case familyAuthorizationPackage:
		return []string{"id", "packageId", "atoId", "sspId", "externalId", "name"}
	case familyPOAMItem:
		return []string{"id", "poamItemId", "weaknessId", "findingId", "externalId", "title"}
	case familyTrainingAttestation:
		return []string{"id", "attestationId", "trainingAttestationId", "externalId"}
	default:
		return []string{"id", "externalId", "name"}
	}
}

func normalizeID(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "/", "_")
	return strings.ReplaceAll(value, " ", "_")
}

func occurredAtFor(family grcFamily, values map[string]any) time.Time {
	for _, key := range timestampKeySets[family] {
		if value := fieldString(values, key); value != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
				return parsed.UTC()
			}
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Now().UTC()
}

var timestampKeySets = map[grcFamily][]string{
	familyControl: {"modificationDate", "creationDate"}, familyControlTest: {"lastTestRunDate", "latestFlipDate"},
	familyPolicy: {"approvedAtDate"}, familyDocument: {"uploadStatusDate"}, familyContract: {"executedDate", "creationDate"},
	familyRegulatoryNotification: {"sentAt", "submittedAt", "notificationDate", "createdAt", "updatedAt"},
	familyRecoveryObjective:      {"reviewedAt", "updatedAt", "createdAt"}, familyAuthorizationPackage: {"authorizedAt", "authorizationDate", "updatedAt", "createdAt"},
	familyPOAMItem: {"closedAt", "openedAt", "identifiedAt", "updatedAt", "createdAt"}, familyTrainingAttestation: {"completedAt", "completionDate", "updatedAt", "createdAt"},
	familyDiscoveredVendor: {"discoveredDate", "ignored.ignoredAtDate", "rejected.rejectedAtDate"}, familyEventLog: {"date"},
	familyGroup: {"creationDate"}, familyVendor: {"lastSecurityReviewCompletionDate"},
	familyVulnerability: {"lastDetectedDate", "sourceDetectedDate", "firstDetectedDate"}, familyVulnerabilityRemediation: {"remediationDate", "detectedDate"},
	familyVulnerableAsset: {"lastDetectedDate", "lastSeenDate", "updatedAt"}, familyMonitoredComputer: {"lastCheckDate"},
	familyRiskScenario: {"identificationDate"},
	familyPerson:       {"employment.startDate", "employment.endDate"},
}

func fieldString(values map[string]any, path string) string {
	value, ok := fieldValue(values, path)
	if !ok {
		return ""
	}
	return valueString(value)
}

func fieldValue(values map[string]any, path string) (any, bool) {
	var current any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func valueString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := valueString(item); value != "" {
				values = append(values, value)
			}
		}
		return strings.Join(values, ",")
	case map[string]any:
		for _, key := range []string{"displayName", "name", "id", "email"} {
			if value := valueString(typed[key]); value != "" {
				return value
			}
		}
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func arrayValue(values map[string]any, key string) []any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	return items
}
