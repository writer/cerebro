package grcvendor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	questionnairedomain "github.com/writer/cerebro/internal/questionnaire"
)

type QuestionnaireVendorRollup struct {
	QuestionnaireCount int
	ReadyAnswers       int
	BlockedAnswers     int
	ReviewAnswers      int
	MissingEvidence    int
	StaleEvidence      int
	DueQuestionnaires  int
	OpenAssignments    int
}

func QuestionnaireVendorRollups(ctx context.Context, store ports.QuestionnaireRunStore, tenantID string, vendorURNs []string, now time.Time) (map[string]QuestionnaireVendorRollup, error) {
	result := map[string]QuestionnaireVendorRollup{}
	vendorSet := map[string]struct{}{}
	for _, urn := range vendorURNs {
		urn = strings.TrimSpace(urn)
		if urn == "" {
			continue
		}
		vendorSet[urn] = struct{}{}
		result[urn] = QuestionnaireVendorRollup{}
	}
	if len(vendorSet) == 0 || store == nil {
		return result, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	seen := map[string]struct{}{}
	vendorList := make([]string, 0, len(vendorSet))
	for vendorURN := range vendorSet {
		vendorList = append(vendorList, vendorURN)
	}
	sort.Strings(vendorList)
	for _, requestedVendorURN := range vendorList {
		records, err := store.ListQuestionnaireRuns(ctx, ports.QuestionnaireRunFilter{
			TenantID:  strings.TrimSpace(tenantID),
			VendorURN: requestedVendorURN,
			Limit:     500,
		})
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if record == nil {
				continue
			}
			vendorURN := strings.TrimSpace(record.VendorURN)
			if vendorURN != requestedVendorURN {
				continue
			}
			key := vendorURN + "\x00" + firstNonEmpty(record.Attributes[questionnairedomain.QuestionnaireAttributeQuestionnaireURN], record.RunID)
			rollup := result[vendorURN]
			if _, ok := seen[key]; !ok {
				rollup.QuestionnaireCount++
				seen[key] = struct{}{}
			}
			if questionnaireTerminal(record.Status) {
				result[vendorURN] = rollup
				continue
			}
			if record.DueAt != nil && !record.DueAt.After(now) {
				rollup.DueQuestionnaires++
			}
			rollup.ReadyAnswers += record.ReadyAnswerCount
			rollup.BlockedAnswers += record.BlockedAnswerCount
			rollup.ReviewAnswers += record.ReviewAnswerCount
			rollup.MissingEvidence += record.MissingEvidence
			rollup.StaleEvidence += record.StaleEvidence
			for _, assignment := range record.Assignments {
				if strings.TrimSpace(assignment.Status) == "" || assignment.Status == "open" {
					rollup.OpenAssignments++
				}
			}
			result[vendorURN] = rollup
		}
	}
	return result, nil
}

func ApplyQuestionnaireVendorRollup(vendor Vendor, rollup QuestionnaireVendorRollup) Vendor {
	if rollup.QuestionnaireCount == 0 && rollup.ReadyAnswers == 0 && rollup.BlockedAnswers == 0 && rollup.ReviewAnswers == 0 && rollup.MissingEvidence == 0 && rollup.StaleEvidence == 0 && rollup.DueQuestionnaires == 0 && rollup.OpenAssignments == 0 {
		return vendor
	}
	if rollup.QuestionnaireCount > vendor.QuestionnaireCount {
		vendor.QuestionnaireCount = rollup.QuestionnaireCount
	}
	if vendor.Attributes == nil {
		vendor.Attributes = map[string]string{}
	}
	vendor.Attributes["questionnaire_run_count"] = fmt.Sprint(rollup.QuestionnaireCount)
	vendor.Attributes["questionnaire_ready_answers"] = fmt.Sprint(rollup.ReadyAnswers)
	vendor.Attributes["questionnaire_blocked_answers"] = fmt.Sprint(rollup.BlockedAnswers)
	vendor.Attributes["questionnaire_review_answers"] = fmt.Sprint(rollup.ReviewAnswers)
	vendor.Attributes["questionnaire_missing_evidence"] = fmt.Sprint(rollup.MissingEvidence)
	vendor.Attributes["questionnaire_stale_evidence"] = fmt.Sprint(rollup.StaleEvidence)
	vendor.Attributes["questionnaire_due"] = fmt.Sprint(rollup.DueQuestionnaires)
	vendor.Attributes["questionnaire_open_assignments"] = fmt.Sprint(rollup.OpenAssignments)
	return RefreshVendorQueuePosture(vendor)
}

func questionnaireTerminal(status string) bool {
	switch strings.TrimSpace(status) {
	case ports.QuestionnaireStatusApproved, ports.QuestionnaireStatusRejected:
		return true
	default:
		return false
	}
}
