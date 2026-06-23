package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func (s *Source) listThreats(ctx context.Context, settings settings, cursor string, limit int) ([]threatRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	sourcecdk.AddQueryParam(query, "createdAt__gte", settings.since)
	sourcecdk.AddQueryParam(query, "createdAt__lte", settings.until)
	sourcecdk.AddQueryParam(query, "siteIds", settings.siteID)
	return listJSONRecords[threatRecord, *threatRecord](ctx, s, settings, "/web/api/v2.1/threats", query)
}

func (s *Source) listAgents(ctx context.Context, settings settings, cursor string, limit int) ([]agentRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	sourcecdk.AddQueryParam(query, "siteIds", settings.siteID)
	sourcecdk.AddQueryParam(query, "groupIds", settings.groupID)
	return listJSONRecords[agentRecord, *agentRecord](ctx, s, settings, "/web/api/v2.1/agents", query)
}

func (s *Source) listSites(ctx context.Context, settings settings, cursor string, limit int) ([]siteRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	return listJSONRecords[siteRecord, *siteRecord](ctx, s, settings, "/web/api/v2.1/sites", query)
}

func (s *Source) listGroups(ctx context.Context, settings settings, cursor string, limit int) ([]groupRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	sourcecdk.AddQueryParam(query, "siteIds", settings.siteID)
	return listJSONRecords[groupRecord, *groupRecord](ctx, s, settings, "/web/api/v2.1/groups", query)
}

func (s *Source) listExclusions(ctx context.Context, settings settings, cursor string, limit int) ([]exclusionRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	sourcecdk.AddQueryParam(query, "siteIds", settings.siteID)
	return listJSONRecords[exclusionRecord, *exclusionRecord](ctx, s, settings, "/web/api/v2.1/exclusions", query)
}

func (s *Source) listActivities(ctx context.Context, settings settings, cursor string, limit int) ([]activityRecord, string, error) {
	query := buildPagedQuery(cursor, limit)
	sourcecdk.AddQueryParam(query, "createdAt__gte", settings.since)
	sourcecdk.AddQueryParam(query, "createdAt__lte", settings.until)
	sourcecdk.AddQueryParam(query, "activityTypes", settings.activity)
	sourcecdk.AddQueryParam(query, "siteIds", settings.siteID)
	sourcecdk.AddQueryParam(query, "groupIds", settings.groupID)
	return listJSONRecords[activityRecord, *activityRecord](ctx, s, settings, "/web/api/v2.1/activities", query)
}

func (s *Source) listApplications(ctx context.Context, settings settings, cursor string, limit int) ([]applicationRecord, string, error) {
	if strings.TrimSpace(settings.agentID) == "" {
		agents, next, err := s.listAgents(ctx, settings, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		records := make([]applicationRecord, 0)
		for _, agent := range agents {
			agentID := strings.TrimSpace(agent.ID)
			if agentID == "" {
				continue
			}
			applications, _, err := s.listApplicationsForAgent(ctx, settings, agentID)
			if err != nil {
				return nil, "", err
			}
			records = append(records, applications...)
		}
		return records, next, nil
	}
	if cursor != "" {
		return nil, "", nil
	}
	return s.listApplicationsForAgent(ctx, settings, settings.agentID)
}

func (s *Source) listApplicationsForAgent(ctx context.Context, settings settings, agentID string) ([]applicationRecord, string, error) {
	query := url.Values{}
	sourcecdk.AddQueryParam(query, "ids", agentID)
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := s.getJSON(ctx, settings, "/web/api/v2.1/agents/applications", query, &resp); err != nil {
		return nil, "", err
	}
	records := make([]applicationRecord, 0, len(resp.Data))
	for _, item := range resp.Data {
		var record applicationRecord
		if err := json.Unmarshal(item, &record); err != nil {
			return nil, "", fmt.Errorf("decode sentinelone application record: %w", err)
		}
		record.AgentID = agentID
		record.setRaw(cloneRaw(item))
		records = append(records, record)
	}
	return records, "", nil
}
