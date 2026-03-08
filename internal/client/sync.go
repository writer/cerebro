package client

import (
	"context"
	"net/http"
	"strings"

	nativesync "github.com/evalops/cerebro/internal/sync"
)

type RelationshipBackfillStats struct {
	Scanned int64 `json:"scanned"`
	Updated int64 `json:"updated"`
	Deleted int64 `json:"deleted"`
	Skipped int64 `json:"skipped"`
}

func (c *Client) BackfillRelationshipIDs(ctx context.Context, batchSize int) (*RelationshipBackfillStats, error) {
	var reqBody map[string]interface{}
	if batchSize > 0 {
		reqBody = map[string]interface{}{"batch_size": batchSize}
	}

	var resp RelationshipBackfillStats
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/backfill-relationships", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type AzureSyncRequest struct {
	Subscription string
	Concurrency  int
	Tables       []string
	Validate     bool
}

type SyncRunResponse struct {
	Provider                   string                  `json:"provider"`
	Validate                   bool                    `json:"validate"`
	Results                    []nativesync.SyncResult `json:"results"`
	RelationshipsExtracted     int64                   `json:"relationships_extracted,omitempty"`
	RelationshipsSkippedReason string                  `json:"relationships_skipped_reason,omitempty"`
}

func (c *Client) RunAzureSync(ctx context.Context, req AzureSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if sub := strings.TrimSpace(req.Subscription); sub != "" {
		reqBody = map[string]interface{}{"subscription": sub}
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/azure", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type AWSSyncRequest struct {
	Region      string
	MultiRegion bool
	Concurrency int
	Tables      []string
	Validate    bool
}

func (c *Client) RunAWSSync(ctx context.Context, req AWSSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if region := strings.TrimSpace(req.Region); region != "" {
		reqBody = map[string]interface{}{"region": region}
	}
	if req.MultiRegion {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["multi_region"] = true
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/aws", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type K8sSyncRequest struct {
	Kubeconfig  string
	Context     string
	Namespace   string
	Concurrency int
	Tables      []string
	Validate    bool
}

func (c *Client) RunK8sSync(ctx context.Context, req K8sSyncRequest) (*SyncRunResponse, error) {
	var reqBody map[string]interface{}
	if kubeconfig := strings.TrimSpace(req.Kubeconfig); kubeconfig != "" {
		reqBody = map[string]interface{}{"kubeconfig": kubeconfig}
	}
	if kubeCtx := strings.TrimSpace(req.Context); kubeCtx != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["context"] = kubeCtx
	}
	if namespace := strings.TrimSpace(req.Namespace); namespace != "" {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["namespace"] = namespace
	}
	if req.Concurrency > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["concurrency"] = req.Concurrency
	}
	if len(req.Tables) > 0 {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["tables"] = req.Tables
	}
	if req.Validate {
		if reqBody == nil {
			reqBody = make(map[string]interface{}, 1)
		}
		reqBody["validate"] = true
	}

	var resp SyncRunResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sync/k8s", nil, reqBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
