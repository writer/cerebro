package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/policy"
)

type listPoliciesResponse struct {
	Policies []*policy.Policy `json:"policies"`
	Count    int              `json:"count"`
}

type PolicyDryRunResponse struct {
	DryRun      bool                       `json:"dry_run"`
	PolicyID    string                     `json:"policy_id"`
	AssetSource string                     `json:"asset_source"`
	Diff        policy.PolicyDiff          `json:"diff"`
	Impact      *policy.PolicyDryRunImpact `json:"impact,omitempty"`
}

func (c *Client) ListPolicies(ctx context.Context, limit, offset int) ([]*policy.Policy, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		query.Set("offset", strconv.Itoa(offset))
	}

	var resp listPoliciesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/policies/", query, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Policies == nil {
		return []*policy.Policy{}, nil
	}
	return resp.Policies, nil
}

func (c *Client) GetPolicy(ctx context.Context, policyID string) (*policy.Policy, error) {
	path := "/api/v1/policies/" + url.PathEscape(strings.TrimSpace(policyID))

	var resp policy.Policy
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) DryRunPolicyChange(ctx context.Context, policyID string, candidate policy.Policy, assets []map[string]interface{}, assetLimit int) (*PolicyDryRunResponse, error) {
	req := map[string]interface{}{
		"policy": candidate,
	}
	if len(assets) > 0 {
		req["assets"] = assets
	}
	if assetLimit > 0 {
		req["asset_limit"] = assetLimit
	}

	path := "/api/v1/policies/" + url.PathEscape(strings.TrimSpace(policyID)) + "/dry-run"
	var resp PolicyDryRunResponse
	if err := c.doJSON(ctx, http.MethodPost, path, nil, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
