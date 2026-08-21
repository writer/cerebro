package sourceworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// Host performs credential redemption and an origin-bounded provider request.
type Host struct {
	worker   Worker
	redeemer CredentialRedeemer
	client   *http.Client
	now      func() time.Time
}

// NewHost constructs a production host with public-DNS-only dialing, no
// redirects, a 30-second deadline, and no environment proxy routing.
func NewHost(worker Worker, redeemer CredentialRedeemer) *Host {
	return &Host{worker: worker, redeemer: redeemer, client: safeHTTPClient(net.DefaultResolver), now: time.Now}
}

// Execute plans, authorizes, performs, and decodes one provider request.
func (h *Host) Execute(ctx context.Context, input ExecutionInput) (*ExecutionOutput, error) {
	if h == nil || h.worker == nil || h.redeemer == nil || h.client == nil || input.Plan == nil {
		return nil, fmt.Errorf("%w: host dependencies and plan are required", ErrInvalidExecution)
	}
	ctx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	if err := validateScope(input.Plan, input.CredentialReference, input.Scope, h.now().UTC()); err != nil {
		return nil, err
	}
	requestPlan, err := h.worker.Plan(ctx, proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1))
	if err != nil {
		return nil, fmt.Errorf("%w: credential-free request planning failed", ErrInvalidExecution)
	}
	providerURL, err := validateWorkerRequest(input.Plan, requestPlan)
	if err != nil {
		return nil, err
	}
	lease, err := h.redeemer.Redeem(ctx, input.CredentialReference, input.Scope)
	if err != nil || lease == nil {
		return nil, ErrCredentialUnavailable
	}
	defer func() { _ = lease.Close() }()
	if lease.ExpiresAt().UTC().Before(h.now().UTC()) {
		return nil, ErrCredentialUnavailable
	}
	responseBody, statusCode, err := h.get(ctx, providerURL, requestPlan.GetAccept(), requestPlan.GetMaxResponseBytes(), lease.BearerToken())
	if err != nil {
		return nil, err
	}
	decodeResult, err := h.worker.Decode(ctx, &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1), StatusCode: uint32(statusCode), ResponseBody: responseBody,
		LogicalPageId: input.Scope.LogicalPageID, RequestIntentDigest: input.Scope.RequestIntentDigest,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: credential-free response decoding failed", ErrInvalidExecution)
	}
	if err := validateWorkerResult(input.Plan, input.Scope, decodeResult); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(responseBody)
	return &ExecutionOutput{Result: decodeResult, Receipt: SafeReceipt{
		PlanDigestSHA256: input.Plan.GetPlanDigestSha256(), LogicalPageID: input.Scope.LogicalPageID,
		RequestIntentDigest: input.Scope.RequestIntentDigest, RuntimeGeneration: input.Scope.RuntimeGeneration,
		LeaseGeneration: input.Scope.LeaseGeneration, CredentialOperation: strings.TrimSpace(lease.OperationID()),
		StatusCode: statusCode, ResponseBytes: len(responseBody), ResponseSHA256: hex.EncodeToString(sum[:]),
	}}, nil
}

func (h *Host) get(ctx context.Context, endpoint *url.URL, accept string, limit uint64, bearer []byte) ([]byte, int, error) {
	defer clear(bearer)
	if len(bearer) == 0 || bytes.ContainsAny(bearer, "\r\n") {
		return nil, 0, ErrCredentialUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: provider request is invalid", ErrInvalidExecution)
	}
	req.Header.Set("Accept", accept)
	authorization := append([]byte("Bearer "), bearer...)
	req.Header.Set("Authorization", string(authorization))
	response, err := h.client.Do(req)
	req.Header.Del("Authorization")
	clear(authorization)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: provider request failed", ErrInvalidExecution)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, fmt.Errorf("%w: provider status %d is not allowed", ErrInvalidExecution, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("%w: provider response read failed", ErrInvalidExecution)
	}
	if uint64(len(body)) > limit {
		return nil, response.StatusCode, fmt.Errorf("%w: provider response exceeds %d bytes", ErrInvalidExecution, limit)
	}
	return body, response.StatusCode, nil
}
