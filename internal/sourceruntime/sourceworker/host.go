package sourceworker

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	if h == nil || h.worker == nil || h.redeemer == nil || h.client == nil {
		return nil, fmt.Errorf("%w: host dependencies are required", ErrInvalidExecution)
	}
	ctx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()
	if input.Plan == nil {
		plan, err := h.worker.Compile(ctx, SelectionRequest{
			SourceID: strings.TrimSpace(input.SourceID), FamilyID: strings.TrimSpace(input.FamilyID),
		})
		if err != nil {
			return nil, err
		}
		input.Plan = plan
	}
	observedAt := h.now().UTC()
	executionContext, err := h.worker.Context(ctx, ContextRequest{
		TenantID: input.Scope.TenantID, RuntimeID: input.Scope.RuntimeID,
		PriorCursor: input.Scope.PriorCursor, PageNumber: input.PageNumber,
		RuntimeGeneration: input.Scope.RuntimeGeneration, LeaseGeneration: input.Scope.LeaseGeneration,
		ObservedAtUnixMillis: observedAt.UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Rust execution context failed: %w", ErrWorkerContract, err)
	}
	input.Scope.LogicalPageID = executionContext.GetLogicalPageId()
	if err := validateScope(input.Plan, input.CredentialReference, input.Scope, observedAt); err != nil {
		return nil, err
	}
	requestPlan, err := h.worker.Plan(ctx, &cerebrov1.SourceWorkerPlanRequestV1{
		Plan:    proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1),
		Context: executionContext,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: credential-free request planning failed: %w", ErrWorkerContract, err)
	}
	providerURL, err := validateWorkerRequest(input.Plan, requestPlan)
	if err != nil {
		return nil, err
	}
	intentDigest := requestPlan.GetRequestIntentDigest()
	operationScope := input.Scope
	operationScope.ObservedAtUnixMillis = observedAt.UnixMilli()
	if operationScope.RequestIntentDigest != "" && subtle.ConstantTimeCompare([]byte(operationScope.RequestIntentDigest), []byte(intentDigest)) != 1 {
		return nil, fmt.Errorf("%w: caller request intent fence does not match the planned operation", ErrWorkerContract)
	}
	operationScope.RequestIntentDigest = intentDigest
	lease, err := h.redeemer.Redeem(ctx, input.CredentialReference, operationScope)
	if err != nil || lease == nil {
		return nil, ErrCredentialUnavailable
	}
	defer func() { _ = lease.Close() }()
	if lease.ExpiresAt().UTC().Before(h.now().UTC()) {
		return nil, ErrCredentialUnavailable
	}
	credentialOperation := strings.TrimSpace(lease.OperationID())
	if !safeIdentifier(credentialOperation) {
		return nil, fmt.Errorf("%w: credential operation identifier is not provider-safe", ErrCredentialUnavailable)
	}
	responseBody, statusCode, err := h.get(ctx, providerURL, requestPlan.GetAccept(), requestPlan.GetMaxResponseBytes(), lease.BearerToken())
	if err != nil {
		return nil, err
	}
	statusCodeWire, err := safeUint32(statusCode)
	if err != nil {
		return nil, err
	}
	receipt := &cerebrov1.SourceWorkerSafeReceiptV1{
		PlanDigestSha256: input.Plan.GetPlanDigestSha256(), LogicalPageId: executionContext.GetLogicalPageId(),
		RequestIntentDigest: intentDigest, RuntimeGeneration: executionContext.GetRuntimeGeneration(),
		LeaseGeneration: executionContext.GetLeaseGeneration(), CredentialOperation: credentialOperation,
		StatusCode: statusCodeWire, ResponseBytes: uint64(len(responseBody)), ResponseSha256: responseSHA256(responseBody),
		TenantId: executionContext.GetTenantId(), RuntimeId: executionContext.GetRuntimeId(), ObservedAtUnixMillis: executionContext.GetObservedAtUnixMillis(),
	}
	decodeResult, err := h.worker.Decode(ctx, &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1), StatusCode: statusCodeWire, ResponseBody: responseBody,
		LogicalPageId: executionContext.GetLogicalPageId(), RequestIntentDigest: intentDigest, Receipt: receipt, Context: executionContext,
	})
	if err != nil {
		return nil, fmt.Errorf("credential-free response decoding failed: %w", err)
	}
	output := &ExecutionOutput{Plan: input.Plan, Context: executionContext, Receipt: receipt, Result: decodeResult}
	decision, err := h.Advance(ctx, output, PhaseDecoded, "", input.Scope.LeaseGeneration)
	if err != nil {
		return nil, err
	}
	output.Decision = decision
	return output, nil
}

// Advance is the temporary side-effect bridge into the Rust-owned lifecycle.
// Delete this bridge when append, projection, and checkpoint ports are callable
// directly by the Rust runtime; Go must not decide or reorder lifecycle phases.
func (h *Host) Advance(ctx context.Context, output *ExecutionOutput, completed Phase, priorDigest string, currentLeaseGeneration uint64) (*LifecycleDecision, error) {
	if h == nil || h.worker == nil || output == nil || output.Plan == nil || output.Context == nil || output.Receipt == nil || output.Result == nil {
		return nil, fmt.Errorf("%w: lifecycle bridge inputs are incomplete", ErrInvalidExecution)
	}
	decision, err := h.worker.Transition(ctx, LifecycleRequest{
		Plan: output.Plan, Context: output.Context, Receipt: output.Receipt, Result: output.Result,
		CompletedPhase: completed, PriorTransitionDigest: priorDigest,
		CurrentLeaseGeneration: currentLeaseGeneration,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Rust lifecycle transition failed: %w", ErrWorkerContract, err)
	}
	return decision, nil
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
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, ErrProviderTimeout
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return nil, 0, ErrProviderTimeout
		}
		return nil, 0, fmt.Errorf("%w: provider request failed", ErrProviderEgress)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return nil, response.StatusCode, ErrProviderAuthentication
		case http.StatusForbidden:
			return nil, response.StatusCode, ErrProviderPermission
		case http.StatusTooManyRequests:
			return nil, response.StatusCode, ErrProviderRateLimited
		default:
			return nil, response.StatusCode, fmt.Errorf("%w: provider status %d is not allowed", ErrProviderMalformedResponse, response.StatusCode)
		}
	}
	readLimit, err := strconv.ParseInt(strconv.FormatUint(limit, 10), 10, 64)
	if err != nil || readLimit < 0 || limit > maxResponseBytes {
		return nil, response.StatusCode, fmt.Errorf("%w: provider response limit is invalid", ErrInvalidExecution)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, readLimit+1))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("%w: provider response read failed", ErrInvalidExecution)
	}
	if uint64(len(body)) > limit {
		return nil, response.StatusCode, fmt.Errorf("%w: limit %d", ErrProviderResponseTooLarge, limit)
	}
	return body, response.StatusCode, nil
}
