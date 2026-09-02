package sourceworker

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// Host performs credential redemption and an origin-bounded provider request.
type Host struct {
	worker              Worker
	credentialReference string
	credential          []byte
	credentialExpiresAt time.Time
	client              *http.Client
	now                 func() time.Time
}

func (*Host) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "sourceworker.Host") }

// NewHost constructs a production host with public-DNS-only dialing, no
// redirects, a 30-second deadline, and no environment proxy routing.
func NewHost(worker Worker, reference string, credential []byte, expiresAt time.Time) *Host {
	return &Host{worker: worker, credentialReference: strings.TrimSpace(reference), credential: append([]byte(nil), credential...), credentialExpiresAt: expiresAt.UTC(), client: safeHTTPClient(net.DefaultResolver), now: time.Now}
}

// Execute plans, authorizes, performs, and decodes one provider request.
func (h *Host) Execute(ctx context.Context, input ExecutionInput) (*ExecutionOutput, error) {
	if h == nil || h.worker == nil || h.client == nil {
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
		input.Scope.SourceID, input.Scope.FamilyID = plan.GetSourceId(), plan.GetFamilyId()
		input.Scope.PlanDigestSHA256 = plan.GetPlanDigestSha256()
	}
	if err := validatePublicConfig(input.Scope.PublicConfig); err != nil {
		return nil, err
	}
	observedAt := h.now().UTC()
	executionContext, err := h.worker.Context(ctx, ContextRequest{
		TenantID: input.Scope.TenantID, RuntimeID: input.Scope.RuntimeID,
		PriorCursor: input.Scope.PriorCursor, PageNumber: input.PageNumber,
		RuntimeGeneration: input.Scope.RuntimeGeneration, LeaseGeneration: input.Scope.LeaseGeneration,
		ObservedAtUnixMillis:             observedAt.UnixMilli(),
		PublicConfig:                     input.Scope.PublicConfig,
		PriorTerminalWatermarkUnixMillis: input.Scope.PriorTerminalWatermarkUnixMillis,
		PriorCheckpoint:                  input.Scope.PriorCheckpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Rust execution context failed: %w", ErrWorkerContract, err)
	}
	input.Scope.LogicalPageID = executionContext.GetLogicalPageId()
	if err := validateScope(input.Plan, input.CredentialReference, input.Scope, observedAt); err != nil {
		return nil, err
	}
	metadata := runtimeMetadata(input.Scope)
	execution, err := h.worker.PlanV2(ctx, &cerebrov1.SourceWorkerPlanEnvelopeV2{
		Request: &cerebrov1.SourceWorkerPlanRequestV1{
			Plan: proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1), Context: executionContext,
		},
		Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: credential-free request planning failed: %w", ErrWorkerContract, err)
	}
	providerURL, err := validateHTTPExecution(input.Plan, execution)
	if err != nil {
		return nil, err
	}
	requestPlan := execution.GetRequest()
	requestIntentDigest := requestPlan.GetRequestIntentDigest()
	executionIntentDigest := execution.GetExecutionIntentDigestSha256()
	if h.credentialExpiresAt.Before(h.now().UTC()) || subtle.ConstantTimeCompare([]byte(h.credentialReference), []byte(strings.TrimSpace(input.CredentialReference))) != 1 {
		return nil, ErrCredentialUnavailable
	}
	bearer := h.credential
	h.credential = nil
	if len(bearer) == 0 {
		return nil, ErrCredentialUnavailable
	}
	responseBody, responseHeaders, statusCode, err := h.get(ctx, providerURL, requestPlan.GetMethod(), requestPlan.GetAccept(), execution.GetDeclaredHeaders(), execution.GetBody(), requestPlan.GetMaxResponseBytes(), execution.GetCredentialOperation(), bearer)
	if err != nil {
		return nil, err
	}
	statusCodeWire, err := safeUint32(statusCode)
	if err != nil {
		return nil, err
	}
	decoded, err := h.worker.DecodeV2(ctx, &cerebrov1.SourceWorkerDecodeEnvelopeV2{
		Request: &cerebrov1.SourceWorkerDecodeRequestV1{
			Plan: proto.Clone(input.Plan).(*cerebrov1.SourceExecutionPlanV1), StatusCode: statusCodeWire, ResponseBody: responseBody,
			LogicalPageId: executionContext.GetLogicalPageId(), RequestIntentDigest: requestIntentDigest, Context: executionContext,
		},
		Metadata: metadata, ResponseHeaders: responseHeaders, ExecutionIntentDigestSha256: executionIntentDigest,
	})
	if err != nil {
		return nil, fmt.Errorf("credential-free response decoding failed: %w", err)
	}
	if decoded.GetReceipt() == nil || decoded.GetResult() == nil {
		return nil, fmt.Errorf("%w: Rust decode evidence is incomplete", ErrWorkerContract)
	}
	output := &ExecutionOutput{Plan: input.Plan, Context: executionContext, Receipt: decoded.GetReceipt(), Result: decoded.GetResult()}
	program, err := h.worker.SealPage(ctx, PageProgramRequest{
		Plan: output.Plan, Context: output.Context, Receipt: output.Receipt, Result: output.Result,
		CurrentLeaseGeneration: input.Scope.LeaseGeneration, Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Rust page program failed: %w", ErrWorkerContract, err)
	}
	output.Program = program
	return output, nil
}

func (h *Host) get(ctx context.Context, endpoint *url.URL, method, accept string, declaredHeaders map[string]string, requestBody []byte, limit uint64, credentialOperation string, credential []byte) ([]byte, map[string]string, int, error) {
	defer clear(credential)
	if len(credential) == 0 || bytes.ContainsAny(credential, "\r\n") {
		return nil, nil, 0, ErrCredentialUnavailable
	}
	if err := validateDeclaredHeaders(declaredHeaders); err != nil {
		return nil, nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%w: provider request is invalid", ErrInvalidExecution)
	}
	req.Header.Set("Accept", accept)
	for name, value := range declaredHeaders {
		req.Header.Set(name, value)
	}
	authHeader := ""
	var authValue []byte
	if credentialOperation == "aws.sigv4" {
		if err := signAWSBedrockRequest(ctx, req, credential, h.now().UTC()); err != nil {
			return nil, nil, 0, err
		}
	} else {
		authHeader, authValue, err = credentialHeader(credentialOperation, credential)
		if err != nil {
			return nil, nil, 0, err
		}
		req.Header.Set(authHeader, string(authValue))
	}
	response, err := h.client.Do(req)
	if authHeader != "" {
		req.Header.Del(authHeader)
	}
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	clear(authValue)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, 0, ErrProviderTimeout
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return nil, nil, 0, ErrProviderTimeout
		}
		return nil, nil, 0, fmt.Errorf("%w: provider request failed", ErrProviderEgress)
	}
	defer func() { _ = response.Body.Close() }()
	responseHeaders, err := safeResponseHeaders(response.Header)
	if err != nil {
		return nil, nil, response.StatusCode, err
	}
	readLimit, err := strconv.ParseInt(strconv.FormatUint(limit, 10), 10, 64)
	if err != nil || readLimit < 0 || limit > maxResponseBytes {
		return nil, nil, response.StatusCode, fmt.Errorf("%w: provider response limit is invalid", ErrInvalidExecution)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, readLimit+1))
	if err != nil {
		return nil, nil, response.StatusCode, fmt.Errorf("%w: provider response read failed", ErrInvalidExecution)
	}
	if uint64(len(responseBody)) > limit {
		return nil, nil, response.StatusCode, fmt.Errorf("%w: limit %d", ErrProviderResponseTooLarge, limit)
	}
	return responseBody, responseHeaders, response.StatusCode, nil
}

func credentialHeader(operation string, credential []byte) (string, []byte, error) {
	switch operation {
	case "source.bearer":
		return "Authorization", append([]byte("Bearer "), credential...), nil
	case "source.x_api_key":
		return "X-Api-Key", append([]byte(nil), credential...), nil
	case "abuseipdb.key":
		return "Key", append([]byte(nil), credential...), nil
	case "anthropic.admin_x_api_key", "anthropic.compliance_x_api_key":
		return "X-Api-Key", append([]byte(nil), credential...), nil
	case "anthropic.org_admin_bearer":
		return "Authorization", append([]byte("Bearer "), credential...), nil
	case "openai.admin_api_key_bearer":
		return "Authorization", append([]byte("Bearer "), credential...), nil
	case "google.api_key_header":
		return "X-Goog-Api-Key", append([]byte(nil), credential...), nil
	case "elevenlabs.xi_api_key":
		return "Xi-Api-Key", append([]byte(nil), credential...), nil
	case "langsmith.x_api_key":
		return "X-Api-Key", append([]byte(nil), credential...), nil
	case "langfuse.basic":
		return "Authorization", append([]byte("Basic "), credential...), nil
	case "microsoft_foundry.api_key":
		return "Api-Key", append([]byte(nil), credential...), nil
	case "pinecone.api_key":
		return "Api-Key", append([]byte(nil), credential...), nil
	case "qdrant.api_key":
		return "Authorization", append([]byte("apikey "), credential...), nil
	case "jumpcloud.x_api_key":
		return "X-Api-Key", append([]byte(nil), credential...), nil
	case "sentinelone.api_token":
		return "Authorization", append([]byte("ApiToken "), credential...), nil
	case "discord.bot_token":
		return "Authorization", append([]byte("Bot "), credential...), nil
	case "twilio.basic":
		return "Authorization", append([]byte("Basic "), credential...), nil
	case "pagerduty.token":
		return "Authorization", append([]byte("Token token="), credential...), nil
	default:
		return "", nil, fmt.Errorf("%w: credential operation is not registered", ErrWorkerContract)
	}
}

func signAWSBedrockRequest(ctx context.Context, req *http.Request, credential []byte, now time.Time) error {
	accessKey, secretKey, err := decodeAWSHostCredential(credential)
	if err != nil {
		return err
	}
	defer clear(accessKey)
	defer clear(secretKey)
	host := strings.ToLower(req.URL.Hostname())
	parts := strings.Split(host, ".")
	if len(parts) != 4 || parts[0] != "bedrock" || parts[2] != "amazonaws" || parts[3] != "com" || !safeAWSRegion(parts[1]) {
		return fmt.Errorf("%w: AWS Bedrock origin is invalid", ErrProviderEgress)
	}
	return awsv4.NewSigner().SignHTTP(ctx, awssdk.Credentials{
		AccessKeyID: string(accessKey), SecretAccessKey: string(secretKey), Source: "cerebro-source-host",
	}, req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "bedrock", parts[1], now)
}

func decodeAWSHostCredential(value []byte) ([]byte, []byte, error) {
	parts := bytes.SplitN(value, []byte("."), 2)
	if len(parts) != 2 {
		return nil, nil, ErrCredentialUnavailable
	}
	accessKey, err := base64.RawStdEncoding.DecodeString(string(parts[0]))
	if err != nil || len(accessKey) == 0 {
		clear(accessKey)
		return nil, nil, ErrCredentialUnavailable
	}
	secretKey, err := base64.RawStdEncoding.DecodeString(string(parts[1]))
	if err != nil || len(secretKey) == 0 {
		clear(accessKey)
		clear(secretKey)
		return nil, nil, ErrCredentialUnavailable
	}
	return accessKey, secretKey, nil
}

func safeAWSRegion(value string) bool {
	return value != "" && len(value) <= 63 && !strings.HasPrefix(value, "-") && !strings.HasSuffix(value, "-") && strings.IndexFunc(value, func(character rune) bool {
		return (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-'
	}) == -1
}

func runtimeMetadata(scope CredentialScope) *cerebrov1.SourceWorkerRuntimeMetadataV2 {
	return &cerebrov1.SourceWorkerRuntimeMetadataV2{
		PublicConfig:                     scope.PublicConfig,
		PriorTerminalWatermarkUnixMillis: scope.PriorTerminalWatermarkUnixMillis,
		PriorCheckpoint:                  scope.PriorCheckpoint,
	}
}
