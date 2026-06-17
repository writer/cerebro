package agentplatform

import (
	"encoding/json"
	"strings"
)

const (
	A2AAgentCardPath       = "/.well-known/agent-card.json"
	A2ALegacyAgentCardPath = "/.well-known/agent.json"
	A2AJSONRPCPath         = "/api/v1/a2a"

	EventSubscriptionContractPath = "/api/v1/event-subscriptions/contract"
	IdempotencyContractPath       = "/api/v1/idempotency-contract"
)

type A2AProtocolContract struct {
	ProtocolVersion    string   `json:"protocol_version"`
	DiscoveryPaths     []string `json:"discovery_paths"`
	JSONRPCPath        string   `json:"jsonrpc_path"`
	SupportedMethods   []string `json:"supported_methods"`
	UnsupportedMethods []string `json:"unsupported_methods"`
	Authentication     []string `json:"authentication"`
	Controls           []string `json:"controls"`
}

type A2AAgentCard struct {
	Name                string                       `json:"name"`
	Description         string                       `json:"description"`
	SupportedInterfaces []A2AAgentInterface          `json:"supportedInterfaces"`
	Provider            A2AProvider                  `json:"provider"`
	Version             string                       `json:"version"`
	DocumentationURL    string                       `json:"documentationUrl,omitempty"`
	Capabilities        A2AAgentCapabilities         `json:"capabilities"`
	SecuritySchemes     map[string]A2ASecurityScheme `json:"securitySchemes,omitempty"`
	Security            []map[string][]string        `json:"security,omitempty"`
	DefaultInputModes   []string                     `json:"defaultInputModes"`
	DefaultOutputModes  []string                     `json:"defaultOutputModes"`
	Skills              []A2AAgentSkill              `json:"skills"`
}

type A2AAgentInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
}

type A2AProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

type A2AAgentCapabilities struct {
	Streaming              bool           `json:"streaming"`
	PushNotifications      bool           `json:"pushNotifications"`
	StateTransitionHistory bool           `json:"stateTransitionHistory"`
	ExtendedAgentCard      bool           `json:"extendedAgentCard"`
	Extensions             []A2AExtension `json:"extensions,omitempty"`
}

type A2AExtension struct {
	URI         string `json:"uri"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type A2ASecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Description  string `json:"description,omitempty"`
}

type A2AAgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes"`
	OutputModes []string `json:"outputModes"`
}

type A2AJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

type A2AJSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  any           `json:"result,omitempty"`
	Error   *A2AJSONError `json:"error,omitempty"`
	ID      any           `json:"id,omitempty"`
}

type A2AJSONError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

type EventSubscriptionContract struct {
	Version          string                  `json:"version"`
	Resource         string                  `json:"resource"`
	Summary          string                  `json:"summary"`
	EventTypes       []EventSubscriptionType `json:"event_types"`
	Delivery         WebhookDeliveryContract `json:"delivery"`
	Signing          WebhookSigningContract  `json:"signing"`
	Retry            WebhookRetryContract    `json:"retry"`
	Idempotency      IdempotencyContract     `json:"idempotency"`
	RequiredControls []string                `json:"required_controls"`
}

type EventSubscriptionType struct {
	Name          string   `json:"name"`
	Family        string   `json:"family"`
	Description   string   `json:"description"`
	PayloadFields []string `json:"payload_fields"`
}

type WebhookDeliveryContract struct {
	Transport            string   `json:"transport"`
	EndpointRequirements []string `json:"endpoint_requirements"`
	Headers              []string `json:"headers"`
	AckStatus            string   `json:"ack_status"`
	Timeout              string   `json:"timeout"`
}

type WebhookSigningContract struct {
	Schemes       []string `json:"schemes"`
	SignatureBase []string `json:"signature_base"`
	KeyRotation   string   `json:"key_rotation"`
}

type WebhookRetryContract struct {
	Schedule     []string `json:"schedule"`
	DeadLetter   string   `json:"dead_letter"`
	DedupeWindow string   `json:"dedupe_window"`
	MaxAttempts  int      `json:"max_attempts"`
}

type IdempotencyContract struct {
	Version        string                     `json:"version"`
	Header         string                     `json:"header"`
	MaxLengthBytes int                        `json:"max_length_bytes"`
	KeyScope       []string                   `json:"key_scope"`
	ConflictStatus int                        `json:"conflict_status"`
	ReplayHeaders  []string                   `json:"replay_headers"`
	Semantics      []string                   `json:"semantics"`
	Routes         []IdempotencyRouteContract `json:"routes"`
}

type IdempotencyRouteContract struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Requirement string `json:"requirement"`
	Scope       string `json:"scope"`
	Replay      string `json:"replay"`
}

func A2AProtocol() A2AProtocolContract {
	return A2AProtocolContract{
		ProtocolVersion:  "1.0",
		DiscoveryPaths:   []string{A2AAgentCardPath, A2ALegacyAgentCardPath},
		JSONRPCPath:      A2AJSONRPCPath,
		SupportedMethods: []string{"SendMessage", "ListTasks"},
		UnsupportedMethods: []string{
			"CancelTask",
			"CreateTaskPushNotificationConfig",
			"DeleteTaskPushNotificationConfig",
			"GetExtendedAgentCard",
			"GetTask",
			"GetTaskPushNotificationConfig",
			"ListTaskPushNotificationConfigs",
			"SendStreamingMessage",
			"SubscribeToTask",
		},
		Authentication: []string{"bearer API key", "OAuth bearer token with cerebro.cosmo.security.read"},
		Controls: []string{
			"public Agent Card contains no tenant, endpoint inventory, credential, or deployment labels",
			"JSON-RPC methods force the authenticated platform tenant before returning contract data",
			"task, streaming, and push-notification methods stay disabled until backed by replayable runtime adapters",
		},
	}
}

func BuildA2AAgentCard(origin string) A2AAgentCard {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		origin = "https://cerebro"
	}
	return A2AAgentCard{
		Name:        "Cerebro Agent Platform",
		Description: "Governed security and compliance agent contracts for graph reasoning, evidence packets, event subscription discovery, and idempotent platform operations.",
		SupportedInterfaces: []A2AAgentInterface{
			{URL: origin + A2AJSONRPCPath, ProtocolBinding: "JSONRPC", ProtocolVersion: "1.0"},
		},
		Provider:         A2AProvider{Organization: "Writer"},
		Version:          ContractVersion,
		DocumentationURL: origin + "/openapi.yaml",
		Capabilities: A2AAgentCapabilities{
			Streaming:              false,
			PushNotifications:      false,
			StateTransitionHistory: false,
			ExtendedAgentCard:      false,
			Extensions: []A2AExtension{
				{
					URI:         "https://github.com/writer/cerebro/a2a/extensions/event-subscriptions/v1",
					Description: "Advertises Cerebro outbound event subscription and webhook trigger contracts.",
					Required:    false,
				},
				{
					URI:         "https://github.com/writer/cerebro/a2a/extensions/idempotency/v1",
					Description: "Advertises the public Idempotency-Key contract for retried platform writes and webhook deliveries.",
					Required:    false,
				},
			},
		},
		SecuritySchemes: map[string]A2ASecurityScheme{
			"platform-http": { //nolint:gosec // Protocol security-scheme metadata; no credential value is embedded.
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "API key or OAuth access token",
				Description:  "Use the same bearer credentials and tenant-scoped authorization model as the Cerebro platform API.",
			},
		},
		Security:           []map[string][]string{{"platform-http": []string{"cerebro.cosmo.security.read"}}},
		DefaultInputModes:  []string{"text/plain", "application/json"},
		DefaultOutputModes: []string{"text/plain", "application/json"},
		Skills: []A2AAgentSkill{
			{
				ID:          "agent-platform-contract",
				Name:        "Agent platform contract discovery",
				Description: "Return the governed Cerebro agent-platform capability, provenance, graph reasoning, and eval contract surfaces.",
				Tags:        []string{"contracts", "agent-platform", "governance"},
				Examples:    []string{"List the public agent-platform contract endpoints."},
				InputModes:  []string{"text/plain", "application/json"},
				OutputModes: []string{"text/plain", "application/json"},
			},
			{
				ID:          "event-subscription-contract",
				Name:        "Outbound event subscription contract discovery",
				Description: "Explain supported outbound webhook trigger families, signing, retry, and idempotency semantics.",
				Tags:        []string{"webhooks", "event-subscriptions", "delivery"},
				Examples:    []string{"Which event types can be subscribed to by webhook receivers?"},
				InputModes:  []string{"text/plain", "application/json"},
				OutputModes: []string{"text/plain", "application/json"},
			},
			{
				ID:          "idempotency-contract",
				Name:        "Idempotency contract discovery",
				Description: "Explain how public API clients should set Idempotency-Key for retry-safe writes and webhook delivery dedupe.",
				Tags:        []string{"idempotency", "public-api", "retries"},
				Examples:    []string{"When is Idempotency-Key required?"},
				InputModes:  []string{"text/plain", "application/json"},
				OutputModes: []string{"text/plain", "application/json"},
			},
		},
	}
}

func A2AJSONRPCResponseFor(request A2AJSONRPCRequest, card A2AAgentCard) A2AJSONRPCResponse {
	response := A2AJSONRPCResponse{JSONRPC: "2.0", ID: request.ID}
	if strings.TrimSpace(request.JSONRPC) != "2.0" {
		response.Error = &A2AJSONError{Code: -32600, Message: "Invalid Request"}
		return response
	}
	switch strings.TrimSpace(request.Method) {
	case "SendMessage":
		response.Result = map[string]any{"message": a2AContractMessage(card)}
	case "ListTasks":
		response.Result = map[string]any{"tasks": []any{}, "totalSize": 0}
	case "GetTask":
		response.Error = &A2AJSONError{Code: -32001, Message: "TaskNotFoundError"}
	case "":
		response.Error = &A2AJSONError{Code: -32600, Message: "Invalid Request"}
	default:
		response.Error = &A2AJSONError{
			Code:    -32004,
			Message: "UnsupportedOperationError",
			Data: map[string]any{
				"supportedMethods": A2AProtocol().SupportedMethods,
				"reason":           "Cerebro only exposes contract discovery over A2A until task execution is backed by a replayable runtime adapter.",
			},
		}
	}
	return response
}

func a2AContractMessage(card A2AAgentCard) map[string]any {
	return map[string]any{
		"role":      "ROLE_AGENT",
		"messageId": "cerebro-contract-discovery",
		"parts": []map[string]any{{
			"text": "Cerebro exposes governed agent-platform, event subscription, and idempotency contracts. Use the links in metadata for the canonical JSON contracts.",
		}},
		"metadata": map[string]any{
			"contractVersion":           ContractVersion,
			"agentPlatformContractPath": "/api/v1/agent-platform/contract",
			"eventSubscriptionContract": EventSubscriptionContractPath,
			"idempotencyContract":       IdempotencyContractPath,
			"skills":                    card.Skills,
		},
	}
}

func EventSubscriptions() EventSubscriptionContract {
	return EventSubscriptionContract{
		Version:  ContractVersion,
		Resource: "/api/v1/event-subscriptions",
		Summary:  "Public contract for outbound HTTPS webhook subscriptions fed by replayable Cerebro platform events.",
		EventTypes: []EventSubscriptionType{
			{Name: "agent.run.completed", Family: "agent_platform", Description: "A governed agent run reached a successful terminal outcome.", PayloadFields: []string{"event_id", "tenant_id", "trace_id", "capability_ids", "terminal_outcome", "occurred_at"}},
			{Name: "agent.run.failed", Family: "agent_platform", Description: "A governed agent run reached a failed terminal outcome.", PayloadFields: []string{"event_id", "tenant_id", "trace_id", "error_class", "occurred_at"}},
			{Name: "eval.scenario.completed", Family: "evals", Description: "A local or CI eval scenario completed with rubric outcomes.", PayloadFields: []string{"event_id", "tenant_id", "scenario_id", "score", "rubric_failures", "trace_link", "occurred_at"}},
			{Name: "adapter.execution.completed", Family: "execution", Description: "A source runtime or response adapter completed with explicit cancellation and truncation state.", PayloadFields: []string{"event_id", "tenant_id", "adapter_kind", "scope", "cancel_state", "truncation_state", "result_ref", "occurred_at"}},
			{Name: "adapter.execution.failed", Family: "execution", Description: "A source runtime or response adapter failed with explicit error class and scope.", PayloadFields: []string{"event_id", "tenant_id", "adapter_kind", "scope", "error_class", "occurred_at"}},
			{Name: "connector.auth.boundary.checked", Family: "connectors", Description: "Connector readiness, token owner, scopes, and surface were evaluated before tool use.", PayloadFields: []string{"event_id", "tenant_id", "source_id", "principal", "scopes", "token_owner", "surface", "occurred_at"}},
			{Name: "event.subscription.delivery.failed", Family: "event_subscriptions", Description: "A webhook delivery attempt failed and remains retryable or dead-lettered.", PayloadFields: []string{"event_id", "tenant_id", "subscription_id", "delivery_id", "event_type", "attempt", "status", "occurred_at"}},
		},
		Delivery: WebhookDeliveryContract{
			Transport: "https_webhook",
			EndpointRequirements: []string{
				"https URL without credentials, fragments, or private deployment labels",
				"receiver acknowledges with 2xx within 10s",
				"receiver treats duplicate delivery IDs and Idempotency-Key values as replay-safe",
			},
			Headers:   []string{"Cerebro-Event-ID", "Cerebro-Event-Type", "Cerebro-Delivery-ID", "Cerebro-Subscription-ID", "Cerebro-Signature", "Idempotency-Key"},
			AckStatus: "any 2xx response acknowledges delivery; other statuses are retryable unless policy marks them terminal",
			Timeout:   "10s",
		},
		Signing: WebhookSigningContract{
			Schemes:       []string{"hmac-sha256", "jwt-bearer"},
			SignatureBase: []string{"delivery_id", "event_id", "event_type", "timestamp", "raw_body_sha256"},
			KeyRotation:   "receivers must support overlapping active and next signing secrets or JWT keys",
		},
		Retry: WebhookRetryContract{
			Schedule:     []string{"immediate", "1m", "5m", "30m", "2h", "12h"},
			DeadLetter:   "delivery records are retained with status, attempt count, and last error class",
			DedupeWindow: "24h minimum",
			MaxAttempts:  6,
		},
		Idempotency: Idempotency(),
		RequiredControls: []string{
			"tenant-scoped subscription ownership",
			"explicit event type allow-list",
			"signature verification before accepting sensitive downstream actions",
			"delivery IDs and idempotency keys on every outbound attempt",
			"no secrets, internal hostnames, tenant labels, or resource inventory in public subscription metadata",
		},
	}
}

func Idempotency() IdempotencyContract {
	return IdempotencyContract{
		Version:        ContractVersion,
		Header:         "Idempotency-Key",
		MaxLengthBytes: 255,
		KeyScope:       []string{"tenant", "route", "method", "authenticated principal or device", "normalized request body hash where supported"},
		ConflictStatus: 409,
		ReplayHeaders:  []string{"Idempotent-Replayed"},
		Semantics: []string{
			"Clients should send a stable Idempotency-Key for every retried mutating public API request.",
			"The same key with the same scoped request returns the original or existing result when the route supports replay.",
			"The same key with a different scoped request returns 409 on routes that persist body hashes or uniqueness constraints.",
			"Keys are opaque client-generated values and must not contain secrets, credentials, tenant names, hostnames, or resource identifiers.",
		},
		Routes: []IdempotencyRouteContract{
			{Method: "POST", Path: "/platform/telemetry/ingest", Requirement: "required", Scope: "device_id + key + raw body hash", Replay: "cached 202 body with Idempotent-Replayed=true"},
			{Method: "POST", Path: "/platform/jobs", Requirement: "recommended", Scope: "tenant_id + key", Replay: "existing job returns 200 instead of creating a duplicate"},
			{Method: "POST", Path: "/connectors/{sourceID}/credentials", Requirement: "recommended", Scope: "tenant_id + source_id + runtime_id + key", Replay: "existing credential record returns 200"},
			{Method: "POST", Path: "/connectors/{sourceID}/credentials/{credentialID}/rotate", Requirement: "recommended", Scope: "tenant_id + source_id + runtime_id + key", Replay: "existing rotated credential record returns 200"},
			{Method: "POST", Path: "/api/v1/event-subscriptions", Requirement: "planned_required", Scope: "tenant_id + subscription target + key", Replay: "subscription create/update returns the existing subscription or 409 on mismatched target"},
			{Method: "POST", Path: "outbound webhook delivery", Requirement: "required", Scope: "subscription_id + delivery_id + event_id", Replay: "receiver deduplicates by delivery ID or Idempotency-Key"},
		},
	}
}
