package sourceworker

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const rustCheckpointCursorMode = "rust_provider_checkpoint"

// RustAuthoritativeFamily returns the normalized family only when the closed
// Rust dispatcher owns production execution for that exact source-family
// pair. Keep this allowlist narrower than the dispatcher's compiled adapters:
// an adapter contract alone is not an authority decision.
func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	sourceID = strings.TrimSpace(sourceID)
	familyID = strings.TrimSpace(familyID)
	switch sourceID {
	case "anthropic":
		if familyID == "" {
			familyID = "user"
		}
		// Every cataloged Anthropic family is closed in the Rust dispatcher.
		// Unknown families fail there instead of restoring the retired Go path.
		return familyID, true
	case "openai":
		if familyID == "" {
			familyID = "user"
		}
		// Every cataloged OpenAI family is closed in the Rust dispatcher.
		// Unknown families fail there instead of restoring the retired Go path.
		return familyID, true
	case "deepseek":
		if familyID == "" {
			familyID = "model_catalog"
		}
		// Both cataloged DeepSeek families are closed in the Rust dispatcher.
		// Unknown families fail there instead of restoring the retired Go path.
		return familyID, true
	case "azure_openai":
		if familyID == "" {
			familyID = "deployments"
		}
		return familyID, true
	case "cohere":
		if familyID == "" {
			familyID = "model_catalog"
		}
		return familyID, true
	case "google_gemini":
		if familyID == "" {
			familyID = "model_catalog"
		}
		return familyID, true
	case "google_vertex_ai":
		if familyID == "" {
			familyID = "models"
		}
		return familyID, true
	case "groq":
		if familyID == "" {
			familyID = "model_catalog"
		}
		return familyID, true
	case "huggingface":
		if familyID == "" {
			familyID = "organization_members"
		}
		return familyID, true
	case "mistral":
		if familyID == "" {
			familyID = "workspaces"
		}
		return familyID, true
	case "perplexity":
		if familyID == "" {
			familyID = "api_groups"
		}
		return familyID, true
	case "aws_bedrock":
		if familyID == "" {
			familyID = "foundation_models"
		}
		return familyID, true
	case "langfuse":
		if familyID == "" {
			familyID = "project"
		}
		return familyID, true
	case "cerebras":
		if familyID == "" {
			familyID = "projects"
		}
		return familyID, true
	case "cloudflare_workers_ai":
		if familyID == "" {
			familyID = "model_catalog"
		}
		return familyID, true
	case "elevenlabs":
		if familyID == "" {
			familyID = "model_catalog"
		}
		return familyID, true
	case "fireworks_ai":
		if familyID == "" {
			familyID = "model_deployments"
		}
		return familyID, true
	case "ibm_watsonx_ai":
		if familyID == "" {
			familyID = "foundation_model_specs"
		}
		return familyID, true
	case "langchain":
		if familyID == "" {
			familyID = "organization"
		}
		return familyID, true
	case "microsoft_foundry":
		if familyID == "" {
			familyID = "agents"
		}
		return familyID, true
	case "openrouter":
		if familyID == "" {
			familyID = "organization_members"
		}
		return familyID, true
	case "pinecone":
		if familyID == "" {
			familyID = "indexes"
		}
		return familyID, true
	case "qdrant_cloud":
		if familyID == "" {
			familyID = "accounts"
		}
		return familyID, true
	case "replicate":
		if familyID == "" {
			familyID = "models"
		}
		return familyID, true
	case "stability_ai":
		if familyID == "" {
			familyID = "engines"
		}
		return familyID, true
	case "together_ai":
		if familyID == "" {
			familyID = "projects"
		}
		return familyID, true
	case "writer":
		if familyID == "" {
			familyID = "application"
		}
		return familyID, true
	case "xai":
		if familyID == "" {
			familyID = "api_keys"
		}
		return familyID, true
	case "asana":
		if familyID == "" {
			familyID = "users"
		}
		// Every portable Asana family is closed in the Rust dispatcher. Unknown
		// families fail there instead of restoring the retired Go provider path.
		return familyID, true
	case "azure":
		return familyID, familyID == "authorization_policy"
	case "digitalocean":
		if familyID == "" {
			familyID = "droplets"
		}
		// Every public DigitalOcean family is closed in the Rust dispatcher. An
		// unknown future family must fail there instead of restoring Go authority.
		return familyID, true
	case "discord":
		if familyID == "" {
			familyID = "audit_log"
		}
		// Every portable Discord family is closed in the Rust dispatcher. Unknown
		// families fail there instead of restoring the retired Go provider path.
		return familyID, true
	case "jumpcloud":
		if familyID == "" {
			familyID = "users"
		}
		// Every public JumpCloud family is closed in the Rust dispatcher. An
		// unknown future family must fail there instead of restoring Go authority.
		return familyID, true
	case "linode":
		if familyID == "" {
			familyID = "issue"
		}
		return familyID, familyID == "issue"
	case "pagerduty":
		if familyID == "" {
			familyID = "user"
		}
		// Every portable PagerDuty family is closed in the Rust dispatcher. Unknown
		// families fail there instead of restoring the retired Go provider path.
		return familyID, true
	case "sentinelone":
		switch familyID {
		case "activity", "agent", "application", "exclusion", "group", "site", "threat":
			return familyID, true
		default:
			return familyID, false
		}
	case "tailscale":
		return TailscaleFamily(sourceID, familyID)
	case "twilio":
		return familyID, familyID == "accounts" || familyID == "audit_events" || familyID == "keys"
	default:
		return "", false
	}
}

// CredentialBinding selects the provider's ordered credential aliases from
// stored references and trusted-host resolved values. It returns strings only
// to the Go host; callers must never include the resolved value in worker
// metadata, receipts, or errors.
func CredentialBinding(sourceID string, references, resolved map[string]string) (string, string) {
	if strings.TrimSpace(sourceID) == "aws_bedrock" {
		accessReference := firstCredentialValue(references, "access_key", "access_key_id")
		secretReference := firstCredentialValue(references, "secret_key", "secret_access_key")
		accessKey := firstCredentialValue(resolved, "access_key", "access_key_id")
		secretKey := firstCredentialValue(resolved, "secret_key", "secret_access_key")
		if accessReference == "" || secretReference == "" || accessKey == "" || secretKey == "" {
			return "", ""
		}
		return secretReference, EncodeAWSHostCredential(accessKey, secretKey)
	}
	if strings.TrimSpace(sourceID) == "langfuse" {
		publicReference := strings.TrimSpace(references["public_key"])
		secretReference := strings.TrimSpace(references["secret_key"])
		publicKey := strings.TrimSpace(resolved["public_key"])
		secretKey := strings.TrimSpace(resolved["secret_key"])
		if publicReference == "" || secretReference == "" || publicKey == "" || secretKey == "" {
			return "", ""
		}
		basic := make([]byte, 0, len(publicKey)+1+len(secretKey))
		basic = append(basic, publicKey...)
		basic = append(basic, ':')
		basic = append(basic, secretKey...)
		encoded := base64.StdEncoding.EncodeToString(basic)
		clear(basic)
		return secretReference, encoded
	}
	if strings.TrimSpace(sourceID) == "twilio" {
		username := strings.TrimSpace(resolved["username"])
		passwordReference := strings.TrimSpace(references["password"])
		password := strings.TrimSpace(resolved["password"])
		if username == "" || passwordReference == "" || password == "" {
			return "", ""
		}
		basic := make([]byte, 0, len(username)+1+len(password))
		basic = append(basic, username...)
		basic = append(basic, ':')
		basic = append(basic, password...)
		encoded := base64.StdEncoding.EncodeToString(basic)
		clear(basic)
		return passwordReference, encoded
	}
	keys := []string{"graph_token", "token"}
	if strings.TrimSpace(sourceID) == "anthropic" {
		keys = []string{"token", "api_token", "api_key", "access_token"}
	}
	if strings.TrimSpace(sourceID) == "openai" {
		keys = []string{"token", "api_token", "api_key", "access_token"}
	}
	if strings.TrimSpace(sourceID) == "deepseek" {
		keys = []string{"token", "api_token", "api_key", "access_token"}
	}
	switch strings.TrimSpace(sourceID) {
	case "azure_openai", "cerebras", "cloudflare_workers_ai", "cohere", "elevenlabs", "fireworks_ai", "google_gemini", "google_vertex_ai", "groq", "huggingface", "ibm_watsonx_ai", "langchain", "microsoft_foundry", "mistral", "openrouter", "perplexity", "pinecone", "qdrant_cloud", "replicate", "stability_ai", "together_ai", "writer", "xai":
		keys = []string{"token", "api_token", "api_key", "access_token"}
	}
	if strings.TrimSpace(sourceID) == "discord" {
		keys = []string{"api_token", "api_key", "token"}
	}
	if strings.TrimSpace(sourceID) == "jumpcloud" {
		keys = []string{"api_key", "api_token", "token"}
	}
	for _, key := range keys {
		if reference := strings.TrimSpace(references[key]); reference != "" {
			return reference, strings.TrimSpace(resolved[key])
		}
	}
	return "", ""
}

// TrustedHostCredentialReference selects the opaque stored reference that
// fences a provider credential derived by a SourceExecutionCredentialProvider.
// It never accepts a resolved secret value.
func TrustedHostCredentialReference(sourceID string, references, resolved map[string]string) string {
	if strings.TrimSpace(sourceID) != "google_workspace" {
		return ""
	}
	if strings.TrimSpace(resolved["token"]) != "" {
		return strings.TrimSpace(references["token"])
	}
	if firstCredentialValue(resolved, "service_account_email") != "" &&
		firstCredentialValue(resolved, "delegated_admin_email", "subject_email") != "" {
		for _, key := range []string{"private_key", "service_account_private_key"} {
			if strings.TrimSpace(resolved[key]) != "" {
				return strings.TrimSpace(references[key])
			}
		}
	}
	if strings.TrimSpace(resolved["client_id"]) != "" && strings.TrimSpace(resolved["client_secret"]) != "" && strings.TrimSpace(resolved["refresh_token"]) != "" {
		return strings.TrimSpace(references["refresh_token"])
	}
	return ""
}

// TailscaleFamily normalizes the requested Tailscale family, including the
// public default used when family is omitted. The closed Rust dispatcher owns
// family membership validation; Go must not restore legacy authority for an
// unknown family.
func TailscaleFamily(sourceID, familyID string) (string, bool) {
	if strings.TrimSpace(sourceID) != "tailscale" {
		return "", false
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		familyID = "device"
	}
	return familyID, true
}

// PublicExecutionConfig returns only configuration declared safe for the
// credential-free worker protocol.
func PublicExecutionConfig(values map[string]string) map[string]string {
	public := make(map[string]string)
	for _, key := range []string{
		"account_sid", "activity_type", "agent_id", "application_id", "audit_end_time", "audit_services", "audit_sort", "audit_start_time", "base_url",
		"family", "group_id", "group_ids", "guild_id", "insights_base_url", "org_id", "page_size", "per_page",
		"service_id", "service_ids", "since", "site_id", "tailnet", "until", "user_group_id", "user_group_ids", "workspace_gid",
	} {
		if value, ok := values[key]; ok {
			public[key] = strings.TrimSpace(value)
		}
	}
	return public
}

// PublicExecutionConfigForSource adds provider-specific selectors that are
// safe for the credential-free protocol. Secret-bearing aliases remain absent.
func PublicExecutionConfigForSource(sourceID string, values map[string]string) map[string]string {
	public := PublicExecutionConfig(values)
	switch strings.TrimSpace(sourceID) {
	case "anthropic":
		for _, key := range []string{
			"activity_types", "actor_ids", "auth_model", "bucket_width", "context_windows",
			"created_at_gt", "created_at_gte", "created_at_lt", "created_at_lte", "ending_at",
			"group_by", "group_id", "include_archived", "inference_geos", "model", "models",
			"organization_ids", "organization_uuid", "periods", "project_id", "role_id",
			"service_tiers", "speeds", "starting_at", "status", "terminal_types", "user_ids",
			"workspace_id", "workspace_ids",
		} {
			copyPublicValue(public, values, key)
		}
		copyPublicAlias(public, values, "api_key_ids", "admin_key_ids")
	case "openai":
		for _, key := range []string{
			"actor_emails", "actor_ids", "batch", "bucket_width", "effective_at_gt",
			"effective_at_gte", "effective_at_lt", "effective_at_lte", "end_time", "event_types",
			"group_by", "group_id", "models", "project_id", "project_ids", "resource_ids",
			"start_time", "tenant_only", "user_id", "user_ids",
		} {
			copyPublicValue(public, values, key)
		}
		copyPublicAlias(public, values, "api_key_ids", "admin_key_ids")
	case "google_workspace":
		for _, key := range []string{"customer_id", "domain"} {
			copyPublicValue(public, values, key)
		}
	case "azure_openai":
		for _, key := range []string{"subscription_id", "resource_group", "account_name", "location"} {
			copyPublicValue(public, values, key)
		}
	case "google_vertex_ai":
		for _, key := range []string{"project_id", "location"} {
			copyPublicValue(public, values, key)
		}
	case "huggingface":
		copyPublicValue(public, values, "organization")
	case "cohere", "google_gemini", "groq", "mistral", "perplexity":
		// These catalog-defined families need no public provider selectors.
	case "aws_bedrock":
		for _, key := range []string{"region", "service"} {
			copyPublicValue(public, values, key)
		}
	case "langfuse":
		for _, key := range []string{
			"project_id", "from_timestamp", "to_timestamp", "from_start_time", "to_start_time",
			"trace_id", "user_id", "session_id", "name", "type", "release", "version", "tags",
			"fields", "filter", "label", "tag", "metrics_query",
		} {
			copyPublicValue(public, values, key)
		}
	case "cloudflare_workers_ai":
		for _, key := range []string{"account_id", "gateway_id"} {
			copyPublicValue(public, values, key)
		}
	case "elevenlabs":
		copyPublicValue(public, values, "service_account_user_id")
	case "fireworks_ai":
		copyPublicValue(public, values, "account_id")
	case "ibm_watsonx_ai":
		for _, key := range []string{"project_id", "region"} {
			copyPublicValue(public, values, key)
		}
	case "langchain":
		for _, key := range []string{
			"auth_model", "data_plane_id", "end_time", "event_type", "feedback_source",
			"filter", "include_deleted", "include_stats", "key", "name", "name_contains",
			"organization_id", "project", "run_id", "run_type", "session", "start_time", "workspace_id",
		} {
			copyPublicValue(public, values, key)
		}
	case "microsoft_foundry":
		for _, key := range []string{"endpoint", "project_name"} {
			copyPublicValue(public, values, key)
		}
	case "qdrant_cloud":
		for _, key := range []string{"account_id", "cluster_id"} {
			copyPublicValue(public, values, key)
		}
	case "writer":
		for _, key := range []string{"file_types", "graph_id", "order", "status", "type"} {
			copyPublicValue(public, values, key)
		}
	case "cerebras", "openrouter", "pinecone", "replicate", "stability_ai", "together_ai", "xai":
		// These catalog-defined families need no additional public selectors.
	default:
		return public
	}
	return public
}

func firstCredentialValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

// EncodeAWSHostCredential binds an AWS access-key pair for one trusted-host
// redemption. The opaque value must never enter worker metadata or receipts.
func EncodeAWSHostCredential(accessKey, secretKey string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(accessKey)) + "." + base64.RawStdEncoding.EncodeToString([]byte(secretKey))
}

func copyPublicValue(public, values map[string]string, key string) {
	if value, ok := values[key]; ok {
		public[key] = strings.TrimSpace(value)
	}
}

func copyPublicAlias(public, values map[string]string, privateName, publicName string) {
	if value, ok := values[privateName]; ok {
		public[publicName] = strings.TrimSpace(value)
	}
}

// ProviderResume unwraps a durable Rust checkpoint without allowing it to
// switch source or family. Provider-native cursors remain accepted for an
// active page continuation and are validated again by Rust planning.
func ProviderResume(cursor *cerebrov1.SourceCursor, sourceID, familyID string) (string, int64, error) {
	if cursor == nil {
		return "", 0, nil
	}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return "", 0, nil
	}
	envelope, encoded := sourcecdk.DecodeCursorEnvelope(opaque)
	if !encoded {
		if strings.HasPrefix(opaque, "{") {
			return "", 0, fmt.Errorf("%w: malformed durable cursor envelope", ErrWorkerContract)
		}
		return opaque, 0, nil
	}
	if envelope.Version != 1 || !envelope.ResumableCheckpoint || envelope.Mode != rustCheckpointCursorMode || envelope.Source != strings.TrimSpace(sourceID) || envelope.Family != strings.TrimSpace(familyID) {
		return "", 0, fmt.Errorf("%w: durable cursor source or family mismatch", ErrWorkerContract)
	}
	if envelope.Token != "" && len(envelope.BoundaryIDs) != 0 {
		return "", 0, fmt.Errorf("%w: durable cursor mixes continuation and terminal boundary", ErrWorkerContract)
	}
	watermark := sourcecdk.CursorWatermark(envelope)
	if envelope.Watermark != "" && watermark.IsZero() {
		return "", 0, fmt.Errorf("%w: durable cursor watermark is malformed", ErrWorkerContract)
	}
	return envelope.Token, watermark.UnixMilli(), nil
}

// PullFromExecutionOutput maps Rust-authored page evidence into the Go host's
// append input. Result.NextCursor controls only same-run pagination; the
// lifecycle checkpoint is encoded independently for a later restart.
func PullFromExecutionOutput(output *ExecutionOutput, tenantID string) (sourcecdk.Pull, error) {
	if output == nil || output.Plan == nil || output.Result == nil || output.Program == nil || output.Program.TransitionDigest == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%w: Rust did not seal the page program", ErrWorkerContract)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(output.Program.AdmittedRecords))
	for _, record := range output.Program.AdmittedRecords {
		if record == nil {
			return sourcecdk.Pull{}, fmt.Errorf("%w: Rust admitted an empty record", ErrWorkerContract)
		}
		events = append(events, &cerebrov1.EventEnvelope{
			Id: record.GetEventId(), TenantId: strings.TrimSpace(tenantID), SourceId: output.Plan.GetSourceId(),
			Kind: output.Plan.GetEventKind(), SchemaRef: output.Plan.GetSchemaRef(), Payload: record.GetPayloadJson(),
			Attributes: record.GetAttributes(), OccurredAt: timestamppb.New(time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()),
		})
	}
	watermark := timestamppb.New(time.UnixMilli(output.Program.CheckpointWatermarkUnixMillis).UTC())
	if err := watermark.CheckValid(); err != nil {
		return sourcecdk.Pull{}, fmt.Errorf("%w: Rust checkpoint watermark is invalid", ErrWorkerContract)
	}
	checkpointCursor := output.Result.GetResultDigestSha256()
	nextCursor := strings.TrimSpace(output.Result.GetNextCursor())
	if _, authoritative := RustAuthoritativeFamily(output.Plan.GetSourceId(), output.Plan.GetFamilyId()); authoritative {
		envelope := sourcecdk.CursorEnvelope{
			Version: 1, Source: output.Plan.GetSourceId(), Family: output.Plan.GetFamilyId(),
			Mode: rustCheckpointCursorMode, ResumableCheckpoint: true, Token: nextCursor,
		}
		if boundary := strings.TrimSpace(output.Program.CheckpointCursor); nextCursor == "" && boundary != "" {
			envelope.BoundaryIDs = []string{boundary}
		}
		sourcecdk.SetCursorWatermark(&envelope, watermark.AsTime())
		var err error
		checkpointCursor, err = sourcecdk.EncodeCursorEnvelope(envelope)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("%w: encode Rust checkpoint: %w", ErrWorkerContract, err)
		}
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: checkpointCursor, Watermark: watermark}}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	return pull, nil
}
