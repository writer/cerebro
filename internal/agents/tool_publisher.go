package agents

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	defaultToolPublisherManifestSubject = "cerebro.tools.manifest"
	defaultToolPublisherRequestPrefix   = "cerebro.tools.request"
	defaultToolPublisherRequestTimeout  = 30 * time.Second
	defaultToolPublisherAuthMode        = "none"
)

// ToolPublisherConfig defines NATS transport and auth settings for publishing
// Cerebro tools to external orchestrators (for example Ensemble).
type ToolPublisherConfig struct {
	Enabled         bool
	URLs            []string
	ManifestSubject string
	RequestPrefix   string
	RequestTimeout  time.Duration
	ConnectTimeout  time.Duration

	AuthMode string
	Username string
	Password string
	NKeySeed string
	UserJWT  string

	TLSEnabled            bool
	TLSCAFile             string
	TLSCertFile           string
	TLSKeyFile            string
	TLSServerName         string
	TLSInsecureSkipVerify bool
}

// ToolPublisher exposes a manifest and request handlers for local Cerebro tools
// over NATS request/reply.
type ToolPublisher struct {
	logger *slog.Logger
	config ToolPublisherConfig
	nc     *nats.Conn

	tools           map[string]Tool
	manifestPayload []byte
	manifestSub     *nats.Subscription
	requestSub      *nats.Subscription
}

type toolInvocationRequest struct {
	Tool         string          `json:"tool,omitempty"`
	Arguments    json.RawMessage `json:"arguments,omitempty"`
	ArgumentsRaw string          `json:"arguments_raw,omitempty"`
}

func NewToolPublisher(cfg ToolPublisherConfig, tools []Tool, logger *slog.Logger) (*ToolPublisher, error) {
	config := cfg.withDefaults()
	if !config.Enabled {
		return nil, nil
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	options, err := config.natsOptions()
	if err != nil {
		return nil, err
	}
	nc, err := nats.Connect(strings.Join(config.URLs, ","), options...)
	if err != nil {
		return nil, fmt.Errorf("connect tool publisher to nats: %w", err)
	}

	publisher := &ToolPublisher{
		logger: logger,
		config: config,
		nc:     nc,
		tools:  make(map[string]Tool),
	}
	if err := publisher.setTools(tools); err != nil {
		nc.Close()
		return nil, err
	}
	if err := publisher.start(); err != nil {
		_ = nc.Drain()
		nc.Close()
		return nil, err
	}

	logger.Info("registered cerebro tools for nats publication",
		"count", publisher.ToolCount(),
		"manifest_subject", config.ManifestSubject,
		"request_prefix", config.RequestPrefix,
	)
	return publisher, nil
}

func (p *ToolPublisher) setTools(tools []Tool) error {
	manifests := make([]RemoteToolManifest, 0, len(tools))
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" || tool.Handler == nil {
			continue
		}
		if _, exists := p.tools[name]; exists {
			return fmt.Errorf("duplicate tool name in publisher config: %s", name)
		}
		p.tools[name] = tool
		manifests = append(manifests, RemoteToolManifest{
			Name:             name,
			Description:      strings.TrimSpace(tool.Description),
			Parameters:       tool.Parameters,
			RequiresApproval: tool.RequiresApproval,
			TimeoutSeconds:   int(p.config.RequestTimeout.Seconds()),
		})
	}
	payload, err := json.Marshal(remoteManifestEnvelope{Tools: manifests})
	if err != nil {
		return fmt.Errorf("encode tool manifest: %w", err)
	}
	p.manifestPayload = payload
	return nil
}

func (p *ToolPublisher) start() error {
	if p == nil || p.nc == nil {
		return fmt.Errorf("tool publisher not initialized")
	}

	manifestSub, err := p.nc.Subscribe(p.config.ManifestSubject, p.handleManifestRequest)
	if err != nil {
		return fmt.Errorf("subscribe manifest subject: %w", err)
	}
	requestSubject := p.config.RequestPrefix + ".>"
	requestSub, err := p.nc.Subscribe(requestSubject, p.handleToolInvocation)
	if err != nil {
		_ = manifestSub.Unsubscribe()
		return fmt.Errorf("subscribe tool request subject: %w", err)
	}

	p.manifestSub = manifestSub
	p.requestSub = requestSub

	if err := p.nc.Flush(); err != nil {
		return fmt.Errorf("flush tool publisher subscriptions: %w", err)
	}

	// Also publish the manifest as an event so subscribers can cache capability
	// updates without issuing a direct request.
	if err := p.nc.Publish(p.config.ManifestSubject, p.manifestPayload); err != nil {
		return fmt.Errorf("publish tool manifest: %w", err)
	}
	return nil
}

func (p *ToolPublisher) handleManifestRequest(msg *nats.Msg) {
	if p == nil || msg == nil || msg.Reply == "" {
		return
	}
	if err := msg.Respond(p.manifestPayload); err != nil && p.logger != nil {
		p.logger.Warn("failed to respond with tool manifest", "error", err)
	}
}

func (p *ToolPublisher) handleToolInvocation(msg *nats.Msg) {
	if p == nil || msg == nil {
		return
	}

	req, args, err := decodeToolInvocationRequest(msg.Data)
	if err != nil {
		p.respondWithError(msg, err)
		return
	}

	toolName := strings.TrimSpace(req.Tool)
	if toolName == "" {
		toolName = extractToolNameFromSubject(p.config.RequestPrefix, msg.Subject)
	}
	if toolName == "" {
		p.respondWithError(msg, fmt.Errorf("tool name is required"))
		return
	}

	tool, ok := p.tools[toolName]
	if !ok || tool.Handler == nil {
		p.respondWithError(msg, fmt.Errorf("unknown tool: %s", toolName))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.config.RequestTimeout)
	defer cancel()

	result, err := tool.Handler(ctx, args)
	if err != nil {
		p.respondWithError(msg, err)
		return
	}
	p.respondWithPayload(msg, encodeToolSuccessPayload(result))
}

func decodeToolInvocationRequest(data []byte) (toolInvocationRequest, json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return toolInvocationRequest{}, nil, nil
	}
	if !json.Valid(trimmed) {
		return toolInvocationRequest{}, nil, fmt.Errorf("invalid tool request payload")
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		// Non-object JSON payloads are treated as direct tool arguments.
		return toolInvocationRequest{}, append(json.RawMessage(nil), trimmed...), nil
	}

	req := toolInvocationRequest{}
	if raw, ok := payload["tool"]; ok {
		_ = json.Unmarshal(raw, &req.Tool)
	}
	if raw, ok := payload["arguments"]; ok {
		req.Arguments = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := payload["arguments_raw"]; ok {
		_ = json.Unmarshal(raw, &req.ArgumentsRaw)
	}

	_, hasTool := payload["tool"]
	_, hasArgs := payload["arguments"]
	_, hasArgsRaw := payload["arguments_raw"]
	if !hasTool && !hasArgs && !hasArgsRaw {
		return req, append(json.RawMessage(nil), trimmed...), nil
	}

	if len(req.Arguments) > 0 {
		return req, req.Arguments, nil
	}
	if strings.TrimSpace(req.ArgumentsRaw) != "" {
		raw := strings.TrimSpace(req.ArgumentsRaw)
		if json.Valid([]byte(raw)) {
			return req, json.RawMessage(raw), nil
		}
		wrapped, _ := json.Marshal(raw)
		return req, wrapped, nil
	}

	return req, nil, nil
}

func extractToolNameFromSubject(prefix, subject string) string {
	trimmedPrefix := strings.Trim(strings.TrimSpace(prefix), ".")
	trimmedSubject := strings.Trim(strings.TrimSpace(subject), ".")
	if trimmedPrefix == "" || trimmedSubject == "" {
		return ""
	}
	expected := trimmedPrefix + "."
	if !strings.HasPrefix(trimmedSubject, expected) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmedSubject, expected))
}

func encodeToolSuccessPayload(result string) []byte {
	payload := remoteToolEnvelope{Status: "ok"}
	trimmed := strings.TrimSpace(result)
	if trimmed != "" {
		if json.Valid([]byte(trimmed)) {
			payload.Data = json.RawMessage(trimmed)
		} else {
			quoted, _ := json.Marshal(trimmed)
			payload.Data = quoted
		}
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}

func encodeToolErrorPayload(err error) []byte {
	message := "tool request failed"
	if err != nil {
		message = strings.TrimSpace(err.Error())
		if message == "" {
			message = "tool request failed"
		}
	}
	payload, _ := json.Marshal(remoteToolEnvelope{
		Status: "error",
		Error:  message,
	})
	return payload
}

func (p *ToolPublisher) respondWithError(msg *nats.Msg, err error) {
	p.respondWithPayload(msg, encodeToolErrorPayload(err))
}

func (p *ToolPublisher) respondWithPayload(msg *nats.Msg, payload []byte) {
	if msg == nil || msg.Reply == "" {
		return
	}
	if err := msg.Respond(payload); err != nil && p.logger != nil {
		p.logger.Warn("failed to respond to tool request", "error", err)
	}
}

func (p *ToolPublisher) ToolCount() int {
	if p == nil {
		return 0
	}
	return len(p.tools)
}

func (p *ToolPublisher) Close() error {
	if p == nil || p.nc == nil {
		return nil
	}
	if err := p.nc.Drain(); err != nil {
		p.nc.Close()
		return err
	}
	p.nc.Close()
	return nil
}

func (c ToolPublisherConfig) withDefaults() ToolPublisherConfig {
	cfg := c
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{"nats://127.0.0.1:4222"}
	}
	if cfg.ManifestSubject == "" {
		cfg.ManifestSubject = defaultToolPublisherManifestSubject
	}
	if cfg.RequestPrefix == "" {
		cfg.RequestPrefix = defaultToolPublisherRequestPrefix
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultToolPublisherRequestTimeout
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = defaultToolPublisherAuthMode
	}
	return cfg
}

func (c ToolPublisherConfig) validate() error {
	if len(c.URLs) == 0 {
		return fmt.Errorf("tool publisher requires at least one NATS URL")
	}
	if strings.TrimSpace(c.ManifestSubject) == "" {
		return fmt.Errorf("tool publisher manifest subject is required")
	}
	if strings.TrimSpace(c.RequestPrefix) == "" {
		return fmt.Errorf("tool publisher request prefix is required")
	}
	switch c.AuthMode {
	case "none":
	case "userpass":
		if strings.TrimSpace(c.Username) == "" || strings.TrimSpace(c.Password) == "" {
			return fmt.Errorf("tool publisher auth mode userpass requires username and password")
		}
	case "nkey":
		if strings.TrimSpace(c.NKeySeed) == "" {
			return fmt.Errorf("tool publisher auth mode nkey requires nkey seed")
		}
	case "jwt":
		if strings.TrimSpace(c.NKeySeed) == "" || strings.TrimSpace(c.UserJWT) == "" {
			return fmt.Errorf("tool publisher auth mode jwt requires nkey seed and user jwt")
		}
	default:
		return fmt.Errorf("unsupported tool publisher auth mode: %s", c.AuthMode)
	}
	return nil
}

func (c ToolPublisherConfig) natsOptions() ([]nats.Option, error) {
	options := []nats.Option{
		nats.Name("cerebro-tool-publisher"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	}
	if c.ConnectTimeout > 0 {
		options = append(options, nats.Timeout(c.ConnectTimeout))
	}

	authOpts, err := c.authOptions()
	if err != nil {
		return nil, err
	}
	options = append(options, authOpts...)

	if c.TLSEnabled {
		tlsConfig, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		options = append(options, nats.Secure(tlsConfig))
	}
	return options, nil
}

func (c ToolPublisherConfig) authOptions() ([]nats.Option, error) {
	switch c.AuthMode {
	case "none":
		return nil, nil
	case "userpass":
		return []nats.Option{nats.UserInfo(c.Username, c.Password)}, nil
	case "nkey":
		publicKey, signer, err := signerFromSeed(c.NKeySeed)
		if err != nil {
			return nil, err
		}
		return []nats.Option{nats.Nkey(publicKey, signer)}, nil
	case "jwt":
		_, signer, err := signerFromSeed(c.NKeySeed)
		if err != nil {
			return nil, err
		}
		jwt := strings.TrimSpace(c.UserJWT)
		return []nats.Option{nats.UserJWT(func() (string, error) { return jwt, nil }, signer)}, nil
	default:
		return nil, fmt.Errorf("unsupported tool publisher auth mode: %s", c.AuthMode)
	}
}

func (c ToolPublisherConfig) tlsConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.TLSInsecureSkipVerify,
	}
	if serverName := strings.TrimSpace(c.TLSServerName); serverName != "" {
		tlsConfig.ServerName = serverName
	}

	if caFile := strings.TrimSpace(c.TLSCAFile); caFile != "" {
		caPEM, err := os.ReadFile(caFile) // #nosec G304 -- TLS CA path is explicit operator configuration
		if err != nil {
			return nil, fmt.Errorf("read tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("load tls ca certs from %q", caFile)
		}
		tlsConfig.RootCAs = pool
	}

	certFile := strings.TrimSpace(c.TLSCertFile)
	keyFile := strings.TrimSpace(c.TLSKeyFile)
	if certFile != "" && keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, nil
}
