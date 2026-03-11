package agents

import (
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
	"github.com/nats-io/nkeys"
)

const (
	defaultRemoteToolsManifestSubject = "ensemble.tools.manifest"
	defaultRemoteToolsRequestPrefix   = "ensemble.tools.request"
	defaultRemoteToolsDiscoverTimeout = 5 * time.Second
	defaultRemoteToolsRequestTimeout  = 30 * time.Second
	defaultRemoteToolsAuthMode        = "none"
)

type RemoteToolProviderConfig struct {
	Enabled         bool
	URLs            []string
	ManifestSubject string
	RequestPrefix   string
	DiscoverTimeout time.Duration
	RequestTimeout  time.Duration
	MaxTools        int
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

type RemoteToolProvider struct {
	logger *slog.Logger
	config RemoteToolProviderConfig
	nc     *nats.Conn
}

type RemoteToolManifest struct {
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Parameters       map[string]interface{} `json:"parameters"`
	RequiresApproval bool                   `json:"requires_approval"`
	TimeoutSeconds   int                    `json:"timeout_seconds,omitempty"`
}

type remoteToolEnvelope struct {
	Status string          `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type remoteManifestEnvelope struct {
	Tools []RemoteToolManifest `json:"tools"`
}

func NewRemoteToolProvider(cfg RemoteToolProviderConfig, logger *slog.Logger) (*RemoteToolProvider, error) {
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
		return nil, fmt.Errorf("connect remote tools to nats: %w", err)
	}

	return &RemoteToolProvider{
		logger: logger,
		config: config,
		nc:     nc,
	}, nil
}

func (p *RemoteToolProvider) Close() error {
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

func (p *RemoteToolProvider) DiscoverTools(ctx context.Context) ([]Tool, error) {
	if p == nil || p.nc == nil {
		return nil, nil
	}
	discoverCtx, cancel := context.WithTimeout(ctx, p.config.DiscoverTimeout)
	defer cancel()

	req := map[string]interface{}{
		"source": "cerebro",
	}
	payload, _ := json.Marshal(req)

	msg, err := p.nc.RequestWithContext(discoverCtx, p.config.ManifestSubject, payload)
	if err != nil {
		return nil, fmt.Errorf("discover remote tools: %w", err)
	}

	manifests, err := decodeRemoteManifest(msg.Data)
	if err != nil {
		return nil, err
	}

	if p.config.MaxTools > 0 && len(manifests) > p.config.MaxTools {
		manifests = manifests[:p.config.MaxTools]
	}

	tools := make([]Tool, 0, len(manifests))
	for _, manifest := range manifests {
		name := strings.TrimSpace(manifest.Name)
		if name == "" {
			continue
		}
		timeout := p.config.RequestTimeout
		if manifest.TimeoutSeconds > 0 {
			timeout = time.Duration(manifest.TimeoutSeconds) * time.Second
		}
		toolName := name
		tools = append(tools, Tool{
			Name:             toolName,
			Description:      strings.TrimSpace(manifest.Description),
			Parameters:       manifest.Parameters,
			RequiresApproval: manifest.RequiresApproval,
			Handler: func(toolCtx context.Context, args json.RawMessage) (string, error) {
				return p.invoke(toolCtx, toolName, args, timeout)
			},
		})
	}

	return tools, nil
}

func decodeRemoteManifest(data []byte) ([]RemoteToolManifest, error) {
	var list []RemoteToolManifest
	if err := json.Unmarshal(data, &list); err == nil {
		return list, nil
	}

	var wrapped remoteManifestEnvelope
	if err := json.Unmarshal(data, &wrapped); err == nil {
		if len(wrapped.Tools) == 0 && !strings.Contains(string(data), "\"tools\"") {
			return nil, fmt.Errorf("decode remote tool manifest")
		}
		return wrapped.Tools, nil
	}

	return nil, fmt.Errorf("decode remote tool manifest")
}

func MergeTools(base []Tool, extras []Tool) []Tool {
	seen := make(map[string]struct{}, len(base))
	merged := make([]Tool, 0, len(base)+len(extras))

	for _, tool := range base {
		merged = append(merged, tool)
		seen[tool.Name] = struct{}{}
	}
	for _, tool := range extras {
		if _, exists := seen[tool.Name]; exists {
			continue
		}
		merged = append(merged, tool)
		seen[tool.Name] = struct{}{}
	}
	return merged
}

func (p *RemoteToolProvider) invoke(ctx context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	subject := fmt.Sprintf("%s.%s", p.config.RequestPrefix, toolName)
	request := map[string]interface{}{
		"tool": toolName,
	}
	if len(args) > 0 {
		var decoded interface{}
		if err := json.Unmarshal(args, &decoded); err == nil {
			request["arguments"] = decoded
		} else {
			request["arguments_raw"] = string(args)
		}
	}
	payload, _ := json.Marshal(request)

	msg, err := p.nc.RequestWithContext(requestCtx, subject, payload)
	if err != nil {
		return "", fmt.Errorf("remote tool %s request failed: %w", toolName, err)
	}

	var envelope remoteToolEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err == nil && (envelope.Status != "" || envelope.Error != "" || len(envelope.Data) > 0) {
		if strings.EqualFold(envelope.Status, "error") || strings.TrimSpace(envelope.Error) != "" {
			return "", fmt.Errorf("remote tool %s failed: %s", toolName, strings.TrimSpace(envelope.Error))
		}
		if len(envelope.Data) > 0 {
			return string(envelope.Data), nil
		}
	}

	return string(msg.Data), nil
}

func (p *RemoteToolProvider) CallTool(ctx context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = p.config.RequestTimeout
	}
	return p.invoke(ctx, strings.TrimSpace(toolName), args, timeout)
}

func (c RemoteToolProviderConfig) withDefaults() RemoteToolProviderConfig {
	cfg := c
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{"nats://127.0.0.1:4222"}
	}
	if cfg.ManifestSubject == "" {
		cfg.ManifestSubject = defaultRemoteToolsManifestSubject
	}
	if cfg.RequestPrefix == "" {
		cfg.RequestPrefix = defaultRemoteToolsRequestPrefix
	}
	if cfg.DiscoverTimeout <= 0 {
		cfg.DiscoverTimeout = defaultRemoteToolsDiscoverTimeout
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRemoteToolsRequestTimeout
	}
	if cfg.MaxTools <= 0 {
		cfg.MaxTools = 200
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = defaultRemoteToolsAuthMode
	}
	return cfg
}

func (c RemoteToolProviderConfig) validate() error {
	if len(c.URLs) == 0 {
		return fmt.Errorf("remote tools requires at least one NATS URL")
	}
	if strings.TrimSpace(c.ManifestSubject) == "" {
		return fmt.Errorf("remote tools manifest subject is required")
	}
	if strings.TrimSpace(c.RequestPrefix) == "" {
		return fmt.Errorf("remote tools request prefix is required")
	}
	switch c.AuthMode {
	case "none":
	case "userpass":
		if strings.TrimSpace(c.Username) == "" || strings.TrimSpace(c.Password) == "" {
			return fmt.Errorf("remote tools auth mode userpass requires username and password")
		}
	case "nkey":
		if strings.TrimSpace(c.NKeySeed) == "" {
			return fmt.Errorf("remote tools auth mode nkey requires nkey seed")
		}
	case "jwt":
		if strings.TrimSpace(c.NKeySeed) == "" || strings.TrimSpace(c.UserJWT) == "" {
			return fmt.Errorf("remote tools auth mode jwt requires nkey seed and user jwt")
		}
	default:
		return fmt.Errorf("unsupported remote tools auth mode: %s", c.AuthMode)
	}
	return nil
}

func (c RemoteToolProviderConfig) natsOptions() ([]nats.Option, error) {
	options := []nats.Option{
		nats.Name("cerebro-remote-tool-provider"),
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

func (c RemoteToolProviderConfig) authOptions() ([]nats.Option, error) {
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
		return nil, fmt.Errorf("unsupported remote tools auth mode: %s", c.AuthMode)
	}
}

func signerFromSeed(seed string) (string, func([]byte) ([]byte, error), error) {
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(seed)))
	if err != nil {
		return "", nil, fmt.Errorf("parse nkey seed: %w", err)
	}

	publicKey, err := kp.PublicKey()
	if err != nil {
		return "", nil, fmt.Errorf("derive nkey public key: %w", err)
	}

	signer := func(nonce []byte) ([]byte, error) {
		return kp.Sign(nonce)
	}

	return publicKey, signer, nil
}

func (c RemoteToolProviderConfig) tlsConfig() (*tls.Config, error) {
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
