package sentinelone

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysRepositorySentinelOneApplication(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", "sentinelone", familyApplication, "list_applications")
	if err != nil {
		t.Fatalf("FindBundle() error = %v", err)
	}
	fixtureRequest, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse fixture request URL: %v", err)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiToken "+fixtureToken {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if r.Host != fixtureRequest.Host || r.Method != http.MethodGet || r.URL.EscapedPath() != fixtureRequest.EscapedPath() || r.URL.Query().Get("ids") != fixtureRequest.Query().Get("ids") {
			t.Fatalf("unexpected SentinelOne replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	certificate := server.Certificate()
	if certificate == nil || len(certificate.DNSNames) == 0 {
		t.Fatal("TLS test server did not provide a DNS certificate identity")
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.ServerName = certificate.DNSNames[0]
	transport.TLSClientConfig = tlsConfig
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	source.client = &http.Client{Transport: transport}
	source.lookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": fixtureBaseURL,
		"family":   familyApplication,
		"token":    fixtureToken,
		"agent_id": fixtureRequest.Query().Get("ids"),
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("Read() returned %d events, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "sentinelone.application_inventory" {
		t.Fatalf("event kind = %q, want sentinelone.application_inventory", event.Kind)
	}
	if event.SchemaRef != "sentinelone/application_inventory/v1" {
		t.Fatalf("event schema = %q, want sentinelone/application_inventory/v1", event.SchemaRef)
	}
	if event.Attributes["family"] != familyApplication || event.Attributes["agent_id"] != "agent-fixture-1" {
		t.Fatalf("event attributes = %#v, want application family and agent identity", event.Attributes)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("Discover() returned %d URNs, want 1 agent scope", len(urns))
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyApplication, pull.Events, urns, updateSentinelOneFixtures()); err != nil {
		t.Fatal(err)
	}
}

func updateSentinelOneFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}
