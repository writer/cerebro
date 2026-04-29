package sourceops

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
	googleworkspacesource "github.com/writer/cerebro/sources/googleworkspace"
	oktasource "github.com/writer/cerebro/sources/okta"
)

func TestList(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	response := service.List()
	if len(response.Sources) != 3 {
		t.Fatalf("len(List().Sources) = %d, want 3", len(response.Sources))
	}
}

func TestCheckDiscoverAndRead(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check().Status = %q, want %q", checkResp.Status, "ok")
	}

	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discoverResp.Urns) != 2 {
		t.Fatalf("len(Discover().Urns) = %d, want 2", len(discoverResp.Urns))
	}

	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "github",
		Config:   map[string]string{"token": "test"},
	})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read().Events) = %d, want 1", len(readResp.Events))
	}
	if readResp.NextCursor == nil {
		t.Fatal("Read().NextCursor = nil, want non-nil")
	}
	if len(readResp.PreviewEvents) != 1 {
		t.Fatalf("len(Read().PreviewEvents) = %d, want 1", len(readResp.PreviewEvents))
	}
	if readResp.PreviewEvents[0].EventId != readResp.Events[0].Id {
		t.Fatalf("Read().PreviewEvents[0].EventId = %q, want %q", readResp.PreviewEvents[0].EventId, readResp.Events[0].Id)
	}
	if readResp.PreviewEvents[0].GetEvent() != nil {
		t.Fatalf("Read().PreviewEvents[0].Event = %#v, want nil", readResp.PreviewEvents[0].GetEvent())
	}
	if !readResp.PreviewEvents[0].PayloadDecoded {
		t.Fatal("Read().PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestCheckDiscoverAndReadOkta(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	config := map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"token":  "test",
	}

	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Check(okta) error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check(okta).Status = %q, want %q", checkResp.Status, "ok")
	}

	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Discover(okta) error = %v", err)
	}
	if len(discoverResp.Urns) != 2 {
		t.Fatalf("len(Discover(okta).Urns) = %d, want 2", len(discoverResp.Urns))
	}

	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "okta",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Read(okta) error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read(okta).Events) = %d, want 1", len(readResp.Events))
	}
	if len(readResp.PreviewEvents) != 1 {
		t.Fatalf("len(Read(okta).PreviewEvents) = %d, want 1", len(readResp.PreviewEvents))
	}
	if !readResp.PreviewEvents[0].PayloadDecoded {
		t.Fatal("Read(okta).PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestCheckDiscoverAndReadGoogleWorkspace(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	service := New(registry)
	ctx := context.Background()

	config := map[string]string{
		"domain":   "writer.com",
		"family":   "user",
		"token":    "test-token",
		"per_page": "1",
	}
	checkResp, err := service.Check(ctx, &cerebrov1.CheckSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Check(google_workspace) error = %v", err)
	}
	if checkResp.Status != "ok" {
		t.Fatalf("Check(google_workspace).Status = %q, want ok", checkResp.Status)
	}
	discoverResp, err := service.Discover(ctx, &cerebrov1.DiscoverSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Discover(google_workspace) error = %v", err)
	}
	if len(discoverResp.Urns) != 2 {
		t.Fatalf("len(Discover(google_workspace).Urns) = %d, want 2", len(discoverResp.Urns))
	}
	readResp, err := service.Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: "google_workspace",
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Read(google_workspace) error = %v", err)
	}
	if len(readResp.Events) != 1 {
		t.Fatalf("len(Read(google_workspace).Events) = %d, want 1", len(readResp.Events))
	}
	if got := readResp.Events[0].GetKind(); got != "google_workspace.user" {
		t.Fatalf("Read(google_workspace).Events[0].Kind = %q, want google_workspace.user", got)
	}
}

func TestUnknownSource(t *testing.T) {
	service := New(nil)
	_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "github"})
	if !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("Check() error = %v, want ErrSourceNotFound", err)
	}
}

func TestEmptySourceIDIsInvalidRequest(t *testing.T) {
	service := New(nil)
	_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Check() error = %v, want ErrInvalidRequest", err)
	}
}

func newFixtureRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	okta, err := oktasource.NewFixture()
	if err != nil {
		return nil, err
	}
	googleWorkspace, err := googleworkspacesource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source, googleWorkspace, okta)
}
