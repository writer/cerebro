package sourceops

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	githubsource "github.com/writer/cerebro/sources/github"
)

func TestList(t *testing.T) {
	registry, err := newGitHubRegistry()
	if err != nil {
		t.Fatalf("newGitHubRegistry() error = %v", err)
	}
	service := New(registry)
	response := service.List()
	if len(response.Sources) != 1 {
		t.Fatalf("len(List().Sources) = %d, want 1", len(response.Sources))
	}
}

func TestCheckDiscoverAndRead(t *testing.T) {
	registry, err := newGitHubRegistry()
	if err != nil {
		t.Fatalf("newGitHubRegistry() error = %v", err)
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
	if !readResp.PreviewEvents[0].PayloadDecoded {
		t.Fatal("Read().PreviewEvents[0].PayloadDecoded = false, want true")
	}
}

func TestUnknownSource(t *testing.T) {
	service := New(nil)
	_, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "github"})
	if !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("Check() error = %v, want ErrSourceNotFound", err)
	}
}

func newGitHubRegistry() (*sourcecdk.Registry, error) {
	source, err := githubsource.NewFixture()
	if err != nil {
		return nil, err
	}
	return sourcecdk.NewRegistry(source)
}
