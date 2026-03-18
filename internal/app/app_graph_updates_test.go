package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
)

type blockingConsistencySource struct {
	started  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (s *blockingConsistencySource) Query(ctx context.Context, query string, args ...any) (*builders.DataQueryResult, error) {
	_ = args
	if strings.Contains(strings.ToLower(query), "information_schema.tables") {
		s.once.Do(func() { close(s.started) })
		<-ctx.Done()
		close(s.finished)
		return nil, ctx.Err()
	}
	return &builders.DataQueryResult{Rows: []map[string]any{}}, nil
}

func TestAppCloseCancelsGraphConsistencyChecks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	source := &blockingConsistencySource{
		started:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	graphCtx, cancel := context.WithCancel(context.Background())

	application := &App{
		Config: &Config{
			GraphConsistencyCheckEnabled: true,
		},
		Logger:      logger,
		Findings:    findings.NewStore(),
		graphCtx:    graphCtx,
		graphCancel: cancel,
	}
	application.SecurityGraphBuilder = builders.NewBuilder(source, logger)
	application.SecurityGraph = application.SecurityGraphBuilder.Graph()

	application.maybeStartGraphConsistencyCheck("test", graph.GraphMutationSummary{
		Mode:            graph.GraphMutationModeIncremental,
		EventsProcessed: 1,
		NodesAdded:      1,
	})

	select {
	case <-source.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for consistency check to start")
	}

	if err := application.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	select {
	case <-source.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("expected Close to cancel and wait for graph consistency checks")
	}
}

func TestSetSecurityGraphRefreshesPropagationEngine(t *testing.T) {
	application := &App{}

	first := graph.New()
	first.AddNode(&graph.Node{ID: "service:first", Kind: graph.NodeKindService, Name: "first"})
	application.setSecurityGraph(first)
	firstEngine := application.propagationEngine()
	if firstEngine == nil {
		t.Fatal("expected propagation engine for first graph")
	}

	second := graph.New()
	second.AddNode(&graph.Node{ID: "service:second", Kind: graph.NodeKindService, Name: "second"})
	application.setSecurityGraph(second)
	secondEngine := application.propagationEngine()
	if secondEngine == nil {
		t.Fatal("expected propagation engine for second graph")
	}
	if firstEngine == secondEngine {
		t.Fatal("expected propagation engine to refresh after graph swap")
	}
}
