package archtests

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// bootstrapProductionGoLineBudget ratchets the raw line count of non-test Go in
// internal/bootstrap. grc_export.go adds GRC findings/controls CSV export
// handlers, and report_schedules.go adds scheduled-report request/response
// mapping plus the thin scheduler composition loop. ask_queries.go adds
// saved-ask-query request/response mapping and tenant-scoped CRUD handlers;
// durable storage lives in internal/statestore/postgres and the AskQueryStore
// port, so the additions stay within bootstrap's routing, auth, and composition
// responsibility. The ask-query write scope constant keeps saved-query mutation
// routes from reusing a read-only scope. risk_scoring_config.go adds the thin
// HTTP request/response mapping for tenant-scoped scoring overrides; validation
// and defaulting live in internal/findings, and storage lives behind the
// RiskScoringConfigStore port. The zero-preserving signal request shape keeps
// OpenAPI-permitted values distinguishable at the HTTP boundary. MCP risk action
// plan mapping now loads that same tenant config and passes it into the domain
// planner without moving scoring behavior into bootstrap. Graph-fact MCP tools
// add only typed request/response mapping over the graphfacts domain service and
// the existing ClaimStore-backed graph-fact substrate, including
// cursor/resource/toolset MCP surface mapping while fact shaping and trace
// behavior stay in graphfacts. Trace metadata mirrors list pagination flags at
// the MCP response boundary so clients see consistent cursor semantics. GRC
// source health summaries add dashboard response mapping while source-health
// aggregation stays behind existing stores. GRC framework lifecycle adds a thin
// HTTP handler and route registration for cached framework listing; compliance
// logic stays in the compliance package. Error-propagation cleanup (#1370) added
// explicit error returns and guard clauses across bootstrap handlers. Tenant
// dynamic connector runtimes add connector-library response mapping and setup
// method shaping while runnable source construction stays behind internal/sourceregistry.
// Runtime connector previews add thin HTTP request/response mapping while live
// check/read behavior stays behind internal/connectorpreview. File-organization
// refactor extracted finding, graph, source-runtime, and report handlers from
// app.go into domain-scoped files; the budget increase covers only the per-file
// package declarations and import blocks with no new behavior. Connector deposit
// ingest adds HTTP request/response mapping while runtime validation, append-log
// persistence, and graph projection stay behind internal/sourceruntime. Connector
// definition version history adds a thin GET handler plus version-record response
// mapping; the immutable snapshots are read through the ConnectorDefinitionStore
// port and storage stays in internal/statestore/postgres. Custom GRC dashboards
// add route wiring plus actor stamping while HTTP behavior lives behind
// internal/sourcehttp/customdashboards and storage stays behind the
// CustomDashboardStore port. The GRC report catalog and query API add a thin
// catalog handler plus a bounded query resolver that dispatches to existing GRC
// read handlers; the allowlisted source catalog and query validation live in
// internal/grccatalog, so bootstrap keeps only routing, request/response
// mapping, and the source-to-handler dispatch. GRC program readiness adds a
// thin HTTP handler that composes existing GRC packet builders, connector
// health mapping, and source coverage into the internal/grcprogram readiness
// domain response. User preferences add only route wiring plus trusted actor
// resolution; HTTP behavior lives in internal/sourcehttp/userpreferences and
// storage stays behind the UserPreferenceStore port. Agent claim verification
// and durable work contracts add HTTP and MCP request/resource mapping while
// claim verdicts, gates, and work state live in internal/agentplatform. GRC
// policy lifecycle adds route/scope/error mapping plus action and CSV export
// adapters; graph aggregation, action event construction, audit row shaping,
// and response shaping live in internal/grcpolicylifecycle.
const bootstrapProductionGoLineBudget = 26425

type bootstrapFileLineCount struct {
	path  string
	lines int
}

func TestBootstrapProductionSurfaceDoesNotGrow(t *testing.T) {
	root := repoRoot(t)
	counts := bootstrapProductionLineCounts(t, root, filepath.Join(root, "internal", "bootstrap"))
	total := 0
	for _, count := range counts {
		total += count.lines
	}
	if total <= bootstrapProductionGoLineBudget {
		return
	}
	t.Fatalf(
		"internal/bootstrap production Go grew to %d lines, budget %d (+%d).\n%s\nMove new domain behavior behind a domain package and keep bootstrap focused on routing, auth, request/response mapping, and dependency wiring; update the budget only with an architecture note.",
		total,
		bootstrapProductionGoLineBudget,
		total-bootstrapProductionGoLineBudget,
		topBootstrapFiles(counts, 8),
	)
}

func TestArchitectureDocumentsBootstrapOwnership(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docs", "reference", "architecture.md"))
	if err != nil {
		t.Fatalf("read docs/reference/architecture.md: %v", err)
	}
	for _, marker := range []string{
		"## Bootstrap ownership",
		"outer composition root",
		"routing, auth, request/response mapping, and dependency wiring",
		"New domain behavior should land behind a domain package",
		"Production Go under `internal/bootstrap` is ratcheted by `tools/archtests`",
	} {
		if !bytes.Contains(body, []byte(marker)) {
			t.Fatalf("docs/reference/architecture.md missing bootstrap ownership marker %q", marker)
		}
	}
}

func bootstrapProductionLineCounts(t *testing.T, root string, dir string) []bootstrapFileLineCount {
	t.Helper()
	counts := []bootstrapFileLineCount{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		counts = append(counts, bootstrapFileLineCount{
			path:  filepath.ToSlash(shortPath(root, path)),
			lines: countLines(t, path),
		})
		return nil
	}); err != nil {
		t.Fatalf("scan internal/bootstrap: %v", err)
	}
	return counts
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

func topBootstrapFiles(counts []bootstrapFileLineCount, limit int) string {
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].lines == counts[j].lines {
			return counts[i].path < counts[j].path
		}
		return counts[i].lines > counts[j].lines
	})
	if limit > len(counts) {
		limit = len(counts)
	}
	lines := make([]string, 0, limit+1)
	lines = append(lines, "largest bootstrap production files:")
	for i := 0; i < limit; i++ {
		lines = append(lines, fmt.Sprintf("- %s: %d", counts[i].path, counts[i].lines))
	}
	return strings.Join(lines, "\n")
}
