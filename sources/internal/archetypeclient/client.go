package archetypeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const defaultFanoutConcurrency = 4

type Settings struct {
	SourceID                 string
	BaseURL                  string
	Token                    string
	APIPrefix                string
	PrivateEndpointAllowlist []string
	AllowLoopback            bool
	FanoutConcurrency        int
}

type JSONTarget interface{}

type Scan struct {
	ID           int    `json:"id"`
	RepositoryID int    `json:"repository_id"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at"`
	CreatedAt    string `json:"created_at"`
}

type Vulnerability struct {
	ID            int     `json:"id"`
	ScanID        int     `json:"scan_id"`
	LineNumber    int     `json:"line_number"`
	FilePath      string  `json:"file_path"`
	Category      string  `json:"category"`
	Severity      string  `json:"severity"`
	Description   string  `json:"description"`
	AnalyzerScore float64 `json:"analyzer_score"`
	AnalyzerLabel string  `json:"analyzer_label"`
	CreatedAt     string  `json:"created_at"`
}

type KnowledgeEntry struct {
	Slug             string   `json:"slug"`
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	Topics           []string `json:"topics,omitempty"`
	DominantSeverity string   `json:"dominant_severity,omitempty"`
	RepositoryID     int      `json:"repository_id"`
	RepositoryName   string   `json:"repository_name"`
	Owner            string   `json:"owner"`
}

type Repository struct {
	ID    int    `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func Get(ctx context.Context, st Settings, path string, out JSONTarget) error {
	requestPath, err := sourcehttp.NormalizeRequestPath(st.SourceID, st.APIPrefix+path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, st.BaseURL+requestPath, nil)
	if err != nil {
		return err
	}
	if st.Token != "" {
		req.Header.Set("Authorization", "Bearer "+st.Token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := sourcehttp.DoWithRetry(ctx, sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:                 st.SourceID,
		AllowLoopback:            st.AllowLoopback,
		PrivateEndpointAllowlist: st.PrivateEndpointAllowlist,
	}), req, sourcehttp.RetryOptions{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &sourcecdk.HTTPStatusError{Code: resp.StatusCode, Message: fmt.Sprintf("archetype GET %s failed with status %d", path, resp.StatusCode)}
	}
	return json.Unmarshal(resp.Body, out)
}

func Repositories(ctx context.Context, st Settings) map[int]Repository {
	var repos []Repository
	if err := Get(ctx, st, "/repositories", &repos); err != nil {
		return nil
	}
	out := map[int]Repository{}
	for _, repo := range repos {
		out[repo.ID] = repo
	}
	return out
}

func RepositoryKnowledge(ctx context.Context, st Settings, repositoryID int) ([]KnowledgeEntry, bool) {
	var response struct {
		Entries []KnowledgeEntry `json:"entries"`
	}
	if err := Get(ctx, st, fmt.Sprintf("/repositories/%d/knowledge", repositoryID), &response); err != nil {
		if sourcecdk.IsHTTPStatus(err, http.StatusNotFound) || sourcecdk.IsHTTPStatus(err, http.StatusForbidden) || sourcecdk.IsRetryableHTTPStatus(err) {
			return nil, !sourcecdk.IsRetryableHTTPStatus(err)
		}
		return nil, false
	}
	return response.Entries, true
}

func VulnerabilitiesForScans(ctx context.Context, st Settings, scans []Scan) ([][]Vulnerability, error) {
	out := make([][]Vulnerability, len(scans))
	group, groupCtx := errgroup.WithContext(ctx)
	fanout := st.FanoutConcurrency
	if fanout <= 0 {
		fanout = defaultFanoutConcurrency
	}
	group.SetLimit(fanout)
	for i, scan := range scans {
		i, scan := i, scan
		group.Go(func() error {
			var vulns []Vulnerability
			if err := Get(groupCtx, st, fmt.Sprintf("/scans/%d/vulnerabilities", scan.ID), &vulns); err != nil {
				return err
			}
			out[i] = vulns
			return nil
		})
	}
	return out, group.Wait()
}
