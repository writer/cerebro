package catalogruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type FixtureReadResult struct {
	EventKinds []string
	SchemaRefs []string
	Query      url.Values
	EventCount int
}

func ReadDefinitionFixture(ctx context.Context, definition connectordefinitions.Definition, familyID string, body []byte) (FixtureReadResult, error) {
	var requested url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	source, err := NewDefinitionWithValidationOptions(definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		return FixtureReadResult{}, err
	}
	pull, err := source.Read(ctx, sourcecdk.NewConfig(map[string]string{
		"tenant_id": "connector-contract-test",
		"family":    familyID,
		"base_url":  server.URL,
		"token":     "fixture-token",
		"api_key":   "fixture-token",
	}), nil)
	if err != nil {
		return FixtureReadResult{}, err
	}
	result := FixtureReadResult{
		Query:      requested,
		EventCount: len(pull.Events),
	}
	for _, event := range pull.Events {
		if event == nil {
			continue
		}
		result.EventKinds = append(result.EventKinds, event.Kind)
		result.SchemaRefs = append(result.SchemaRefs, event.SchemaRef)
	}
	return result, nil
}
