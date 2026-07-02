package catalogruntime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

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
	pull, err := source.Read(ctx, fixtureConfig(definition, familyID, server.URL), nil)
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

func fixtureConfig(definition connectordefinitions.Definition, familyID string, baseURL string) sourcecdk.Config {
	values := map[string]string{
		"tenant_id": "connector-contract-test",
		"family":    familyID,
		"base_url":  baseURL,
		"token":     "fixture-token",
		"api_key":   "fixture-token",
	}
	for _, field := range append(definition.ConfigFields, definition.Auth.CredentialFields...) {
		key := strings.TrimSpace(field.Key)
		if key == "" || !field.Required || strings.TrimSpace(values[key]) != "" {
			continue
		}
		values[key] = fixtureValue(key)
	}
	return sourcecdk.NewConfig(values)
}

func fixtureValue(key string) string {
	switch strings.TrimSpace(key) {
	case "client_id":
		return "fixture-client-id"
	case "client_secret":
		return "fixture-client-secret"
	case "enterprise_id":
		return "fixture-enterprise-id"
	default:
		return "fixture-" + strings.ReplaceAll(strings.TrimSpace(key), "_", "-")
	}
}
