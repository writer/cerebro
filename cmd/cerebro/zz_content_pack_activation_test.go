package main

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/contentpacks"
)

func TestActivateContentPacksIsolatesConnectorParserFailure(t *testing.T) {
	selection := contentpacks.RuntimeSelection{
		ConnectorCatalogs: map[string][]byte{"deepseek": []byte("not: [valid")},
		PolicyRules:       map[string][]byte{},
		State: contentpacks.RuntimeState{Accepted: []contentpacks.ActivePack{{
			PackID: "deepseek-catalog", Kind: "connector",
		}}},
	}

	sources, _, err := activateContentPacks(&selection)
	if err != nil {
		t.Fatalf("activateContentPacks() error = %v", err)
	}
	deepseek, ok := sources.Get("deepseek")
	if !ok {
		t.Fatal("embedded DeepSeek source is not registered")
	}
	if got := deepseek.Spec().GetName(); got != "DeepSeek" {
		t.Fatalf("DeepSeek source name = %q, want embedded fallback", got)
	}
	if len(selection.State.Accepted) != 0 || len(selection.State.Rejected) != 1 {
		t.Fatalf("selection state = %#v, want isolated connector rejection", selection.State)
	}
	if got := strings.Join(selection.State.FallbackKinds, ","); got != "connector,policy-control" {
		t.Fatalf("fallback kinds = %q, want connector,policy-control", got)
	}
}

func TestActivateContentPacksIsolatesPolicyParserFailure(t *testing.T) {
	selection := contentpacks.RuntimeSelection{
		ConnectorCatalogs: map[string][]byte{},
		PolicyRules: map[string][]byte{
			"ai-agent-tool-allowlist-required": []byte("not: [valid"),
		},
		State: contentpacks.RuntimeState{Accepted: []contentpacks.ActivePack{{
			PackID: "ai-tool-policy", Kind: "policy-control",
		}}},
	}

	_, rules, err := activateContentPacks(&selection)
	if err != nil {
		t.Fatalf("activateContentPacks() error = %v", err)
	}
	if _, ok := rules.Get("ai-agent-tool-allowlist-required"); !ok {
		t.Fatal("embedded AI tool policy is not registered")
	}
	if len(selection.State.Accepted) != 0 || len(selection.State.Rejected) != 1 {
		t.Fatalf("selection state = %#v, want isolated policy-control rejection", selection.State)
	}
}
