package main

import "testing"

func TestParseGraphRebuildArgs(t *testing.T) {
	runtimeID, pageLimit, previewLimit, dryRun, err := parseGraphRebuildArgs([]string{
		"writer-github",
		"page_limit=3",
		"preview_limit=7",
		"dry_run=true",
	})
	if err != nil {
		t.Fatalf("parseGraphRebuildArgs() error = %v", err)
	}
	if runtimeID != "writer-github" {
		t.Fatalf("runtimeID = %q, want %q", runtimeID, "writer-github")
	}
	if pageLimit != 3 {
		t.Fatalf("pageLimit = %d, want 3", pageLimit)
	}
	if previewLimit != 7 {
		t.Fatalf("previewLimit = %d, want 7", previewLimit)
	}
	if !dryRun {
		t.Fatalf("dryRun = %t, want true", dryRun)
	}
}

func TestParseGraphRebuildArgsRejectsUnknownKey(t *testing.T) {
	_, _, _, _, err := parseGraphRebuildArgs([]string{"writer-github", "bogus=1"})
	if err == nil {
		t.Fatal("parseGraphRebuildArgs() error = nil, want usage error")
	}
}
