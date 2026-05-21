package main

import (
	"testing"
	"time"
)

func TestParseVulnDBOptionsSyncJobFields(t *testing.T) {
	options, err := parseVulnDBOptions([]string{
		"store=file",
		"job_id=osv-hourly",
		"feed_source=osv",
		"url=/tmp/osv.json",
		"interval=1h",
		"lease_ttl=5m",
		"limit=2",
		"allow_insecure_http=true",
	})
	if err != nil {
		t.Fatalf("parseVulnDBOptions() error = %v", err)
	}
	if options.StoreMode != "file" || options.JobID != "osv-hourly" || options.FeedSource != "osv" || options.Source != "/tmp/osv.json" {
		t.Fatalf("unexpected parsed options: %+v", options)
	}
	if options.JobInterval != time.Hour || options.JobLeaseTTL != 5*time.Minute || options.Limit != 2 || !options.AllowInsecureHTTP {
		t.Fatalf("unexpected parsed durations/flags: %+v", options)
	}
}

func TestShouldUseStateVulnDBStoreHonorsExplicitStateFile(t *testing.T) {
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")
	if shouldUseStateVulnDBStore(vulnDBOptions{StateFileExplicit: true, StateFile: "local.json"}) {
		t.Fatal("expected explicit state_file to keep file store in auto mode")
	}
	if !shouldUseStateVulnDBStore(vulnDBOptions{StateFileExplicit: true, StateFile: "local.json", StoreMode: "state"}) {
		t.Fatal("expected store=state to force configured state store")
	}
}
