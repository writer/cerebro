package connectorpresentation

import "testing"

func TestConnectorPresentationHelpers(t *testing.T) {
	if view, err := ParseLibraryView(""); err != nil || view != "full" {
		t.Fatalf("ParseLibraryView(empty) = %q, %v", view, err)
	}
	if _, err := ParseLibraryView("compact"); err == nil {
		t.Fatal("ParseLibraryView(compact) error = nil")
	}
	if !SourceListed([]string{" AWS "}, "aws") {
		t.Fatal("SourceListed() = false")
	}
	if got := ActivityID("runtime", "sync", "now"); got != "runtime:sync:now" {
		t.Fatalf("ActivityID() = %q", got)
	}
}
