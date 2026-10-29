package cloud_identity

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestReadRejectsIncompletePlanBeforeProviderAccess(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range []string{
		`{"scope":"example","targets":[],"services":[]}`,
		`{"scope":"example","targets":[],"services":[],"allow_unsafe_promotion":true}`,
	} {
		pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "example", "family": "cohort", "scan_plan": plan}), nil)
		if err == nil || len(pull.Events) != 0 || pull.NextCursor != nil {
			t.Fatalf("invalid plan was admitted as a collection: pull=%#v err=%v", pull, err)
		}
	}
}
