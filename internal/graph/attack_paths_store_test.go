package graph

import (
	"context"
	"reflect"
	"testing"
)

func TestAttackPathStoreRootsIncludesInternetExposedResources(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "db:public", Kind: NodeKindDatabase, Name: "Public DB", Risk: RiskCritical})
	g.AddNode(&Node{ID: "db:internal", Kind: NodeKindDatabase, Name: "Internal DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "internet-public", Source: "internet", Target: "db:public", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "public-internal", Source: "db:public", Target: "db:internal", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	roots, err := attackPathStoreRoots(context.Background(), g)
	if err != nil {
		t.Fatalf("attackPathStoreRoots() error = %v", err)
	}
	got := make([]string, 0, len(roots))
	for _, root := range roots {
		if root != nil {
			got = append(got, root.ID)
		}
	}
	want := []string{"db:public", "internet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attackPathStoreRoots() = %#v, want %#v", got, want)
	}
}
