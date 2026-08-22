package sourceprojection

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type kubernetesRustProjectionFixture struct {
	TenantID string                         `json:"tenant_id"`
	Cases    []kubernetesRustProjectionCase `json:"cases"`
}

type kubernetesRustProjectionCase struct {
	Family        string            `json:"family"`
	Attributes    map[string]string `json:"attributes"`
	Payload       json.RawMessage   `json:"payload"`
	ExpectedLinks [][3]string       `json:"expected_links"`
}

func TestKubernetesRustProjectionFixtureMatchesGoOracle(t *testing.T) {
	raw, err := os.ReadFile("../../crates/source-runtime-next/src/kubernetes/fixtures/projection_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture kubernetesRustProjectionFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode Kubernetes Rust projection fixture: %v", err)
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Family, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "kubernetes-rust-parity-" + testCase.Family,
				TenantId:   fixture.TenantID,
				SourceId:   "kubernetes",
				Kind:       "kubernetes." + testCase.Family,
				SchemaRef:  "kubernetes/" + testCase.Family + "/v1",
				Attributes: testCase.Attributes,
				Payload:    testCase.Payload,
				OccurredAt: timestamppb.New(time.Unix(0, 0).UTC()),
			})
			if err != nil {
				t.Fatalf("project Go oracle event: %v", err)
			}
			for _, link := range testCase.ExpectedLinks {
				assertProjectedLink(t, state, link[0], link[1], link[2])
			}
		})
	}
}
