package graphingest

import (
	"testing"

	"github.com/writer/cerebro/internal/graphstore"
)

func TestRunMessageIncludesCheckpointState(t *testing.T) {
	message := RunMessage(graphstore.IngestRun{
		ID: "graph-run-1", CheckpointID: "checkpoint-1", CheckpointCursor: "page-2", CheckpointComplete: false, CheckpointCompleteKnown: true,
	})
	if message.GetCheckpointId() != "checkpoint-1" || message.GetCheckpointCursor() != "page-2" || message.CheckpointComplete == nil || message.GetCheckpointComplete() {
		t.Fatalf("RunMessage() checkpoint = %#v, want persisted partial checkpoint", message)
	}
	message = RunMessage(graphstore.IngestRun{ID: "graph-run-2", CheckpointID: "checkpoint-2", CheckpointComplete: true, CheckpointCompleteKnown: true})
	if message.GetCheckpointCursor() != "" || message.CheckpointComplete == nil || !message.GetCheckpointComplete() {
		t.Fatalf("RunMessage() checkpoint = %#v, want complete terminal checkpoint", message)
	}
	message = RunMessage(graphstore.IngestRun{ID: "graph-run-legacy"})
	if message.CheckpointComplete != nil {
		t.Fatalf("RunMessage() checkpoint = %#v, want legacy terminal state absent", message)
	}
}
