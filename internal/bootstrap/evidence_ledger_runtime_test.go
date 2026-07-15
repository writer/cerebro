package bootstrap

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestEvidenceLedgerServiceComposition(t *testing.T) {
	t.Parallel()
	state := &evidenceLedgerStateStub{}
	app, err := NewWithError(config.Config{}, Dependencies{StateStore: state, AppendLog: bootstrapAppendOnlyLog{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if app.services.evidence == nil {
		t.Fatal("evidence ledger service was not composed")
	}

	app, err = NewWithError(config.Config{}, Dependencies{StateStore: nonEvidenceStateStub{}, AppendLog: bootstrapAppendOnlyLog{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if app.services.evidence != nil {
		t.Fatal("evidence ledger service composed without a ledger-capable state store")
	}
}

type evidenceLedgerStateStub struct {
	ports.EvidenceLedgerStore
}

func (*evidenceLedgerStateStub) Ping(context.Context) error { return nil }

type nonEvidenceStateStub struct{}

func (nonEvidenceStateStub) Ping(context.Context) error { return nil }
