package eventadmission

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type closeTrackingAdmitter struct {
	closeCount int
	closeErr   error
}

func (*closeTrackingAdmitter) Admit(context.Context, []*cerebrov1.EventEnvelope, []sourcecdk.EventContract) (Response, error) {
	return Response{}, nil
}

func (a *closeTrackingAdmitter) Close() error {
	a.closeCount++
	return a.closeErr
}

func TestCloseOnErrorClosesAndJoinsFailure(t *testing.T) {
	constructionErr := errors.New("later bootstrap failure")
	closeErr := errors.New("close failure")
	admitter := &closeTrackingAdmitter{closeErr: closeErr}

	CloseOnError(admitter, &constructionErr)

	if admitter.closeCount != 1 {
		t.Fatalf("close count = %d, want 1", admitter.closeCount)
	}
	if !errors.Is(constructionErr, closeErr) {
		t.Fatalf("construction error = %v, want joined close failure", constructionErr)
	}
}

func TestCloseOnErrorKeepsSuccessfulConstructionOpen(t *testing.T) {
	admitter := &closeTrackingAdmitter{}
	var constructionErr error

	CloseOnError(admitter, &constructionErr)

	if admitter.closeCount != 0 {
		t.Fatalf("close count = %d, want 0", admitter.closeCount)
	}
}
