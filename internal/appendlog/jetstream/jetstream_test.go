package jetstream

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	natsjetstream "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
)

type fakePublisher struct {
	accountErr error
	publishErr error
	published  *nats.Msg
}

func (f *fakePublisher) AccountInfo(context.Context) (*natsjetstream.AccountInfo, error) {
	return &natsjetstream.AccountInfo{}, f.accountErr
}

func (f *fakePublisher) PublishMsg(_ context.Context, msg *nats.Msg, _ ...natsjetstream.PublishOpt) (*natsjetstream.PubAck, error) {
	f.published = msg
	return &natsjetstream.PubAck{}, f.publishErr
}

func TestAppendPublishesEnvelope(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}

	event := &cerebrov1.EventEnvelope{
		Id:       "evt-1",
		TenantId: "tenant-1",
		SourceId: "source-1",
		Kind:     "entity.upsert",
	}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published == nil {
		t.Fatal("published message = nil")
	}
	if pub.published.Subject != "events.entity.upsert" {
		t.Fatalf("subject = %q, want %q", pub.published.Subject, "events.entity.upsert")
	}
	if got := pub.published.Header.Get(nats.MsgIdHdr); got != "evt-1" {
		t.Fatalf("msg id = %q, want %q", got, "evt-1")
	}
	var decoded cerebrov1.EventEnvelope
	if err := proto.Unmarshal(pub.published.Data, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if !proto.Equal(&decoded, event) {
		t.Fatalf("decoded envelope = %#v, want %#v", &decoded, event)
	}
}

func TestAppendNormalizesKindInPublishedEnvelope(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}

	event := &cerebrov1.EventEnvelope{
		Id:   "evt-1",
		Kind: " entity.upsert ",
	}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published.Subject != "events.entity.upsert" {
		t.Fatalf("subject = %q, want %q", pub.published.Subject, "events.entity.upsert")
	}
	var decoded cerebrov1.EventEnvelope
	if err := proto.Unmarshal(pub.published.Data, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if decoded.Kind != "entity.upsert" {
		t.Fatalf("decoded.Kind = %q, want %q", decoded.Kind, "entity.upsert")
	}
	if event.Kind != " entity.upsert " {
		t.Fatalf("event.Kind = %q, want original input unchanged", event.Kind)
	}
}

func TestAppendRejectsMissingKind(t *testing.T) {
	log := &Log{js: &fakePublisher{}, subjectPrefix: "events"}
	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Append() error = nil, want non-nil")
	}
}

func TestAppendRejectsInvalidPublishSubject(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events."}

	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{Kind: "entity.upsert"}); err == nil {
		t.Fatal("Append() error = nil, want non-nil")
	}
	if pub.published != nil {
		t.Fatal("published message != nil, want nil")
	}
}

func TestOpenRejectsInvalidSubjectPrefixBeforeConnect(t *testing.T) {
	_, err := Open(config.AppendLogConfig{
		JetStreamURL:           "nats://127.0.0.1:4222",
		JetStreamSubjectPrefix: "events.",
	})
	if err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
	var subjectErr invalidSubjectError
	if !errors.As(err, &subjectErr) {
		t.Fatalf("Open() error = %v, want invalid subject error", err)
	}
}

func TestPingSurfacesPublisherError(t *testing.T) {
	log := &Log{js: &fakePublisher{accountErr: errors.New("down")}, subjectPrefix: "events"}
	if err := log.Ping(context.Background()); err == nil {
		t.Fatal("Ping() error = nil, want non-nil")
	}
}
