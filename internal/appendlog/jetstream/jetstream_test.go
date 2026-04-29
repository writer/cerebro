package jetstream

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/nats-io/nats.go"
	natsjetstream "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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

type fakeReplayManager struct {
	streams     []*natsjetstream.StreamInfo
	msgs        map[string]map[uint64]*natsjetstream.RawStreamMsg
	err         error
	streamCalls int
}

func (f *fakeReplayManager) Streams(context.Context) ([]*natsjetstream.StreamInfo, error) {
	return f.streams, f.err
}

func (f *fakeReplayManager) Stream(_ context.Context, stream string) (replayStream, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.streamCalls++
	return &fakeReplayStream{msgs: f.msgs[stream]}, nil
}

type fakeReplayStream struct {
	msgs map[uint64]*natsjetstream.RawStreamMsg
}

func (f *fakeReplayStream) GetMsg(_ context.Context, seq uint64, _ ...natsjetstream.GetMsgOpt) (*natsjetstream.RawStreamMsg, error) {
	raw := f.msgs[seq]
	if raw == nil {
		return nil, natsjetstream.ErrMsgNotFound
	}
	return raw, nil
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

func TestAppendRejectsMissingKind(t *testing.T) {
	log := &Log{js: &fakePublisher{}, subjectPrefix: "events"}
	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Append() error = nil, want non-nil")
	}
}

func TestPingSurfacesPublisherError(t *testing.T) {
	log := &Log{js: &fakePublisher{accountErr: errors.New("down")}, subjectPrefix: "events"}
	if err := log.Ping(context.Background()); err == nil {
		t.Fatal("Ping() error = nil, want non-nil")
	}
}

func TestReplayFiltersEventsByRuntime(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
				2: rawReplayMsg(t, "events.github.pull_request", replayEvent("evt-2", "github.pull_request", "other-runtime")),
				3: rawReplayMsg(t, "events.github.pull_request", replayEvent("evt-3", "github.pull_request", "writer-github")),
				4: rawReplayMsg(t, "events.ignored", replayEvent("evt-4", "ignored", "")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{
		RuntimeID: "writer-github",
		Limit:     2,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetId() != "evt-1" || events[1].GetId() != "evt-3" {
		t.Fatalf("replayed ids = [%q, %q], want [evt-1, evt-3]", events[0].GetId(), events[1].GetId())
	}
	if replay.streamCalls != 1 {
		t.Fatalf("streamCalls = %d, want 1", replay.streamCalls)
	}
}

func TestReplayAppliesDefaultLimit(t *testing.T) {
	msgs := make(map[uint64]*natsjetstream.RawStreamMsg)
	for seq := uint64(1); seq <= defaultReplayLimit+5; seq++ {
		msgs[seq] = rawReplayMsg(t, "events.github.audit", replayEvent("evt-"+strconv.FormatUint(seq, 10), "github.audit", "writer-github"))
	}
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: defaultReplayLimit + 5},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{"CEREBRO_EVENTS": msgs},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != defaultReplayLimit {
		t.Fatalf("len(events) = %d, want %d", len(events), defaultReplayLimit)
	}
}

func TestReplayRejectsMissingRuntimeID(t *testing.T) {
	log := &Log{replay: &fakeReplayManager{}, subjectPrefix: "events"}
	if _, err := log.Replay(context.Background(), ports.ReplayRequest{}); err == nil {
		t.Fatal("Replay() error = nil, want non-nil")
	}
}

func replayEvent(id string, kind string, runtimeID string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       id,
		Kind:     kind,
		SourceId: "github",
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: runtimeID,
		},
	}
}

func rawReplayMsg(t *testing.T, subject string, event *cerebrov1.EventEnvelope) *natsjetstream.RawStreamMsg {
	t.Helper()
	payload, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	return &natsjetstream.RawStreamMsg{Subject: subject, Data: payload}
}
