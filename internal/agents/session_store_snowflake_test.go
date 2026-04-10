package agents

import (
	"database/sql"
	"testing"
	"time"
)

type stubSnowflakeSessionRow struct {
	createdAt time.Time
	updatedAt time.Time
}

func (r stubSnowflakeSessionRow) Scan(dest ...any) error {
	*(dest[0].(*string)) = "session-1"
	*(dest[1].(*string)) = "agent-1"
	*(dest[2].(*sql.NullString)) = sql.NullString{}
	*(dest[3].(*string)) = "active"
	*(dest[4].(*any)) = []byte(`[{"role":"user","content":"hello"}]`)
	*(dest[5].(*any)) = []byte(`{"metadata":{"ticket":"INC-123"}}`)
	*(dest[6].(*time.Time)) = r.createdAt
	*(dest[7].(*time.Time)) = r.updatedAt
	return nil
}

func TestScanSnowflakeSessionAllowsNullUserID(t *testing.T) {
	createdAt := time.Now()
	updatedAt := createdAt.Add(5 * time.Minute)

	session, err := scanSnowflakeSession(stubSnowflakeSessionRow{
		createdAt: createdAt,
		updatedAt: updatedAt,
	})
	if err != nil {
		t.Fatalf("scanSnowflakeSession() error = %v", err)
	}
	if session.UserID != "" {
		t.Fatalf("UserID = %q, want empty string", session.UserID)
	}
	if len(session.Messages) != 1 || session.Messages[0].Content != "hello" {
		t.Fatalf("Messages = %#v, want parsed content", session.Messages)
	}
	if got := session.Context.Metadata["ticket"]; got != "INC-123" {
		t.Fatalf("Context[ticket] = %#v, want INC-123", got)
	}
	if !session.CreatedAt.Equal(createdAt.UTC()) {
		t.Fatalf("CreatedAt = %v, want %v", session.CreatedAt, createdAt.UTC())
	}
	if !session.UpdatedAt.Equal(updatedAt.UTC()) {
		t.Fatalf("UpdatedAt = %v, want %v", session.UpdatedAt, updatedAt.UTC())
	}
}
