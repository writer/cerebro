package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestUpsertProjectedEntityRejectsNilEntity(t *testing.T) {
	store := &Store{}
	if err := store.UpsertProjectedEntity(context.Background(), nil); err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedEntityRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedEntity(context.Background(), &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	})
	if err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedLinkRejectsMissingRelation(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLink(context.Background(), &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		ToURN:    "urn:cerebro:writer:github_repo:writer/cerebro",
	})
	if err == nil {
		t.Fatal("UpsertProjectedLink() error = nil, want non-nil")
	}
}

func TestUpsertProjectedRecordsEnsureProjectionTablesOnce(t *testing.T) {
	recorder := &projectionSQLRecorder{}
	store := newProjectionTestStore(t, recorder)

	entity := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	}
	if err := store.UpsertProjectedEntity(context.Background(), entity); err != nil {
		t.Fatalf("UpsertProjectedEntity() error = %v", err)
	}
	link := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		FromURN:  "urn:cerebro:writer:github_user:alice",
		Relation: "member_of",
		ToURN:    "urn:cerebro:writer:github_org:writer",
	}
	if err := store.UpsertProjectedLink(context.Background(), link); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}

	ddlExecs, upserts := recorder.counts()
	if ddlExecs != len(ensureProjectionStatements) {
		t.Fatalf("projection DDL executions = %d, want %d", ddlExecs, len(ensureProjectionStatements))
	}
	if upserts != 2 {
		t.Fatalf("upsert executions = %d, want 2", upserts)
	}
}

func TestUpsertProjectedEntityMergesAttributesOnConflict(t *testing.T) {
	recorder := &projectionSQLRecorder{}
	store := newProjectionTestStore(t, recorder)

	entity := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_repo:writer/cerebro",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.repo",
		Attributes: map[string]string{"resource_type": "repository"},
	}
	if err := store.UpsertProjectedEntity(context.Background(), entity); err != nil {
		t.Fatalf("UpsertProjectedEntity() error = %v", err)
	}

	query := recorder.lastUpsert()
	if !strings.Contains(query, "attributes_json = entities.attributes_json || EXCLUDED.attributes_json") {
		t.Fatalf("entity upsert query does not merge attributes_json: %s", query)
	}
}

func TestUpsertProjectedLinkMergesAttributesOnConflict(t *testing.T) {
	recorder := &projectionSQLRecorder{}
	store := newProjectionTestStore(t, recorder)

	link := &ports.ProjectedLink{
		TenantID:   "writer",
		SourceID:   "github",
		FromURN:    "urn:cerebro:writer:github_user:alice",
		Relation:   "member_of",
		ToURN:      "urn:cerebro:writer:github_org:writer",
		Attributes: map[string]string{"role": "maintainer"},
	}
	if err := store.UpsertProjectedLink(context.Background(), link); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}

	query := recorder.lastUpsert()
	if !strings.Contains(query, "attributes_json = entity_links.attributes_json || EXCLUDED.attributes_json") {
		t.Fatalf("link upsert query does not merge attributes_json: %s", query)
	}
}

func TestUpsertProjectedRetriesEnsureAfterFailure(t *testing.T) {
	recorder := &projectionSQLRecorder{failNextDDL: true}
	store := newProjectionTestStore(t, recorder)
	entity := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github.user",
	}

	if err := store.UpsertProjectedEntity(context.Background(), entity); err == nil {
		t.Fatal("UpsertProjectedEntity(first) error = nil, want non-nil")
	}
	if err := store.UpsertProjectedEntity(context.Background(), entity); err != nil {
		t.Fatalf("UpsertProjectedEntity(second) error = %v", err)
	}

	ddlExecs, upserts := recorder.counts()
	wantDDL := len(ensureProjectionStatements) + 1
	if ddlExecs != wantDDL {
		t.Fatalf("projection DDL executions = %d, want %d", ddlExecs, wantDDL)
	}
	if upserts != 1 {
		t.Fatalf("upsert executions = %d, want 1", upserts)
	}
}

var projectionSQLDriverSeq int64

func newProjectionTestStore(t *testing.T, recorder *projectionSQLRecorder) *Store {
	t.Helper()
	driverName := fmt.Sprintf("projection-test-%d", atomic.AddInt64(&projectionSQLDriverSeq, 1))
	sql.Register(driverName, projectionSQLDriver{recorder: recorder})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatalf("open projection test db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close projection test db: %v", err)
		}
	})
	return &Store{db: db}
}

type projectionSQLDriver struct {
	recorder *projectionSQLRecorder
}

func (d projectionSQLDriver) Open(string) (driver.Conn, error) {
	return projectionSQLConn(d), nil
}

type projectionSQLConn struct {
	recorder *projectionSQLRecorder
}

func (c projectionSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (c projectionSQLConn) Close() error {
	return nil
}

func (c projectionSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (c projectionSQLConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	return c.recorder.exec(query)
}

type projectionSQLRecorder struct {
	mu          sync.Mutex
	ddlExecs    int
	upserts     int
	upsertSQL   []string
	failNextDDL bool
}

func (r *projectionSQLRecorder) exec(query string) (driver.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.HasPrefix(strings.TrimSpace(query), "CREATE ") {
		r.ddlExecs++
		if r.failNextDDL {
			r.failNextDDL = false
			return nil, errors.New("ddl failed")
		}
		return driver.RowsAffected(1), nil
	}
	r.upserts++
	r.upsertSQL = append(r.upsertSQL, query)
	return driver.RowsAffected(1), nil
}

func (r *projectionSQLRecorder) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ddlExecs, r.upserts
}

func (r *projectionSQLRecorder) lastUpsert() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.upsertSQL) == 0 {
		return ""
	}
	return r.upsertSQL[len(r.upsertSQL)-1]
}
