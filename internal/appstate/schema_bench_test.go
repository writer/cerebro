package appstate

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newBenchmarkAppStateSQLiteDB(b *testing.B, name string) *sql.DB {
	b.Helper()
	dbPath := filepath.Join(b.TempDir(), name)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(8)
	b.Cleanup(func() { _ = db.Close() })
	return db
}

func benchmarkEnsureSchemaReady(b *testing.B, ensure func(context.Context) error) {
	b.Helper()
	if err := ensure(context.Background()); err != nil {
		b.Fatalf("seed EnsureSchema(): %v", err)
	}

	b.Run("serial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := ensure(context.Background()); err != nil {
				b.Fatalf("EnsureSchema(): %v", err)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if err := ensure(context.Background()); err != nil {
					b.Fatalf("EnsureSchema(): %v", err)
				}
			}
		})
	})
}

func BenchmarkAuditRepositoryEnsureSchemaReady(b *testing.B) {
	repo := NewAuditRepository(newBenchmarkAppStateSQLiteDB(b, "audit.db"))
	repo.rewriteSQL = appStateSQLiteRewrite
	benchmarkEnsureSchemaReady(b, repo.EnsureSchema)
}

func BenchmarkPolicyHistoryRepositoryEnsureSchemaReady(b *testing.B) {
	repo := NewPolicyHistoryRepository(newBenchmarkAppStateSQLiteDB(b, "policy_history.db"))
	repo.rewriteSQL = appStateSQLiteRewrite
	benchmarkEnsureSchemaReady(b, repo.EnsureSchema)
}

func BenchmarkRiskEngineStateRepositoryEnsureSchemaReady(b *testing.B) {
	repo := NewRiskEngineStateRepository(newBenchmarkAppStateSQLiteDB(b, "risk_engine_state.db"))
	repo.rewriteSQL = appStateSQLiteRewrite
	benchmarkEnsureSchemaReady(b, repo.EnsureSchema)
}
