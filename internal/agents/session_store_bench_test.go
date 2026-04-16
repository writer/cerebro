package agents

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newBenchmarkSessionSQLiteDB(b *testing.B) *sql.DB {
	b.Helper()
	dbPath := filepath.Join(b.TempDir(), "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(8)
	b.Cleanup(func() { _ = db.Close() })
	return db
}

func BenchmarkPostgresSessionStoreEnsureSchemaReady(b *testing.B) {
	store := NewPostgresSessionStore(newBenchmarkSessionSQLiteDB(b))
	store.rewriteSQL = sessionStoreSQLiteRewrite
	if err := store.EnsureSchema(context.Background()); err != nil {
		b.Fatalf("seed EnsureSchema(): %v", err)
	}

	b.Run("serial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := store.EnsureSchema(context.Background()); err != nil {
				b.Fatalf("EnsureSchema(): %v", err)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if err := store.EnsureSchema(context.Background()); err != nil {
					b.Fatalf("EnsureSchema(): %v", err)
				}
			}
		})
	})
}
