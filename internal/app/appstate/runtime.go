package appstate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
)

type Runtime struct {
	db *sql.DB
}

type EnsureSchemaFunc func(context.Context, *sql.DB) error

func NewRuntime() *Runtime {
	return &Runtime{}
}

func DatabaseURL(jobDatabaseURL, warehouseBackend, warehousePostgresDSN string) string {
	switch strings.ToLower(strings.TrimSpace(warehouseBackend)) {
	case "postgres", "snowflake":
		return strings.TrimSpace(warehousePostgresDSN)
	default:
		return ""
	}
}

func (r *Runtime) DB() *sql.DB {
	if r == nil {
		return nil
	}
	return r.db
}

func (r *Runtime) SetDB(db *sql.DB) {
	if r == nil {
		return
	}
	r.db = db
}

func (r *Runtime) Init(ctx context.Context, dsn string, ensureFns ...EnsureSchemaFunc) error {
	if r == nil {
		return fmt.Errorf("appstate runtime is nil")
	}
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open app-state database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping app-state database: %w", err)
	}

	for _, ensureFn := range ensureFns {
		if ensureFn == nil {
			continue
		}
		if err := ensureFn(ctx, db); err != nil {
			_ = db.Close()
			return err
		}
	}

	r.db = db
	return nil
}

func (r *Runtime) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	err := r.db.Close()
	r.db = nil
	return err
}
