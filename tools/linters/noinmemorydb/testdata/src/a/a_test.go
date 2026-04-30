package a

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestAllowed(t *testing.T) {
	_, _ = sql.Open("sqlite", ":memory:")
}
