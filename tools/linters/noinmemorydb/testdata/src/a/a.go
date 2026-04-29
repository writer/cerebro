package a

import (
	"database/sql"

	_ "modernc.org/sqlite" // want `embedded or in-memory database usage is forbidden`
)

func Bad() {
	_, _ = sql.Open("sqlite", "file:legacy.db?mode=memory&cache=shared") // want `embedded or in-memory database usage is forbidden` `embedded or in-memory database usage is forbidden`
}

func AlsoBad() {
	_, _ = sql.Open("postgres", ":memory:") // want `embedded or in-memory database usage is forbidden`
}

func Good() {
	_, _ = sql.Open("postgres", "postgres://db")
}
