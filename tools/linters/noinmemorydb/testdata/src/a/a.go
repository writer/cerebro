package a

import (
	"database/sql"

	_ "modernc.org/sqlite" // want `embedded or in-memory database usage is forbidden`
)

const (
	sqliteDriver      = "sqlite"
	sqlite3Driver     = "sqlite3"
	splitSQLiteDriver = "sql" + "ite"
	memoryDSN         = "file:legacy.db?mode=memory&cache=shared"
)

func Bad() {
	_, _ = sql.Open("sqlite", "file:legacy.db?mode=memory&cache=shared") // want `embedded or in-memory database usage is forbidden` `embedded or in-memory database usage is forbidden`
}

func ConstDriverBad() {
	_, _ = sql.Open(sqliteDriver, "postgres://db") // want `embedded or in-memory database usage is forbidden`
}

func ConstSQLite3DriverBad() {
	_, _ = sql.Open(sqlite3Driver, "postgres://db") // want `embedded or in-memory database usage is forbidden`
}

func ConstExprDriverBad() {
	_, _ = sql.Open(splitSQLiteDriver, "postgres://db") // want `embedded or in-memory database usage is forbidden`
}

func ConstMemoryDSNBad() {
	_, _ = sql.Open("postgres", memoryDSN) // want `embedded or in-memory database usage is forbidden`
}

func AlsoBad() {
	_, _ = sql.Open("postgres", ":memory:") // want `embedded or in-memory database usage is forbidden`
}

func Good() {
	_, _ = sql.Open("postgres", "postgres://db")
}

type opener struct{}

func (opener) Open(driver string) {}

func AlsoGood() {
	opener{}.Open("sqlite")
}

func NameOnlyReceiverGood() {
	sqliteConnection := opener{}
	sqliteConnection.Open("postgres")
}

func AliasBad() {
	open := sql.Open
	_, _ = open("sqlite", "postgres://db") // want `embedded or in-memory database usage is forbidden`
}

var pkgOpen = sql.Open

func PackageAliasBad() {
	_, _ = pkgOpen("sqlite3", "postgres://db") // want `embedded or in-memory database usage is forbidden`
}
