package a

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // want `embedded or in-memory database usage is forbidden`
)

func Bad() {
	_, _ = sql.Open("sqlite", "file:legacy.db?mode=memory&cache=shared") // want `embedded or in-memory database usage is forbidden` `embedded or in-memory database usage is forbidden`
}

func AlsoBad() {
	_, _ = sql.Open("postgres", ":memory:") // want `embedded or in-memory database usage is forbidden`
}

const sqliteDriver = "sqlite"
const memoryDSN = "file:legacy.db?mode=memory&cache=shared"

func ConstantBad() {
	_, _ = sql.Open(sqliteDriver, "file:legacy.db") // want `embedded or in-memory database usage is forbidden`
	_, _ = sql.Open("postgres", memoryDSN)          // want `embedded or in-memory database usage is forbidden`
}

func Good() {
	_, _ = sql.Open("postgres", "postgres://db")
	fmt.Println(":memory:")
}

type opener struct{}

func (opener) Open(driver string) {}

var sqliteConnector opener

func AlsoGood() {
	opener{}.Open("sqlite")
	sqliteConnector.Open("sqlite")
}
