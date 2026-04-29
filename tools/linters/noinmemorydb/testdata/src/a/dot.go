package a

import . "database/sql"

func DotImportBad() {
	_, _ = Open("sqlite", "postgres://db") // want `embedded or in-memory database usage is forbidden`
}
