package main

import (
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/cli"
)

func main() {
	cli.Execute()
}
