package main

import (
	"os"
	"testing"
)

func TestMainVersionCommand(t *testing.T) {
	args := os.Args
	t.Cleanup(func() {
		os.Args = args
	})

	os.Args = []string{"cerebro", "version"}
	main()
}
