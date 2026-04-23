package a

import (
	"os"
	"testing"
)

func TestAllowed(t *testing.T) {
	_ = os.Getenv("HOME")
}
