package a

import (
	"errors"
	"fmt"
	"strings"
)

var errNotFound = errors.New("not found")

func good(err error) bool {
	return errors.Is(err, errNotFound)
}

func bad1(err error) bool {
	return strings.Contains(err.Error(), "not found") // want `matching on err.Error\(\) is forbidden`
}

func bad2(err error) bool {
	return strings.HasPrefix(err.Error(), "boom") // want `matching on err.Error\(\) is forbidden`
}

func bad3(err error) bool {
	return err.Error() == "not found" // want `comparing err.Error\(\) to a string is forbidden`
}

func bad4(err error) bool {
	return "oops" != err.Error() // want `comparing err.Error\(\) to a string is forbidden`
}

// Strings operations on a non-error string are fine.
func ok(s string) bool {
	return strings.Contains(s, "hello")
}

// Wrapping is fine.
func wrap(err error) error {
	return fmt.Errorf("wrapped: %w", err)
}
