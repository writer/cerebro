package sourceworker

import (
	"fmt"
	"math"
	"strings"
)

func safeUint32(value int) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, fmt.Errorf("%w: protocol integer is out of range", ErrInvalidExecution)
	}
	return uint32(value), nil
}

func safeIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\t")
}
