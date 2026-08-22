package sourceworker

import (
	"crypto/sha256"
	"encoding/hex"
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

func lowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func responseSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func safeUint64(value int) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%w: protocol integer is negative", ErrInvalidExecution)
	}
	return uint64(value), nil
}
