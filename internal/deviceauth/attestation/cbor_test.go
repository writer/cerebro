package attestation

import (
	"errors"
	"testing"
)

func TestDecodeCBORRejectsHugeContainerLengths(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "array", raw: []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{name: "map", raw: []byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeCBOR(tc.raw); !errors.Is(err, errCBORUnsupported) {
				t.Fatalf("decodeCBOR() error = %v, want errCBORUnsupported", err)
			}
		})
	}
}
