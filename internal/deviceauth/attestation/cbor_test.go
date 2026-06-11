package attestation

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecodeCBORAcceptsAppleShapedSubset(t *testing.T) {
	raw, err := encodeCBORMap([][2]any{
		{"fmt", "apple-appattest"},
		{"authData", []byte{0x01, 0x02, 0x03}},
		{"attStmt", [][2]any{
			{"x5c", [][]byte{{0x04}, {0x05}}},
			{"receipt", []byte{0x06}},
		}},
	})
	if err != nil {
		t.Fatalf("encodeCBORMap() error = %v", err)
	}

	got, rest, err := decodeCBOR(raw)
	if err != nil {
		t.Fatalf("decodeCBOR() error = %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("decodeCBOR() rest = %x, want empty", rest)
	}
	if got.major != 5 {
		t.Fatalf("root major = %d, want 5", got.major)
	}
	fmtVal, ok := got.lookup("fmt")
	if !ok || fmtVal.major != 3 || fmtVal.text != "apple-appattest" {
		t.Fatalf("fmt = (%+v, %v), want text apple-appattest", fmtVal, ok)
	}
	authData, ok := got.lookup("authData")
	if !ok || authData.major != 2 || !bytes.Equal(authData.bytes, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("authData = (%+v, %v), want byte string", authData, ok)
	}
	attStmt, ok := got.lookup("attStmt")
	if !ok || attStmt.major != 5 {
		t.Fatalf("attStmt = (%+v, %v), want map", attStmt, ok)
	}
	x5c, ok := attStmt.lookup("x5c")
	if !ok || x5c.major != 4 || len(x5c.array) != 2 {
		t.Fatalf("x5c = (%+v, %v), want two-element array", x5c, ok)
	}
}

func TestDecodeCBORPreservesTrailingBytes(t *testing.T) {
	raw, err := encodeCBORMap([][2]any{{"fmt", "apple-appattest"}})
	if err != nil {
		t.Fatalf("encodeCBORMap() error = %v", err)
	}
	raw = append(raw, 0xff, 0x01)

	_, rest, err := decodeCBOR(raw)
	if err != nil {
		t.Fatalf("decodeCBOR() error = %v", err)
	}
	if !bytes.Equal(rest, []byte{0xff, 0x01}) {
		t.Fatalf("decodeCBOR() rest = %x, want ff01", rest)
	}
}

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

func TestDecodeCBORRejectsUnsupportedItems(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "indefinite byte string", raw: []byte{0x5f, 0x40, 0xff}},
		{name: "indefinite array", raw: []byte{0x9f, 0xff}},
		{name: "tag", raw: []byte{0xc0, 0x60}},
		{name: "float", raw: []byte{0xf9, 0x00, 0x00}},
		{name: "simple value", raw: []byte{0xf5}},
		{name: "non string map key", raw: []byte{0xa1, 0x01, 0x02}},
		{name: "duplicate map key", raw: []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeCBOR(tc.raw); !errors.Is(err, errCBORUnsupported) {
				t.Fatalf("decodeCBOR() error = %v, want errCBORUnsupported", err)
			}
		})
	}
}
