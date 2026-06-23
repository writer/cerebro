package eventregistry

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestAvroWriterBoolean(t *testing.T) {
	w := newAvroWriter()
	w.boolean(true)
	w.boolean(false)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 2 || got[0] != 1 || got[1] != 0 {
		t.Fatalf("boolean encoding = %v, want [1, 0]", got)
	}
}

func TestAvroWriterLongZigZag(t *testing.T) {
	tests := []struct {
		name  string
		value int64
		want  []byte
	}{
		{"zero", 0, []byte{0}},
		{"one", 1, []byte{2}},
		{"negative_one", -1, []byte{1}},
		{"large", 64, []byte{0x80, 0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newAvroWriter()
			w.long(tt.value)
			got, err := w.bytes()
			if err != nil {
				t.Fatalf("bytes() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("long(%d) len = %d, want %d", tt.value, len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("long(%d) byte[%d] = 0x%02x, want 0x%02x", tt.value, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAvroWriterDouble(t *testing.T) {
	w := newAvroWriter()
	w.double(1.5)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("double encoding len = %d, want 8", len(got))
	}
	bits := binary.LittleEndian.Uint64(got)
	if math.Float64frombits(bits) != 1.5 {
		t.Fatalf("double decoded = %f, want 1.5", math.Float64frombits(bits))
	}
}

func TestAvroWriterString(t *testing.T) {
	w := newAvroWriter()
	w.string("hello")
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Length prefix is zigzag(5) = 10, then "hello"
	if got[0] != 10 {
		t.Fatalf("string length byte = %d, want 10", got[0])
	}
	if string(got[1:]) != "hello" {
		t.Fatalf("string payload = %q, want %q", string(got[1:]), "hello")
	}
}

func TestAvroWriterEmptyString(t *testing.T) {
	w := newAvroWriter()
	w.string("")
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("empty string encoding = %v, want [0]", got)
	}
}

func TestAvroWriterNullableStringNil(t *testing.T) {
	w := newAvroWriter()
	w.nullableString(nil)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Null branch index = zigzag(0) = 0
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("nullable nil encoding = %v, want [0]", got)
	}
}

func TestAvroWriterNullableStringPresent(t *testing.T) {
	w := newAvroWriter()
	s := "hi"
	w.nullableString(&s)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Union index 1 = zigzag(1) = 2, then string "hi" with len zigzag(2) = 4
	if got[0] != 2 {
		t.Fatalf("nullable present union index = %d, want 2", got[0])
	}
	if got[1] != 4 {
		t.Fatalf("nullable present string length = %d, want 4", got[1])
	}
	if string(got[2:]) != "hi" {
		t.Fatalf("nullable present payload = %q, want %q", string(got[2:]), "hi")
	}
}

func TestAvroWriterStringArrayEmpty(t *testing.T) {
	w := newAvroWriter()
	w.stringArray(nil)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("empty array encoding = %v, want [0]", got)
	}
}

func TestAvroWriterStringArrayNonEmpty(t *testing.T) {
	w := newAvroWriter()
	w.stringArray([]string{"a", "b"})
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Block count zigzag(2) = 4, then "a" (len=2, payload), "b" (len=2, payload), then block end 0
	if got[0] != 4 {
		t.Fatalf("array block count = %d, want 4 (zigzag of 2)", got[0])
	}
	lastByte := got[len(got)-1]
	if lastByte != 0 {
		t.Fatalf("array terminator = %d, want 0", lastByte)
	}
}

func TestAvroWriterStringMapSortedKeys(t *testing.T) {
	w := newAvroWriter()
	w.stringMap(map[string]string{"z": "1", "a": "2"})
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Block count zigzag(2) = 4, first key should be "a" (sorted)
	if got[0] != 4 {
		t.Fatalf("map block count = %d, want 4", got[0])
	}
	// After block count: key length zigzag(1)=2, then "a"
	if got[1] != 2 || got[2] != 'a' {
		t.Fatalf("first map key = %v, want 'a'", got[1:3])
	}
}

func TestAvroWriterStringMapEmpty(t *testing.T) {
	w := newAvroWriter()
	w.stringMap(nil)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("empty map encoding = %v, want [0]", got)
	}
}

func TestAvroWriterIntegerOutOfRange(t *testing.T) {
	w := newAvroWriter()
	w.integer(math.MaxInt32 + 1)
	_, err := w.bytes()
	if err == nil {
		t.Fatal("integer out of range should produce error")
	}
}

func TestAvroWriterMetadataMapTypes(t *testing.T) {
	w := newAvroWriter()
	w.metadataMap(map[string]any{
		"str":  "hello",
		"num":  int64(42),
		"flag": true,
	})
	_, err := w.bytes()
	if err != nil {
		t.Fatalf("metadataMap() error = %v", err)
	}
}

func TestAvroWriterMetadataUnsupportedType(t *testing.T) {
	w := newAvroWriter()
	w.metadataValue(struct{}{})
	_, err := w.bytes()
	if err == nil {
		t.Fatal("unsupported metadata type should produce error")
	}
}

func TestAvroWriterNullableDoubleNil(t *testing.T) {
	w := newAvroWriter()
	w.nullableDouble(nil)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("nullable double nil = %v, want [0]", got)
	}
}

func TestAvroWriterNullableDoublePresent(t *testing.T) {
	w := newAvroWriter()
	v := 3.14
	w.nullableDouble(&v)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Union index 1 = zigzag(1) = 2, then 8 bytes of double
	if got[0] != 2 {
		t.Fatalf("nullable double union index = %d, want 2", got[0])
	}
	if len(got) != 9 {
		t.Fatalf("nullable double total len = %d, want 9", len(got))
	}
}

func TestAvroWriterFindingControlRefArrayEmpty(t *testing.T) {
	w := newAvroWriter()
	w.findingControlRefArray(nil)
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("empty control ref array = %v, want [0]", got)
	}
}

func TestAvroWriterFindingControlRefArrayNonEmpty(t *testing.T) {
	w := newAvroWriter()
	w.findingControlRefArray([]FindingControlRefSnapshot{
		{FrameworkName: "SOC2", ControlID: "CC6.1"},
	})
	got, err := w.bytes()
	if err != nil {
		t.Fatalf("bytes() error = %v", err)
	}
	// Block count zigzag(1) = 2, then two strings, then terminator 0
	if got[0] != 2 {
		t.Fatalf("control ref block count = %d, want 2", got[0])
	}
	if got[len(got)-1] != 0 {
		t.Fatalf("control ref terminator = %d, want 0", got[len(got)-1])
	}
}
