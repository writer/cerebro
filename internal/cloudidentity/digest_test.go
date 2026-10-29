package cloudidentity

import "testing"

func TestDigestJSONDiffersForDifferentValues(t *testing.T) {
	a := Grant{ID: "a", Effect: "Allow"}
	b := Grant{ID: "b", Effect: "Allow"}
	da, err := digestJSON(a)
	if err != nil {
		t.Fatalf("digestJSON(a) error = %v", err)
	}
	db, err := digestJSON(b)
	if err != nil {
		t.Fatalf("digestJSON(b) error = %v", err)
	}
	if da == db {
		t.Fatal("expected different digests for different values")
	}
}

func TestDigestJSONStableAcrossMapKeyOrder(t *testing.T) {
	m1 := map[string]int{"a": 1, "b": 2, "c": 3}
	m2 := map[string]int{"c": 3, "b": 2, "a": 1}
	d1, err := digestJSON(m1)
	if err != nil {
		t.Fatalf("digestJSON(m1) error = %v", err)
	}
	d2, err := digestJSON(m2)
	if err != nil {
		t.Fatalf("digestJSON(m2) error = %v", err)
	}
	if d1 != d2 {
		t.Fatal("expected identical digests regardless of map construction order")
	}
}

// TestDigestJSONReturnsErrorForNonJSONValue pins the fallible contract: a
// value encoding/json cannot marshal (here, a channel) is a programming
// error, never content evidence, and must come back as an explicit error
// rather than a panic or a fabricated digest.
func TestDigestJSONReturnsErrorForNonJSONValue(t *testing.T) {
	d, err := digestJSON(make(chan int))
	if err == nil {
		t.Fatal("expected an error for a non-JSON-marshalable value, got nil")
	}
	if d != "" {
		t.Fatalf("expected an empty digest alongside the error, got %q", d)
	}
}

func TestDigestBytesMatchesHistoricalJSONEncoding(t *testing.T) {
	const want = "sha256:42898f37607b0fe287b91cba8a2aa51a9925e3ea193a7aea8c6cc26053128fb6"
	if got := DigestBytes([]byte("hello world")); got != want {
		t.Fatalf("DigestBytes = %q, want historical base64-JSON digest %q", got, want)
	}
}

func TestDigestStringMatchesHistoricalJSONEncoding(t *testing.T) {
	const want = "sha256:9ddefe4435b21d901439e546d54a14a175a3493b9fd8fbf38d9ea6d3cbf70826"
	if got := DigestString("hello world"); got != want {
		t.Fatalf("DigestString = %q, want historical quoted-JSON digest %q", got, want)
	}
}

// TestDigestJSONReturnsErrorForInvalidPayload pins DigestJSON's fallible
// contract: malformed JSON bytes handed in as a json.RawMessage must come
// back as an explicit error, never a fabricated digest computed over
// invalid/garbage input.
func TestDigestJSONReturnsErrorForInvalidPayload(t *testing.T) {
	d, err := DigestJSON([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected an error for a malformed JSON payload, got nil")
	}
	if d != "" {
		t.Fatalf("expected an empty digest alongside the error, got %q", d)
	}
}

func TestDigestJSONMatchesHistoricalJSONEncoding(t *testing.T) {
	const want = "sha256:f16ebb765547a3d014857bef31dbb80ff8b201b5aa2cdcc6a6616630f7fbf3fd"
	got, err := DigestJSON([]byte(`{"b":2,"a":"\u003ctag\u003e"}`))
	if err != nil {
		t.Fatalf("DigestJSON() error = %v", err)
	}
	if got != want {
		t.Fatalf("DigestJSON = %q, want historical serialized-JSON digest %q", got, want)
	}
}

func TestRepositoryDigestDeterministic(t *testing.T) {
	files := []SourceFile{{Path: "b.txt", Content: []byte("b")}, {Path: "a.txt", Content: []byte("a")}}
	d1, err := RepositoryDigest(files)
	if err != nil {
		t.Fatalf("RepositoryDigest() error = %v", err)
	}
	reversed := []SourceFile{{Path: "a.txt", Content: []byte("a")}, {Path: "b.txt", Content: []byte("b")}}
	d2, err := RepositoryDigest(reversed)
	if err != nil {
		t.Fatalf("RepositoryDigest() error = %v", err)
	}
	if d1 != d2 {
		t.Fatal("expected identical RepositoryDigest regardless of file-slice order")
	}
}
