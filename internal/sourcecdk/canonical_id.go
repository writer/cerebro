package sourcecdk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// CanonicalRecordID hashes a length-prefixed canonical tuple with SHA-256:
// each part is preceded by its own 8-byte big-endian length, so no
// concatenation of distinct part values can ever produce the same byte
// stream (and therefore the same digest) as a different tuple. This keeps,
// for example, two principal IDs that only differ in separator placement
// ("role/a-b" vs "role/a/b") from aliasing to the same record ID under a
// naive join-based ID scheme.
func CanonicalRecordID(parts ...string) string {
	h := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}
