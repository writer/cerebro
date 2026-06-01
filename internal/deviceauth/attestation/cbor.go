package attestation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Minimal deterministic-CBOR decoder, sized to what Apple App Attest
// attestation objects actually contain: top-level map, text-string keys,
// byte-string values, arrays of byte strings, and unsigned/negative
// integers. This avoids pulling fxamacker/cbor or another third-party
// library, per the repo's stdlib-only policy.
//
// We deliberately do NOT implement: tags, indefinite-length items,
// floats, big-int, half-precision floats, or non-string map keys. An
// attestation that uses any of these is rejected with errCBORUnsupported.

type cborValue struct {
	major byte
	value uint64
	bytes []byte
	text  string
	array []cborValue
	mapEl []cborMapEntry
}

type cborMapEntry struct {
	key string
	val cborValue
}

const maxCBORContainerElements = 1024

func (v cborValue) lookup(key string) (cborValue, bool) {
	for _, e := range v.mapEl {
		if e.key == key {
			return e.val, true
		}
	}
	return cborValue{}, false
}

func decodeCBOR(data []byte) (cborValue, []byte, error) {
	if len(data) == 0 {
		return cborValue{}, nil, errCBORUnsupported
	}
	first := data[0]
	major := first >> 5
	additional := first & 0x1f
	rest := data[1:]
	val, rest, err := readCount(major, additional, rest)
	if err != nil {
		return cborValue{}, nil, err
	}
	switch major {
	case 0: // unsigned int
		return cborValue{major: major, value: val}, rest, nil
	case 1: // negative int
		return cborValue{major: major, value: val}, rest, nil
	case 2: // byte string
		if uint64(len(rest)) < val {
			return cborValue{}, nil, errCBORUnsupported
		}
		bs := append([]byte(nil), rest[:val]...)
		return cborValue{major: major, bytes: bs, value: val}, rest[val:], nil
	case 3: // text string
		if uint64(len(rest)) < val {
			return cborValue{}, nil, errCBORUnsupported
		}
		text := string(rest[:val])
		return cborValue{major: major, text: text, value: val}, rest[val:], nil
	case 4: // array
		if val > maxCBORContainerElements {
			return cborValue{}, nil, errCBORUnsupported
		}
		arr := make([]cborValue, 0, val)
		for i := uint64(0); i < val; i++ {
			el, r2, err := decodeCBOR(rest)
			if err != nil {
				return cborValue{}, nil, err
			}
			arr = append(arr, el)
			rest = r2
		}
		return cborValue{major: major, array: arr, value: val}, rest, nil
	case 5: // map
		if val > maxCBORContainerElements {
			return cborValue{}, nil, errCBORUnsupported
		}
		entries := make([]cborMapEntry, 0, val)
		for i := uint64(0); i < val; i++ {
			k, r2, err := decodeCBOR(rest)
			if err != nil {
				return cborValue{}, nil, err
			}
			rest = r2
			if k.major != 3 {
				return cborValue{}, nil, errCBORUnsupported
			}
			vEl, r3, err := decodeCBOR(rest)
			if err != nil {
				return cborValue{}, nil, err
			}
			rest = r3
			entries = append(entries, cborMapEntry{key: k.text, val: vEl})
		}
		return cborValue{major: major, mapEl: entries, value: val}, rest, nil
	default:
		return cborValue{}, nil, errCBORUnsupported
	}
}

func readCount(major, additional byte, rest []byte) (uint64, []byte, error) {
	switch {
	case additional < 24:
		return uint64(additional), rest, nil
	case additional == 24:
		if len(rest) < 1 {
			return 0, nil, errCBORUnsupported
		}
		return uint64(rest[0]), rest[1:], nil
	case additional == 25:
		if len(rest) < 2 {
			return 0, nil, errCBORUnsupported
		}
		return uint64(binary.BigEndian.Uint16(rest[:2])), rest[2:], nil
	case additional == 26:
		if len(rest) < 4 {
			return 0, nil, errCBORUnsupported
		}
		return uint64(binary.BigEndian.Uint32(rest[:4])), rest[4:], nil
	case additional == 27:
		if len(rest) < 8 {
			return 0, nil, errCBORUnsupported
		}
		return binary.BigEndian.Uint64(rest[:8]), rest[8:], nil
	default:
		return 0, nil, errCBORUnsupported
	}
}

// encodeCBORDeterministic produces deterministic CBOR (RFC 8949 §4.2.1)
// for a small subset of values: maps with string keys, strings, byte
// strings, integers, and arrays of byte strings. This is the inverse of
// decodeCBOR and is used by tests to build synthetic Apple-shaped
// attestation objects without pulling in a third-party encoder.
func encodeCBORMap(entries [][2]any) ([]byte, error) {
	out := make([]byte, 0, 64)
	count := uint64(len(entries))
	out = append(out, encodeHead(5, count)...)
	for _, e := range entries {
		k, ok := e[0].(string)
		if !ok {
			return nil, errors.New("encodeCBORMap: only string keys supported")
		}
		out = append(out, encodeHead(3, uint64(len(k)))...)
		out = append(out, []byte(k)...)
		v, err := encodeCBORValue(e[1])
		if err != nil {
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

func encodeCBORValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case string:
		out := encodeHead(3, uint64(len(x)))
		return append(out, []byte(x)...), nil
	case []byte:
		out := encodeHead(2, uint64(len(x)))
		return append(out, x...), nil
	case [][]byte:
		out := encodeHead(4, uint64(len(x)))
		for _, item := range x {
			seg := encodeHead(2, uint64(len(item)))
			out = append(out, seg...)
			out = append(out, item...)
		}
		return out, nil
	case int:
		if x < 0 {
			return nil, errors.New("encodeCBORValue: negative ints unsupported")
		}
		return encodeHead(0, uint64(x)), nil
	case uint64:
		return encodeHead(0, x), nil
	case [][2]any:
		return encodeCBORMap(x)
	default:
		return nil, fmt.Errorf("encodeCBORValue: unsupported type %T", v)
	}
}

func encodeHead(major byte, count uint64) []byte {
	switch {
	case count < 24:
		return []byte{(major << 5) | byte(count)}
	case count <= math.MaxUint8:
		return []byte{(major << 5) | 24, byte(count)}
	case count <= math.MaxUint16:
		return []byte{(major << 5) | 25, byte(count >> 8), byte(count)}
	case count <= math.MaxUint32:
		buf := []byte{(major << 5) | 26}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(count))
		return append(buf, b[:]...)
	default:
		buf := []byte{(major << 5) | 27}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], count)
		return append(buf, b[:]...)
	}
}

var errCBORUnsupported = errors.New("attestation: cbor item unsupported")
