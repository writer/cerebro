package attestation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"

	fxcbor "github.com/fxamacker/cbor/v2"
)

// Strict deterministic-CBOR adapter, sized to what Apple App Attest
// attestation objects actually contain: top-level map, text-string keys,
// byte-string values, arrays of byte strings, and unsigned/negative
// integers.
//
// We deliberately do NOT implement: tags, indefinite-length items,
// floats, bignum tags, half-precision floats, or non-string map keys. An
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

var strictCBORDecMode = mustCBORDecMode()

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
	var decoded any
	rest, err := strictCBORDecMode.UnmarshalFirst(data, &decoded)
	if err != nil {
		return cborValue{}, nil, fmt.Errorf("%w: %w", errCBORUnsupported, err)
	}
	value, err := cborValueFromDecoded(decoded)
	if err != nil {
		return cborValue{}, nil, err
	}
	return value, rest, nil
}

func mustCBORDecMode() fxcbor.DecMode {
	mode, err := fxcbor.DecOptions{
		DupMapKey:        fxcbor.DupMapKeyEnforcedAPF,
		IndefLength:      fxcbor.IndefLengthForbidden,
		TagsMd:           fxcbor.TagsForbidden,
		BignumTag:        fxcbor.BignumTagForbidden,
		IntDec:           fxcbor.IntDecConvertNone,
		MaxArrayElements: maxCBORContainerElements,
		MaxMapPairs:      maxCBORContainerElements,
		DefaultMapType:   reflect.TypeOf(map[string]any{}),
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func cborValueFromDecoded(decoded any) (cborValue, error) {
	switch x := decoded.(type) {
	case uint64:
		return cborValue{major: 0, value: x}, nil
	case int64:
		if x >= 0 {
			return cborValue{}, errCBORUnsupported
		}
		return cborValue{major: 1, value: uint64(-1 - x)}, nil
	case big.Int:
		return negativeBigIntCBORValue(&x)
	case *big.Int:
		if x == nil {
			return cborValue{}, errCBORUnsupported
		}
		return negativeBigIntCBORValue(x)
	case []byte:
		bs := append([]byte(nil), x...)
		return cborValue{major: 2, bytes: bs, value: uint64(len(bs))}, nil
	case string:
		return cborValue{major: 3, text: x, value: uint64(len(x))}, nil
	case []any:
		if len(x) > maxCBORContainerElements {
			return cborValue{}, errCBORUnsupported
		}
		arr := make([]cborValue, 0, len(x))
		for _, item := range x {
			converted, err := cborValueFromDecoded(item)
			if err != nil {
				return cborValue{}, err
			}
			arr = append(arr, converted)
		}
		return cborValue{major: 4, array: arr, value: uint64(len(arr))}, nil
	case map[string]any:
		if len(x) > maxCBORContainerElements {
			return cborValue{}, errCBORUnsupported
		}
		entries := make([]cborMapEntry, 0, len(x))
		for key, item := range x {
			converted, err := cborValueFromDecoded(item)
			if err != nil {
				return cborValue{}, err
			}
			entries = append(entries, cborMapEntry{key: key, val: converted})
		}
		return cborValue{major: 5, mapEl: entries, value: uint64(len(entries))}, nil
	default:
		return cborValue{}, errCBORUnsupported
	}
}

func negativeBigIntCBORValue(x *big.Int) (cborValue, error) {
	if x.Sign() >= 0 {
		return cborValue{}, errCBORUnsupported
	}
	n := new(big.Int).Neg(x)
	n.Sub(n, big.NewInt(1))
	if !n.IsUint64() {
		return cborValue{}, errCBORUnsupported
	}
	return cborValue{major: 1, value: n.Uint64()}, nil
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
		buf := []byte{(major << 5) | 25}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(count))
		return append(buf, b[:]...)
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
