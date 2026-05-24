package eventregistry

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

type avroWriter struct {
	buf bytes.Buffer
	err error
}

func newAvroWriter() *avroWriter {
	return &avroWriter{}
}

func (w *avroWriter) bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.buf.Bytes(), nil
}

func (w *avroWriter) boolean(value bool) {
	if value {
		w.writeByte(1)
		return
	}
	w.writeByte(0)
}

func (w *avroWriter) integer(value int) {
	if value > math.MaxInt32 || value < math.MinInt32 {
		w.setErr(fmt.Errorf("avro int out of range: %d", value))
		return
	}
	w.long(int64(value))
}

func (w *avroWriter) long(value int64) {
	u := uint64(value<<1) ^ uint64(value>>63)
	for u >= 0x80 {
		w.writeByte(byte(u) | 0x80)
		u >>= 7
	}
	w.writeByte(byte(u))
}

func (w *avroWriter) double(value float64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], math.Float64bits(value))
	w.write(data[:])
}

func (w *avroWriter) string(value string) {
	w.long(int64(len(value)))
	w.write([]byte(value))
}

func (w *avroWriter) bytesValue(value []byte) {
	w.long(int64(len(value)))
	w.write(value)
}

func (w *avroWriter) nullableString(value *string) {
	if value == nil {
		w.long(0)
		return
	}
	w.long(1)
	w.string(*value)
}

func (w *avroWriter) nullableDouble(value *float64) {
	if value == nil {
		w.long(0)
		return
	}
	w.long(1)
	w.double(*value)
}

func (w *avroWriter) stringArray(values []string) {
	if len(values) == 0 {
		w.long(0)
		return
	}
	w.long(int64(len(values)))
	for _, value := range values {
		w.string(value)
	}
	w.long(0)
}

func (w *avroWriter) findingControlRefArray(values []FindingControlRefSnapshot) {
	if len(values) == 0 {
		w.long(0)
		return
	}
	w.long(int64(len(values)))
	for _, value := range values {
		w.string(value.FrameworkName)
		w.string(value.ControlID)
	}
	w.long(0)
}

func (w *avroWriter) stringMap(values map[string]string) {
	if len(values) == 0 {
		w.long(0)
		return
	}
	keys := sortedKeys(values)
	w.long(int64(len(keys)))
	for _, key := range keys {
		w.string(key)
		w.string(values[key])
	}
	w.long(0)
}

func (w *avroWriter) metadataMap(values map[string]any) {
	if len(values) == 0 {
		w.long(0)
		return
	}
	keys := sortedKeys(values)
	w.long(int64(len(keys)))
	for _, key := range keys {
		w.string(key)
		w.metadataValue(values[key])
	}
	w.long(0)
}

func (w *avroWriter) metadataValue(value any) {
	switch v := value.(type) {
	case nil:
		w.long(0)
	case string:
		w.long(1)
		w.string(v)
	case int:
		w.long(2)
		w.long(int64(v))
	case int8:
		w.long(2)
		w.long(int64(v))
	case int16:
		w.long(2)
		w.long(int64(v))
	case int32:
		w.long(2)
		w.long(int64(v))
	case int64:
		w.long(2)
		w.long(v)
	case uint:
		w.uintMetadata(v)
	case uint8:
		w.uintMetadata(v)
	case uint16:
		w.uintMetadata(v)
	case uint32:
		w.uintMetadata(v)
	case uint64:
		w.uintMetadata(v)
	case float32:
		w.long(3)
		w.double(float64(v))
	case float64:
		w.long(3)
		w.double(v)
	case bool:
		w.long(4)
		w.boolean(v)
	case map[string]any:
		w.jsonMetadata(v)
	case []any:
		w.jsonMetadata(v)
	case map[string]string:
		w.jsonMetadata(v)
	case []string:
		w.jsonMetadata(v)
	default:
		w.setErr(fmt.Errorf("unsupported metadata value type %T", value))
	}
}

func (w *avroWriter) uintMetadata(value any) {
	var u uint64
	switch v := value.(type) {
	case uint:
		u = uint64(v)
	case uint8:
		u = uint64(v)
	case uint16:
		u = uint64(v)
	case uint32:
		u = uint64(v)
	case uint64:
		u = v
	}
	if u > math.MaxInt64 {
		w.setErr(fmt.Errorf("metadata unsigned integer out of range: %d", u))
		return
	}
	w.long(2)
	w.long(int64(u))
}

func (w *avroWriter) jsonMetadata(value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		w.setErr(fmt.Errorf("marshal metadata value %T: %w", value, err))
		return
	}
	w.long(1)
	w.string(string(payload))
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (w *avroWriter) writeByte(value byte) {
	if w.err != nil {
		return
	}
	w.err = w.buf.WriteByte(value)
}

func (w *avroWriter) write(value []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.buf.Write(value)
}

func (w *avroWriter) setErr(err error) {
	if w.err == nil {
		w.err = err
	}
}
