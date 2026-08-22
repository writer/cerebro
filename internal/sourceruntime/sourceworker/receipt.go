package sourceworker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func responseHeadersSHA256(headers map[string]string) string {
	hash := sha256.New()
	writeDigestValue(hash, uint64Bytes(uint64(len(headers))))
	for _, key := range sortedHeaderKeys(headers) {
		writeDigestValue(hash, []byte(key))
		writeDigestValue(hash, []byte(headers[key]))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func executionIntentSHA256(metadata *cerebrov1.SourceWorkerRuntimeMetadataV2, execution *cerebrov1.SourceWorkerHTTPExecutionV2) string {
	hash := sha256.New()
	writeDigestValue(hash, []byte("source-worker-http-execution-v2"))
	writeDigestValue(hash, []byte(execution.GetRequest().GetRequestIntentDigest()))
	writeDigestValue(hash, uint64Bytes(uint64(metadata.GetPriorTerminalWatermarkUnixMillis())))
	writeDigestValue(hash, []byte(metadata.GetPriorCheckpoint()))
	writeDigestMap(hash, metadata.GetPublicConfig())
	writeDigestValue(hash, execution.GetBody())
	writeDigestMap(hash, execution.GetDeclaredHeaders())
	writeDigestValue(hash, []byte(execution.GetCredentialOperation()))
	return hex.EncodeToString(hash.Sum(nil))
}

func writeDigestMap(hash digestWriter, values map[string]string) {
	writeDigestValue(hash, uint64Bytes(uint64(len(values))))
	for _, key := range sortedHeaderKeys(values) {
		writeDigestValue(hash, []byte(key))
		writeDigestValue(hash, []byte(values[key]))
	}
}

type digestWriter interface{ Write([]byte) (int, error) }

func writeDigestValue(writer digestWriter, value []byte) {
	_, _ = writer.Write(uint64Bytes(uint64(len(value))))
	_, _ = writer.Write(value)
}

func uint64Bytes(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func safeUint64(value int) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%w: protocol integer is negative", ErrInvalidExecution)
	}
	return uint64(value), nil
}
