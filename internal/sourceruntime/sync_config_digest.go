package sourceruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourceconfig"
)

// SyncConfigDigest fingerprints the operator-owned part of a runtime: its
// source ID and every config key that is not runtime-owned (__cerebro_*).
// Sync bookkeeping rewrites runtime-owned keys on every run, so including
// them would lift operator-action holds without any operator change.
func SyncConfigDigest(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return ""
	}
	config := runtime.GetConfig()
	keys := make([]string, 0, len(config))
	for key := range config {
		if sourceconfig.InternalKey(key) {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var payload strings.Builder
	writeSyncDigestField(&payload, strings.TrimSpace(runtime.GetSourceId()))
	for _, key := range keys {
		writeSyncDigestField(&payload, key)
		writeSyncDigestField(&payload, config[key])
	}
	sum := sha256.Sum256([]byte(payload.String()))
	return hex.EncodeToString(sum[:])
}

// writeSyncDigestField length-prefixes each value so adjacent keys and values
// cannot collide by shifting bytes between them.
func writeSyncDigestField(payload *strings.Builder, value string) {
	payload.WriteString(strconv.Itoa(len(value)))
	payload.WriteByte(':')
	payload.WriteString(value)
}
