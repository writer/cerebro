package runtime

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
)

const (
	runtimeProcessedEventBloomFalsePositiveRate = 0.001
	runtimeProcessedEventBloomRebuildFactor     = 2
)

const (
	processedEventBloomFNVOffset = 14695981039346656037
	processedEventBloomFNVPrime  = 1099511628211
	processedEventBloomSaltA     = 0x9e3779b97f4a7c15
	processedEventBloomSaltB     = 0xc2b2ae3d27d4eb4f
)

type processedEventFastClaimStore interface {
	TryClaimProcessedEvent(context.Context, executionstore.ProcessedEventRecord, int) (bool, error)
}

type processedEventKeyLister interface {
	ListActiveProcessedEventKeys(context.Context, string, time.Time, int) ([]string, error)
}

type processedEventBloom struct {
	mu               sync.RWMutex
	bits             []uint64
	bitCount         uint64
	hashCount        uint64
	insertCount      uint64
	rebuildThreshold uint64
	nextRebuildAt    uint64
}

func newProcessedEventBloom(maxEntries int, falsePositiveRate float64) *processedEventBloom {
	if maxEntries <= 0 {
		return nil
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = runtimeProcessedEventBloomFalsePositiveRate
	}

	n := float64(maxEntries)
	m := uint64(math.Ceil((-n * math.Log(falsePositiveRate)) / (math.Ln2 * math.Ln2)))
	m *= 2
	if m < 64 {
		m = 64
	}
	k := uint64(math.Ceil((float64(m) / n) * math.Ln2))
	if k == 0 {
		k = 1
	}

	return &processedEventBloom{
		bits:             make([]uint64, (m+63)/64),
		bitCount:         m,
		hashCount:        k,
		rebuildThreshold: uint64(maxEntries * runtimeProcessedEventBloomRebuildFactor),
		nextRebuildAt:    uint64(maxEntries * runtimeProcessedEventBloomRebuildFactor),
	}
}

func (f *processedEventBloom) maybeContains(key string) bool {
	if f == nil {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.maybeContainsLocked(key)
}

func (f *processedEventBloom) maybeContainsLocked(key string) bool {
	if f.bitCount == 0 || len(f.bits) == 0 {
		return false
	}
	h1, h2 := processedEventBloomHashes(key)
	for i := uint64(0); i < f.hashCount; i++ {
		index := (h1 + i*h2) % f.bitCount
		if !processedEventBloomBitIsSet(f.bits, index) {
			return false
		}
	}
	return true
}

func (f *processedEventBloom) add(key string) bool {
	if f == nil {
		return false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	processedEventBloomAddToBits(f.bits, f.bitCount, f.hashCount, key)
	f.insertCount++
	if f.rebuildThreshold == 0 || f.insertCount < f.nextRebuildAt {
		return false
	}
	f.nextRebuildAt = f.insertCount + f.rebuildThreshold
	return true
}

func (f *processedEventBloom) replace(keys []string) {
	if f == nil {
		return
	}
	replacement := make([]uint64, len(f.bits))
	for _, key := range keys {
		processedEventBloomAddToBits(replacement, f.bitCount, f.hashCount, key)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	copy(f.bits, replacement)
	f.insertCount = uint64(len(keys))
	if f.rebuildThreshold > 0 {
		f.nextRebuildAt = f.insertCount + f.rebuildThreshold
	}
}

func processedEventBloomAddToBits(bits []uint64, bitCount, hashCount uint64, key string) {
	if bitCount == 0 || len(bits) == 0 {
		return
	}
	h1, h2 := processedEventBloomHashes(key)
	for i := uint64(0); i < hashCount; i++ {
		index := (h1 + i*h2) % bitCount
		bits[index/64] |= uint64(1) << (index % 64)
	}
}

func processedEventBloomBitIsSet(bits []uint64, index uint64) bool {
	if len(bits) == 0 {
		return false
	}
	return bits[index/64]&(uint64(1)<<(index%64)) != 0
}

func processedEventBloomHashes(key string) (uint64, uint64) {
	h1 := processedEventBloomHash64(key, processedEventBloomSaltA)
	h2 := processedEventBloomHash64(key, processedEventBloomSaltB)
	if h2 == 0 {
		h2 = processedEventBloomFNVPrime
	}
	return h1, h2
}

func processedEventBloomHash64(value string, salt uint64) uint64 {
	h := processedEventBloomFNVOffset ^ salt
	for i := 0; i < len(value); i++ {
		h ^= uint64(value[i])
		h *= processedEventBloomFNVPrime
	}
	return h
}
