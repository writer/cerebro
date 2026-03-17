package graph

import (
	"math"
)

// NodeOrdinal is the compact integer form used to represent an interned node ID.
type NodeOrdinal uint32

// InvalidNodeOrdinal is reserved for blank or missing node IDs.
const InvalidNodeOrdinal NodeOrdinal = 0

// NodeIDIndex interns string node IDs into stable compact ordinals.
type NodeIDIndex struct {
	strToOrdinal map[string]NodeOrdinal
	ordinalToStr []string
}

// NewNodeIDIndex returns an empty string<->ordinal index.
func NewNodeIDIndex() *NodeIDIndex {
	return &NodeIDIndex{
		strToOrdinal: make(map[string]NodeOrdinal),
		ordinalToStr: []string{""}, // reserve zero as InvalidNodeOrdinal
	}
}

// Intern returns a stable ordinal for id, allocating one only on the first sighting.
func (idx *NodeIDIndex) Intern(id string) NodeOrdinal {
	if idx == nil {
		return InvalidNodeOrdinal
	}
	if id == "" {
		return InvalidNodeOrdinal
	}
	if ordinal, ok := idx.strToOrdinal[id]; ok {
		return ordinal
	}
	ordinal, ok := nodeOrdinalFromLength(len(idx.ordinalToStr))
	if !ok {
		return InvalidNodeOrdinal
	}
	idx.strToOrdinal[id] = ordinal
	idx.ordinalToStr = append(idx.ordinalToStr, id)
	return ordinal
}

// Lookup returns the existing ordinal for id without allocating a new one.
func (idx *NodeIDIndex) Lookup(id string) (NodeOrdinal, bool) {
	if idx == nil {
		return InvalidNodeOrdinal, false
	}
	if id == "" {
		return InvalidNodeOrdinal, false
	}
	ordinal, ok := idx.strToOrdinal[id]
	return ordinal, ok
}

// Resolve maps an ordinal back to its original string ID.
func (idx *NodeIDIndex) Resolve(ordinal NodeOrdinal) (string, bool) {
	if idx == nil || ordinal == InvalidNodeOrdinal {
		return "", false
	}
	if int(ordinal) >= len(idx.ordinalToStr) {
		return "", false
	}
	id := idx.ordinalToStr[ordinal]
	if id == "" {
		return "", false
	}
	return id, true
}

// Len reports the number of interned node IDs.
func (idx *NodeIDIndex) Len() int {
	if idx == nil || len(idx.ordinalToStr) == 0 {
		return 0
	}
	return len(idx.ordinalToStr) - 1
}

// NewBitmap allocates a visited bitmap large enough to index every interned ID.
func (idx *NodeIDIndex) NewBitmap() []bool {
	if idx == nil || len(idx.ordinalToStr) == 0 {
		return nil
	}
	return make([]bool, len(idx.ordinalToStr))
}

func nodeOrdinalFromLength(length int) (NodeOrdinal, bool) {
	if length <= 0 || length > math.MaxUint32 {
		return InvalidNodeOrdinal, false
	}
	return NodeOrdinal(uint32(length)), true
}

func ordinalWordAndMask(ordinal NodeOrdinal) (int, uint64, bool) {
	if ordinal == InvalidNodeOrdinal {
		return 0, 0, false
	}
	slot := int(ordinal - 1)
	if slot < 0 {
		return 0, 0, false
	}
	word := slot / 64
	bit := slot & 63
	return word, uint64(1) << bit, true
}

func nodeOrdinalFromWordBit(wordIndex, bit int) (NodeOrdinal, bool) {
	if wordIndex < 0 || bit < 0 || bit >= 64 {
		return InvalidNodeOrdinal, false
	}
	ordinal := uint64(wordIndex)*64 + uint64(bit) + 1
	if ordinal == 0 || ordinal > math.MaxUint32 {
		return InvalidNodeOrdinal, false
	}
	return NodeOrdinal(ordinal), true
}
