package graph

type ordinalVisitSet struct {
	nodeIDs *NodeIDIndex
	words   []uint64
}

func newOrdinalVisitSet(nodeIDs *NodeIDIndex) ordinalVisitSet {
	return ordinalVisitSet{nodeIDs: nodeIDs}
}

func (s *ordinalVisitSet) mark(nodeID string) bool {
	if s == nil || s.nodeIDs == nil {
		return false
	}
	ordinal := s.nodeIDs.Intern(nodeID)
	return s.markOrdinal(ordinal)
}

func (s ordinalVisitSet) has(nodeID string) bool {
	if s.nodeIDs == nil {
		return false
	}
	ordinal, ok := s.nodeIDs.Lookup(nodeID)
	if !ok {
		return false
	}
	return s.hasOrdinal(ordinal)
}

func (s *ordinalVisitSet) markOrdinal(ordinal NodeOrdinal) bool {
	if s == nil {
		return false
	}
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok {
		return false
	}
	if word >= len(s.words) {
		grown := make([]uint64, word+1)
		copy(grown, s.words)
		s.words = grown
	}
	alreadyMarked := s.words[word]&mask != 0
	s.words[word] |= mask
	return !alreadyMarked
}

func (s ordinalVisitSet) hasOrdinal(ordinal NodeOrdinal) bool {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok {
		return false
	}
	if word >= len(s.words) {
		return false
	}
	return s.words[word]&mask != 0
}

func (s ordinalVisitSet) clone() ordinalVisitSet {
	cloned := ordinalVisitSet{nodeIDs: s.nodeIDs}
	if len(s.words) > 0 {
		cloned.words = append([]uint64(nil), s.words...)
	}
	return cloned
}
