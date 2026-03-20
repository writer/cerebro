package graph

type ordinalVisitSet struct {
	nodeIDs      *NodeIDIndex
	words        []uint64
	localNodeIDs *NodeIDIndex
	localWords   []uint64
}

func newOrdinalVisitSet(nodeIDs *NodeIDIndex) ordinalVisitSet {
	return ordinalVisitSet{nodeIDs: nodeIDs}
}

func (s *ordinalVisitSet) mark(nodeID string) bool {
	if s == nil {
		return false
	}
	if s.nodeIDs != nil {
		ordinal := s.nodeIDs.Intern(nodeID)
		return s.markOrdinal(ordinal)
	}
	if s.localNodeIDs == nil {
		s.localNodeIDs = NewNodeIDIndex()
	}
	ordinal := s.localNodeIDs.Intern(nodeID)
	return markOrdinalInWords(&s.localWords, ordinal)
}

func (s ordinalVisitSet) has(nodeID string) bool {
	if s.nodeIDs != nil {
		if ordinal, ok := s.nodeIDs.Lookup(nodeID); ok {
			return s.hasOrdinal(ordinal)
		}
	}
	if s.localNodeIDs != nil {
		ordinal, ok := s.localNodeIDs.Lookup(nodeID)
		if ok {
			return hasOrdinalInWords(s.localWords, ordinal)
		}
	}
	return false
}

func (s *ordinalVisitSet) markNode(nodeID string, ordinal NodeOrdinal) bool {
	if ordinal != InvalidNodeOrdinal {
		return s.markOrdinal(ordinal)
	}
	return s.mark(nodeID)
}

func (s ordinalVisitSet) hasNode(nodeID string, ordinal NodeOrdinal) bool {
	if ordinal != InvalidNodeOrdinal {
		return s.hasOrdinal(ordinal)
	}
	return s.has(nodeID)
}

func (s *ordinalVisitSet) markOrdinal(ordinal NodeOrdinal) bool {
	if s == nil {
		return false
	}
	return markOrdinalInWords(&s.words, ordinal)
}

func (s ordinalVisitSet) hasOrdinal(ordinal NodeOrdinal) bool {
	return hasOrdinalInWords(s.words, ordinal)
}

func markOrdinalInWords(words *[]uint64, ordinal NodeOrdinal) bool {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok {
		return false
	}
	if word >= len(*words) {
		grown := make([]uint64, word+1)
		copy(grown, *words)
		*words = grown
	}
	alreadyMarked := (*words)[word]&mask != 0
	(*words)[word] |= mask
	return !alreadyMarked
}

func hasOrdinalInWords(words []uint64, ordinal NodeOrdinal) bool {
	word, mask, ok := ordinalWordAndMask(ordinal)
	if !ok {
		return false
	}
	if word >= len(words) {
		return false
	}
	return words[word]&mask != 0
}

func (s ordinalVisitSet) clone() ordinalVisitSet {
	cloned := ordinalVisitSet{
		nodeIDs: s.nodeIDs,
	}
	if s.localNodeIDs != nil {
		cloned.localNodeIDs = s.localNodeIDs.Clone()
	}
	if len(s.words) > 0 {
		cloned.words = append([]uint64(nil), s.words...)
	}
	if len(s.localWords) > 0 {
		cloned.localWords = append([]uint64(nil), s.localWords...)
	}
	return cloned
}
