package graphstore

type TwoHopRelationPair struct {
	First  string
	Second string
}

var suppressedTwoHopRelationPairs = []TwoHopRelationPair{
	{First: "belongs_to", Second: "has_finding"},
	{First: "represents", Second: "has_finding"},
	{First: "contains", Second: "has_finding"},
	{First: "contains", Second: "affected_by"},
	{First: "belongs_to", Second: "affected_by"},
	{First: "represents", Second: "affected_by"},
}

var suppressedTwoHopRelations = []string{"acted_on"}

// SuppressTwoHopPath reports whether a two-hop path is too broad for summary traversal.
func SuppressTwoHopPath(firstRelation string, secondRelation string) bool {
	for _, relation := range suppressedTwoHopRelations {
		if firstRelation == relation || secondRelation == relation {
			return true
		}
	}
	for _, pair := range suppressedTwoHopRelationPairs {
		if firstRelation == pair.First && secondRelation == pair.Second {
			return true
		}
	}
	return false
}

func SuppressedTwoHopRelations() []string {
	result := make([]string, len(suppressedTwoHopRelations))
	copy(result, suppressedTwoHopRelations)
	return result
}

func SuppressedTwoHopRelationPairKeys() []string {
	result := make([]string, 0, len(suppressedTwoHopRelationPairs))
	for _, pair := range suppressedTwoHopRelationPairs {
		result = append(result, pair.First+"|"+pair.Second)
	}
	return result
}
