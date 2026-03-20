package graph

import "sort"

func (g *Graph) addNodeToDerivedIndexesLocked(node *Node) {
	if !g.indexBuilt || node == nil || node.DeletedAt != nil {
		return
	}
	if g.isInternetFacing(node) {
		g.internetNodes = append(g.internetNodes, node)
	}
	if g.isCrownJewel(node) {
		g.crownJewels = append(g.crownJewels, node)
	}
	if doc, ok := buildEntitySearchDocument(node); ok {
		g.addEntitySearchDocumentLocked(doc)
	}
}

func (g *Graph) removeNodeFromDerivedIndexesLocked(node *Node) {
	if !g.indexBuilt || node == nil {
		return
	}
	g.internetNodes = removeIndexedNodeLocked(g.internetNodes, node.ID)
	g.crownJewels = removeIndexedNodeLocked(g.crownJewels, node.ID)
	g.removeEntitySearchDocumentLocked(node.ID)
}

func (g *Graph) refreshNodeClassifiedIndexesLocked(node *Node, wasInternetFacing, wasCrownJewel bool) {
	if !g.indexBuilt || node == nil || node.DeletedAt != nil {
		return
	}
	isInternetFacing := g.isInternetFacing(node)
	switch {
	case wasInternetFacing && !isInternetFacing:
		g.internetNodes = removeIndexedNodeLocked(g.internetNodes, node.ID)
	case !wasInternetFacing && isInternetFacing:
		g.internetNodes = append(g.internetNodes, node)
	}

	isCrownJewel := g.isCrownJewel(node)
	switch {
	case wasCrownJewel && !isCrownJewel:
		g.crownJewels = removeIndexedNodeLocked(g.crownJewels, node.ID)
	case !wasCrownJewel && isCrownJewel:
		g.crownJewels = append(g.crownJewels, node)
	}
}

func (g *Graph) addEntitySearchDocumentLocked(doc entitySearchDocument) {
	if !g.indexBuilt || doc.ID == "" {
		return
	}
	if g.entitySearchDocs == nil {
		g.entitySearchDocs = make(map[string]entitySearchDocument)
	}
	if g.entitySearchTokenIndex == nil {
		g.entitySearchTokenIndex = make(map[string][]string)
	}
	if g.entitySearchTrigramIndex == nil {
		g.entitySearchTrigramIndex = make(map[string][]string)
	}

	g.removeEntitySearchDocumentLocked(doc.ID)
	g.entitySearchDocs[doc.ID] = doc
	for _, token := range doc.Tokens {
		addEntitySearchIndexIDLocked(g.entitySearchTokenIndex, token, doc.ID)
	}
	for _, trigram := range entitySearchTrigrams(doc.SearchText) {
		addEntitySearchIndexIDLocked(g.entitySearchTrigramIndex, trigram, doc.ID)
	}
}

func (g *Graph) removeEntitySearchDocumentLocked(id string) {
	if !g.indexBuilt || id == "" || len(g.entitySearchDocs) == 0 {
		return
	}
	doc, ok := g.entitySearchDocs[id]
	if !ok {
		return
	}
	delete(g.entitySearchDocs, id)
	for _, token := range doc.Tokens {
		removeEntitySearchIndexIDLocked(g.entitySearchTokenIndex, token, id)
	}
	for _, trigram := range entitySearchTrigrams(doc.SearchText) {
		removeEntitySearchIndexIDLocked(g.entitySearchTrigramIndex, trigram, id)
	}
}

func addEntitySearchIndexIDLocked(index map[string][]string, key, id string) {
	if key == "" || id == "" {
		return
	}
	ids := index[key]
	pos := sort.SearchStrings(ids, id)
	if pos < len(ids) && ids[pos] == id {
		return
	}
	ids = append(ids, "")
	copy(ids[pos+1:], ids[pos:])
	ids[pos] = id
	index[key] = ids
}

func removeEntitySearchIndexIDLocked(index map[string][]string, key, id string) {
	if key == "" || id == "" {
		return
	}
	ids := index[key]
	pos := sort.SearchStrings(ids, id)
	if pos >= len(ids) || ids[pos] != id {
		return
	}
	copy(ids[pos:], ids[pos+1:])
	ids[len(ids)-1] = ""
	ids = ids[:len(ids)-1]
	if len(ids) == 0 {
		delete(index, key)
		return
	}
	index[key] = ids
}
