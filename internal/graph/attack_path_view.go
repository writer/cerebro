package graph

import (
	"context"
	"fmt"
	"strings"
)

// BuildAttackPathViewGraph builds a minimal graph view for one attack path
// using store-native node lookups instead of snapshot materialization.
func BuildAttackPathViewGraph(ctx context.Context, store GraphStore, path *ScoredAttackPath) (*Graph, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	view := New()
	if path == nil {
		return view, nil
	}

	seenNodes := make(map[string]struct{}, len(path.Steps)+2)
	addNode := func(node *Node, id string) error {
		if node != nil && strings.TrimSpace(node.ID) != "" {
			id = node.ID
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return nil
		}
		if _, ok := seenNodes[id]; ok {
			return nil
		}
		resolved := node
		if resolved == nil && store != nil {
			lookup, ok, err := store.LookupNode(ctx, id)
			if err != nil {
				return err
			}
			if ok {
				resolved = lookup
			}
		}
		if resolved == nil {
			resolved = &Node{ID: attackPathViewNodeID(id), Name: id}
		} else {
			resolved = cloneNode(resolved)
			if strings.TrimSpace(resolved.Name) == "" {
				resolved.Name = resolved.ID
			}
		}
		view.AddNode(resolved)
		seenNodes[id] = struct{}{}
		return nil
	}

	if err := addNode(path.EntryPoint, ""); err != nil {
		return nil, err
	}
	if err := addNode(path.Target, ""); err != nil {
		return nil, err
	}
	for i, step := range path.Steps {
		if err := addNode(nil, step.FromNode); err != nil {
			return nil, err
		}
		if err := addNode(nil, step.ToNode); err != nil {
			return nil, err
		}
		view.AddEdge(&Edge{
			ID:     attackPathViewEdgeID(path.ID, i+1),
			Source: strings.TrimSpace(step.FromNode),
			Target: strings.TrimSpace(step.ToNode),
			Kind:   step.EdgeKind,
			Effect: EdgeEffectAllow,
		})
	}
	return view, nil
}

func attackPathViewNodeID(id string) string {
	return strings.TrimSpace(id)
}

func attackPathViewEdgeID(pathID string, index int) string {
	return fmt.Sprintf("attack_path:%s:%d", strings.TrimSpace(pathID), index)
}
