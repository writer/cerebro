package providers

import (
	"fmt"
	"strconv"
	"strings"
)

var providerPaginationMaxPages = 1000

type paginationGuard struct {
	provider string
	resource string
	maxPages int
	pages    int
	seen     map[string]struct{}
}

func newPaginationGuard(provider, resource string) *paginationGuard {
	maxPages := providerPaginationMaxPages
	if maxPages <= 0 {
		maxPages = 1000
	}
	return &paginationGuard{
		provider: provider,
		resource: resource,
		maxPages: maxPages,
		seen:     make(map[string]struct{}),
	}
}

func (g *paginationGuard) nextPage() error {
	if g.pages >= g.maxPages {
		return fmt.Errorf("%s pagination exceeded %d pages for %s", g.provider, g.maxPages, g.resource)
	}
	g.pages++
	return nil
}

func (g *paginationGuard) nextToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if _, exists := g.seen[token]; exists {
		return fmt.Errorf("%s pagination loop detected for %s", g.provider, g.resource)
	}
	g.seen[token] = struct{}{}
	return nil
}

func (g *paginationGuard) nextOffset(offset int) error {
	return g.nextToken(strconv.Itoa(offset))
}
