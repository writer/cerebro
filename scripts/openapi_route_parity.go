package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	routePattern   = regexp.MustCompile(`(?:mux\.HandleFunc\(|registerHTTPRoute\(mux,\s*)"(?:(GET|POST|PUT|PATCH|DELETE) )?([^"]+)"`)
	componentsLine = []byte("\ncomponents:\n")
)

const openAPIPath = "api/openapi.yaml"

type route struct {
	Method string
	Path   string
}

func main() {
	write := flag.Bool("write", false, "add placeholder OpenAPI paths for missing routes")
	flag.Parse()

	routes, err := registeredRoutes("internal/bootstrap/app.go", "internal/bootstrap/routes.go")
	if err != nil {
		fail(err)
	}
	rustRoutes, err := registeredRustAuthorityRoutes("crates/cerebro-platform/src/main.rs")
	if err != nil {
		fail(err)
	}
	routes = append(routes, rustRoutes...)
	paths, methods, err := openAPIPaths(openAPIPath)
	if err != nil {
		fail(err)
	}
	missing := missingOpenAPIRoutes(routes, paths, methods)
	unregistered := unregisteredOpenAPIRoutes(routes, methods)
	if len(missing) == 0 && len(unregistered) == 0 {
		return
	}
	if *write && len(unregistered) == 0 {
		if err := appendPlaceholders(missing); err != nil {
			fail(err)
		}
		return
	}
	for _, route := range missing {
		method := route.Method
		if method == "" {
			method = "ANY"
		}
		fmt.Fprintf(os.Stderr, "OpenAPI missing route: %s %s\n", method, route.Path)
	}
	for _, route := range unregistered {
		fmt.Fprintf(os.Stderr, "OpenAPI route is not registered: %s %s\n", strings.ToUpper(route.Method), route.Path)
	}
	os.Exit(1)
}

func registeredRustAuthorityRoutes(path string) ([]route, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	routes := []struct {
		route  route
		marker string
	}{
		{route: route{Method: "get", Path: "/platform/graph/neighborhood"}, marker: "get(product_neighborhood_route)"},
		{route: route{Method: "get", Path: "/platform/graph/provenance"}, marker: "get(graph_provenance_route)"},
		{route: route{Method: "get", Path: "/v1/security/lifecycle"}, marker: "get(security_lifecycle)"},
	}
	registered := make([]route, 0, len(routes))
	for _, candidate := range routes {
		if !bytes.Contains(payload, []byte(`"`+candidate.route.Path+`"`)) || !bytes.Contains(payload, []byte(candidate.marker)) {
			return nil, fmt.Errorf("Rust authority route is not registered: %s %s", strings.ToUpper(candidate.route.Method), candidate.route.Path)
		}
		registered = append(registered, candidate.route)
	}
	return registered, nil
}

func missingOpenAPIRoutes(routes []route, paths map[string]bool, methods map[route]bool) []route {
	var missing []route
	for _, route := range routes {
		if !paths[route.Path] || (route.Method != "" && !methods[route]) {
			missing = append(missing, route)
		}
	}
	return missing
}

func unregisteredOpenAPIRoutes(routes []route, methods map[route]bool) []route {
	registered := make(map[route]bool, len(routes))
	wildcardPaths := make(map[string]bool)
	for _, route := range routes {
		if route.Method == "" {
			wildcardPaths[route.Path] = true
			continue
		}
		registered[route] = true
	}

	var unregistered []route
	for route := range methods {
		if !registered[route] && !wildcardPaths[route.Path] {
			unregistered = append(unregistered, route)
		}
	}
	sort.Slice(unregistered, func(i, j int) bool {
		if unregistered[i].Path == unregistered[j].Path {
			return unregistered[i].Method < unregistered[j].Method
		}
		return unregistered[i].Path < unregistered[j].Path
	})
	return unregistered
}

func registeredRoutes(paths ...string) ([]route, error) {
	seen := map[route]struct{}{}
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		matches := routePattern.FindAllStringSubmatch(string(payload), -1)
		for _, match := range matches {
			method := strings.ToLower(strings.TrimSpace(match[1]))
			routePath := strings.TrimSpace(match[2])
			if routePath == "" {
				continue
			}
			seen[route{Method: method, Path: routePath}] = struct{}{}
		}
	}
	routes := make([]route, 0, len(seen))
	for route := range seen {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes, nil
}

func openAPIPaths(path string) (map[string]bool, map[route]bool, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := doc.Validate(context.Background()); err != nil {
		return nil, nil, err
	}
	paths := map[string]bool{}
	methods := map[route]bool{}
	for path, item := range doc.Paths.Map() {
		paths[path] = true
		if item == nil {
			continue
		}
		for method := range item.Operations() {
			if isParityMethod(method) {
				methods[route{Method: strings.ToLower(method), Path: path}] = true
			}
		}
	}
	return paths, methods, nil
}

func isParityMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func appendPlaceholders(routes []route) error {
	payload, err := os.ReadFile(openAPIPath)
	if err != nil {
		return err
	}
	paths, _, err := openAPIPaths(openAPIPath)
	if err != nil {
		return err
	}
	insertAt := bytes.Index(payload, componentsLine)
	if insertAt < 0 {
		return fmt.Errorf("components section not found")
	}
	var addition strings.Builder
	for _, route := range routes {
		if paths[route.Path] {
			return fmt.Errorf("OpenAPI path %s exists but is missing method %s; add the method manually", route.Path, route.Method)
		}
		method := route.Method
		if method == "" {
			method = "get"
		}
		addition.WriteString(fmt.Sprintf("  %s:\n", route.Path))
		addition.WriteString(fmt.Sprintf("    %s:\n", method))
		addition.WriteString("      summary: TODO\n")
		addition.WriteString("      responses:\n")
		addition.WriteString("        '200':\n")
		addition.WriteString("          description: TODO\n")
	}
	next := append([]byte{}, payload[:insertAt]...)
	next = append(next, []byte(addition.String())...)
	next = append(next, payload[insertAt:]...)
	return os.WriteFile(openAPIPath, next, 0o644) // #nosec G306,G703 -- writes only the repository OpenAPI file selected by this build-time tool.
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
