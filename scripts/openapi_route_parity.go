package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	routePattern   = regexp.MustCompile(`mux\.HandleFunc\("(?:(GET|POST|PUT|PATCH|DELETE) )?([^"]+)"`)
	pathPattern    = regexp.MustCompile(`^  (/[^:]+):\s*$`)
	methodPattern  = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	componentsLine = []byte("\ncomponents:\n")
)

type route struct {
	Method string
	Path   string
}

func main() {
	write := flag.Bool("write", false, "add placeholder OpenAPI paths for missing routes")
	flag.Parse()

	routes, err := registeredRoutes("internal/bootstrap/app.go")
	if err != nil {
		fail(err)
	}
	paths, methods, err := openAPIPaths("api/openapi.yaml")
	if err != nil {
		fail(err)
	}
	var missing []route
	for _, route := range routes {
		if !paths[route.Path] {
			missing = append(missing, route)
			continue
		}
		if route.Method != "" && !methods[route] {
			missing = append(missing, route)
		}
	}
	if len(missing) == 0 {
		return
	}
	if *write {
		if err := appendPlaceholders("api/openapi.yaml", missing); err != nil {
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
	os.Exit(1)
}

func registeredRoutes(path string) ([]route, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	matches := routePattern.FindAllStringSubmatch(string(payload), -1)
	seen := map[route]struct{}{}
	for _, match := range matches {
		method := strings.ToLower(strings.TrimSpace(match[1]))
		routePath := strings.TrimSpace(match[2])
		if routePath == "" {
			continue
		}
		seen[route{Method: method, Path: routePath}] = struct{}{}
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
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	paths := map[string]bool{}
	methods := map[route]bool{}
	currentPath := ""
	for _, line := range strings.Split(string(payload), "\n") {
		if match := pathPattern.FindStringSubmatch(line); match != nil {
			currentPath = match[1]
			paths[currentPath] = true
			continue
		}
		if currentPath == "" {
			continue
		}
		if match := methodPattern.FindStringSubmatch(line); match != nil {
			methods[route{Method: match[1], Path: currentPath}] = true
		}
	}
	return paths, methods, nil
}

func appendPlaceholders(path string, routes []route) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	paths, _, err := openAPIPaths(path)
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
	return os.WriteFile(path, next, 0o644)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
