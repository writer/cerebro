package filesystemanalyzer

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAnalyzerBuildsNPMDependencyGraphAndReachability(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.18.2",
        "lodash": "4.17.21"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": "1.20.2"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.2"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "const express = require('express')\napp.use(express.json())\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pkgs := make(map[string]PackageRecord, len(report.Packages))
	for _, pkg := range report.Packages {
		pkgs[pkg.Ecosystem+"|"+pkg.Name+"|"+pkg.Version] = pkg
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 npm packages from package-lock, got %#v", report.Packages)
	}

	if got := pkgs["npm|express|4.18.2"]; !got.DirectDependency || got.DependencyDepth != 1 || !got.Reachable || got.ImportFileCount != 1 {
		t.Fatalf("expected express to be direct depth=1 reachable, got %#v", got)
	}
	if got := pkgs["npm|body-parser|1.20.2"]; got.DirectDependency || got.DependencyDepth != 2 || !got.Reachable || got.ImportFileCount != 1 {
		t.Fatalf("expected body-parser to be transitive depth=2 reachable, got %#v", got)
	}
	if got := pkgs["npm|lodash|4.17.21"]; !got.DirectDependency || got.DependencyDepth != 1 || got.Reachable || got.ImportFileCount != 0 {
		t.Fatalf("expected lodash to be direct depth=1 and not reachable, got %#v", got)
	}

	if len(report.SBOM.Dependencies) != 1 {
		t.Fatalf("expected one package dependency edge, got %#v", report.SBOM.Dependencies)
	}
	expressRef := sbomComponentRef(pkgs["npm|express|4.18.2"])
	bodyParserRef := sbomComponentRef(pkgs["npm|body-parser|1.20.2"])
	dep := report.SBOM.Dependencies[0]
	if dep.Ref != expressRef || len(dep.DependsOn) != 1 || dep.DependsOn[0] != bodyParserRef {
		t.Fatalf("expected express -> body-parser dependency, got %#v", dep)
	}
}

func TestAnalyzerMarksDirectlyImportedTransitiveNPMPackageReachable(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.18.2"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": "1.20.2"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.2"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "const bodyParser = require('body-parser')\napp.use(bodyParser.json())\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pkg := findPackageRecord(report.Packages, "npm", "body-parser", "1.20.2")
	if pkg == nil {
		t.Fatalf("expected body-parser package in %#v", report.Packages)
	}
	if !pkg.Reachable || pkg.ImportFileCount != 1 {
		t.Fatalf("expected directly imported transitive package to be reachable, got %#v", *pkg)
	}
}

func TestAnalyzerBuildsNPMDependencyGraphFromV1Lockfile(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "requires": {
        "body-parser": "1.20.2"
      },
      "dependencies": {
        "body-parser": {
          "version": "1.20.2"
        }
      }
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "import express from 'express'\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	express := findPackageRecord(report.Packages, "npm", "express", "4.18.2")
	if express == nil {
		t.Fatalf("expected express package in %#v", report.Packages)
	}
	if !express.DirectDependency || express.DependencyDepth != 1 || !express.Reachable || express.ImportFileCount != 1 {
		t.Fatalf("expected express to be direct depth=1 reachable, got %#v", *express)
	}
	bodyParser := findPackageRecord(report.Packages, "npm", "body-parser", "1.20.2")
	if bodyParser == nil {
		t.Fatalf("expected body-parser package in %#v", report.Packages)
	}
	if bodyParser.DirectDependency || bodyParser.DependencyDepth != 2 || !bodyParser.Reachable || bodyParser.ImportFileCount != 1 {
		t.Fatalf("expected body-parser to be transitive depth=2 reachable, got %#v", *bodyParser)
	}
	if len(report.SBOM.Dependencies) != 1 {
		t.Fatalf("expected one dependency edge, got %#v", report.SBOM.Dependencies)
	}
}

func TestAnalyzerResolvesHoistedAncestorNPMPackages(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "srv", "app", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "a": "1.0.0"
      }
    },
    "node_modules/a": {
      "version": "1.0.0",
      "dependencies": {
        "b": "1.0.0"
      }
    },
    "node_modules/a/node_modules/b": {
      "version": "1.0.0",
      "dependencies": {
        "c": "1.0.0"
      }
    },
    "node_modules/a/node_modules/c": {
      "version": "1.0.0"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "srv", "app", "src", "index.js"), "import a from 'a'\nconsole.log(a)\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	cPkg := findPackageRecord(report.Packages, "npm", "c", "1.0.0")
	if cPkg == nil {
		t.Fatalf("expected hoisted ancestor package in %#v", report.Packages)
	}
	if cPkg.DependencyDepth != 3 || !cPkg.Reachable || cPkg.ImportFileCount != 1 {
		t.Fatalf("expected hoisted ancestor package to resolve and become reachable, got %#v", *cPkg)
	}
}

func TestAnalyzerDedupesInstalledNPMPackagesWhenLockfileOwnsTree(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "workspace", "node_modules", "lodash", "package.json"), `{"name":"lodash","version":"4.17.21"}`)
	mustWriteFile(t, filepath.Join(root, "workspace", "src", "index.js"), "import _ from 'lodash'\nconsole.log(_.camelCase('x'))\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if got := countPackageRecords(report.Packages, "npm", "lodash", "4.17.21"); got != 1 {
		t.Fatalf("expected lockfile-owned npm package to dedupe installed package.json records, got %d in %#v", got, report.Packages)
	}
	lockfilePkg := findPackageRecordByLocation(report.Packages, "npm", "lodash", "4.17.21", "workspace/package-lock.json")
	if lockfilePkg == nil {
		t.Fatalf("expected canonical lockfile-backed package record in %#v", report.Packages)
	}
	if !lockfilePkg.Reachable || lockfilePkg.ImportFileCount != 1 {
		t.Fatalf("expected canonical lockfile-backed package to retain reachability, got %#v", *lockfilePkg)
	}
	if installedPkg := findPackageRecordByLocation(report.Packages, "npm", "lodash", "4.17.21", "workspace/node_modules/lodash/package.json"); installedPkg != nil {
		t.Fatalf("expected installed package.json duplicate to be removed, got %#v", *installedPkg)
	}
}

func TestParseNPMDependencyGraphHandlesCircularDependencies(t *testing.T) {
	done := make(chan *npmDependencyGraph, 1)
	go func() {
		done <- parseNPMDependencyGraph("workspace/package-lock.json", []byte(`{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "a": "1.0.0"
      }
    },
    "node_modules/a": {
      "version": "1.0.0",
      "dependencies": {
        "b": "1.0.0"
      }
    },
    "node_modules/b": {
      "version": "1.0.0",
      "dependencies": {
        "a": "1.0.0"
      }
    }
  }
}`))
	}()

	select {
	case graph := <-done:
		if graph == nil || len(graph.Packages) != 2 {
			t.Fatalf("expected circular lockfile to resolve two packages, got %#v", graph)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("parseNPMDependencyGraph did not terminate for circular dependencies")
	}
}

func TestAnalyzerBuildsGoDependencyReachabilityFromGoMod(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/demo

go 1.22

require (
	github.com/google/uuid v1.6.0
	golang.org/x/text v0.14.0 // indirect
)
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `github.com/google/uuid v1.6.0
golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "main.go"), `package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	fmt.Println(uuid.NewString())
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	uuid := findPackageRecord(report.Packages, "golang", "github.com/google/uuid", "v1.6.0")
	if uuid == nil {
		t.Fatalf("expected uuid package in %#v", report.Packages)
	}
	if got := countPackageRecords(report.Packages, "golang", "github.com/google/uuid", "v1.6.0"); got != 1 {
		t.Fatalf("expected one uuid package record, got %d in %#v", got, report.Packages)
	}
	if !uuid.DirectDependency || uuid.DependencyDepth != 1 || !uuid.Reachable || uuid.ImportFileCount != 1 {
		t.Fatalf("expected uuid to be direct depth=1 reachable, got %#v", *uuid)
	}

	text := findPackageRecord(report.Packages, "golang", "golang.org/x/text", "v0.14.0")
	if text == nil {
		t.Fatalf("expected x/text package in %#v", report.Packages)
	}
	if got := countPackageRecords(report.Packages, "golang", "golang.org/x/text", "v0.14.0"); got != 1 {
		t.Fatalf("expected one x/text package record, got %d in %#v", got, report.Packages)
	}
	if text.DirectDependency || text.DependencyDepth != 2 || text.Reachable || text.ImportFileCount != 0 {
		t.Fatalf("expected x/text to be indirect depth=2 and not reachable, got %#v", *text)
	}
	if len(report.SBOM.Dependencies) != 1 {
		t.Fatalf("expected one Go SBOM dependency entry, got %#v", report.SBOM.Dependencies)
	}
	appComponent := findSBOMComponent(report.SBOM.Components, "application", "example.com/demo", "")
	if appComponent == nil {
		t.Fatalf("expected Go application component in %#v", report.SBOM.Components)
	}
	dep := report.SBOM.Dependencies[0]
	if dep.Ref != appComponent.BOMRef {
		t.Fatalf("expected Go dependencies to hang from application component %q, got %#v", appComponent.BOMRef, dep)
	}
	uuidRef := sbomComponentRef(*uuid)
	if len(dep.DependsOn) != 1 || dep.DependsOn[0] != uuidRef {
		t.Fatalf("expected Go application to depend only on direct dependency %q, got %#v", uuidRef, dep)
	}
	if report.Summary.DependencyCount != 1 {
		t.Fatalf("expected dependency_count=1, got %#v", report.Summary)
	}
}

func TestAnalyzerMarksGoSubpackageImportsReachable(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/demo

go 1.22

require golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "main.go"), `package main

import "golang.org/x/text/cases"

func main() {
	_ = cases.Title
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	text := findPackageRecord(report.Packages, "golang", "golang.org/x/text", "v0.14.0")
	if text == nil {
		t.Fatalf("expected x/text package in %#v", report.Packages)
	}
	if !text.Reachable || text.ImportFileCount != 1 {
		t.Fatalf("expected subpackage import to mark module reachable, got %#v", *text)
	}
}

func TestAnalyzerUsesLongestGoModulePrefixForReachability(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/demo

go 1.22

require (
	github.com/foo v1.0.0
	github.com/foo/bar v1.2.3
)
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `github.com/foo v1.0.0
github.com/foo/bar v1.2.3
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "main.go"), `package main

import "github.com/foo/bar/baz"

func main() {
	_ = baz.Do
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	short := findPackageRecord(report.Packages, "golang", "github.com/foo", "v1.0.0")
	if short == nil {
		t.Fatalf("expected short-prefix module in %#v", report.Packages)
	}
	if short.Reachable || short.ImportFileCount != 0 {
		t.Fatalf("expected shorter module prefix to remain unreachable, got %#v", *short)
	}

	long := findPackageRecord(report.Packages, "golang", "github.com/foo/bar", "v1.2.3")
	if long == nil {
		t.Fatalf("expected longest-prefix module in %#v", report.Packages)
	}
	if !long.Reachable || long.ImportFileCount != 1 {
		t.Fatalf("expected longest-prefix module to be reachable, got %#v", *long)
	}
}

func TestAnalyzerScopesNPMReachabilityToNearestManifest(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "package-lock.json"), `{
  "name": "root",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "root",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "workspace", "service", "package-lock.json"), `{
  "name": "service",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "service",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "workspace", "service", "src", "index.js"), "import _ from 'lodash'\nconsole.log(_.camelCase('x'))\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	rootPkg := findPackageRecordByLocation(report.Packages, "npm", "lodash", "4.17.21", "workspace/package-lock.json")
	if rootPkg == nil {
		t.Fatalf("expected root lodash package in %#v", report.Packages)
	}
	if rootPkg.Reachable || rootPkg.ImportFileCount != 0 {
		t.Fatalf("expected root manifest package to stay unreachable, got %#v", *rootPkg)
	}

	servicePkg := findPackageRecordByLocation(report.Packages, "npm", "lodash", "4.17.21", "workspace/service/package-lock.json")
	if servicePkg == nil {
		t.Fatalf("expected service lodash package in %#v", report.Packages)
	}
	if !servicePkg.Reachable || servicePkg.ImportFileCount != 1 {
		t.Fatalf("expected nested manifest package to be reachable, got %#v", *servicePkg)
	}
}

func TestAnalyzerScopesGoReachabilityToNearestManifest(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "workspace", "go.mod"), `module example.com/root

go 1.22

require golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "go.sum"), `golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "tools", "go.mod"), `module example.com/root/tools

go 1.22

require golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "tools", "go.sum"), `golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "workspace", "tools", "main.go"), `package main

import "golang.org/x/text/cases"

func main() {
	_ = cases.Title
}
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	rootPkg := findPackageRecordByLocation(report.Packages, "golang", "golang.org/x/text", "v0.14.0", "workspace/go.mod")
	if rootPkg == nil {
		t.Fatalf("expected root Go package in %#v", report.Packages)
	}
	if rootPkg.Reachable || rootPkg.ImportFileCount != 0 {
		t.Fatalf("expected root module package to stay unreachable, got %#v", *rootPkg)
	}

	toolPkg := findPackageRecordByLocation(report.Packages, "golang", "golang.org/x/text", "v0.14.0", "workspace/tools/go.mod")
	if toolPkg == nil {
		t.Fatalf("expected nested Go package in %#v", report.Packages)
	}
	if !toolPkg.Reachable || toolPkg.ImportFileCount != 1 {
		t.Fatalf("expected nested Go module package to be reachable, got %#v", *toolPkg)
	}
}

func TestAnalyzerIgnoresTopLevelNodeModulesForJSImportReachability(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "package-lock.json"), `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.21"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`)
	mustWriteFile(t, filepath.Join(root, "node_modules", "rogue", "index.js"), "import _ from 'lodash'\n")

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	lodash := findPackageRecord(report.Packages, "npm", "lodash", "4.17.21")
	if lodash == nil {
		t.Fatalf("expected lodash package in %#v", report.Packages)
	}
	if lodash.Reachable || lodash.ImportFileCount != 0 {
		t.Fatalf("expected node_modules import to be ignored, got %#v", *lodash)
	}
}

func TestAnalyzerIgnoresTopLevelVendorForGoReachability(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "go.mod"), `module example.com/demo

go 1.22

require golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "go.sum"), `golang.org/x/text v0.14.0
`)
	mustWriteFile(t, filepath.Join(root, "vendor", "rogue.go"), `package vendor

import "golang.org/x/text/cases"
`)

	report, err := New(Options{}).Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	text := findPackageRecord(report.Packages, "golang", "golang.org/x/text", "v0.14.0")
	if text == nil {
		t.Fatalf("expected x/text package in %#v", report.Packages)
	}
	if text.Reachable || text.ImportFileCount != 0 {
		t.Fatalf("expected vendor import to be ignored, got %#v", *text)
	}
}

func findPackageRecord(pkgs []PackageRecord, ecosystem, name, version string) *PackageRecord {
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Ecosystem == ecosystem && pkg.Name == name && pkg.Version == version {
			return pkg
		}
	}
	return nil
}

func findPackageRecordByLocation(pkgs []PackageRecord, ecosystem, name, version, location string) *PackageRecord {
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Ecosystem == ecosystem && pkg.Name == name && pkg.Version == version && pkg.Location == location {
			return pkg
		}
	}
	return nil
}

func countPackageRecords(pkgs []PackageRecord, ecosystem, name, version string) int {
	count := 0
	for _, pkg := range pkgs {
		if pkg.Ecosystem == ecosystem && pkg.Name == name && pkg.Version == version {
			count++
		}
	}
	return count
}

func findSBOMComponent(components []SBOMComponent, componentType, name, version string) *SBOMComponent {
	for idx := range components {
		component := &components[idx]
		if component.Type == componentType && component.Name == name && component.Version == version {
			return component
		}
	}
	return nil
}
