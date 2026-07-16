// Command wasminspect reports the capability surface and size of WebAssembly artifacts.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/tetratelabs/wazero"
)

type report struct {
	Artifact          string   `json:"artifact"`
	Bytes             int      `json:"bytes"`
	ImportedFunctions []string `json:"imported_functions"`
	ImportedMemories  []string `json:"imported_memories"`
	ExportedFunctions []string `json:"exported_functions"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wasminspect <module.wasm> [module.wasm ...]")
		os.Exit(2)
	}
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer func() {
		_ = runtime.Close(ctx)
	}()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	for _, path := range os.Args[1:] {
		result, err := inspect(ctx, runtime, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inspect %s: %v\n", path, err)
			os.Exit(1)
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
			os.Exit(1)
		}
	}
}

func inspect(ctx context.Context, runtime wazero.Runtime, path string) (report, error) {
	module, err := os.ReadFile(path) // #nosec G304,G703 -- paths are explicit command-line inputs to a local developer tool.
	if err != nil {
		return report{}, err
	}
	compiled, err := runtime.CompileModule(ctx, module)
	if err != nil {
		return report{}, err
	}
	defer func() {
		_ = compiled.Close(ctx)
	}()

	result := report{
		Artifact:          filepath.Base(path),
		Bytes:             len(module),
		ImportedFunctions: []string{},
		ImportedMemories:  []string{},
		ExportedFunctions: []string{},
	}
	for _, definition := range compiled.ImportedFunctions() {
		moduleName, name, imported := definition.Import()
		if imported {
			result.ImportedFunctions = append(result.ImportedFunctions, moduleName+"."+name)
		}
	}
	for _, definition := range compiled.ImportedMemories() {
		moduleName, name, imported := definition.Import()
		if imported {
			result.ImportedMemories = append(result.ImportedMemories, moduleName+"."+name)
		}
	}
	for name := range compiled.ExportedFunctions() {
		result.ExportedFunctions = append(result.ExportedFunctions, name)
	}
	slices.Sort(result.ImportedFunctions)
	slices.Sort(result.ImportedMemories)
	slices.Sort(result.ExportedFunctions)
	return result, nil
}
