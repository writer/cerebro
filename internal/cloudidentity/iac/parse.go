package iac

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// moduleFiles identifies the slice of a ci.Repository that makes up one
// Terraform module directory (root or a local/remote module call target).
type moduleFiles struct {
	pin  ci.SourcePin
	dir  string // normalized directory, "" for repository root
	addr string // human-readable module address for citations/gap scoping
	// files holds only the direct (non-recursive) .tf children of dir.
	files map[string]*ci.SourceFile
	// index holds the complete file index of the repository this module
	// directory was materialized from -- the top-level stack repository
	// for the root module and every local module reached from it, or the
	// remotely-fetched repository for a pinned public module and every
	// local module reached from within it. Local child module resolution
	// (`source = "./..."`/`"../..."`) always looks here, never at the
	// stack-wide rn.files, so `./submodules/x` inside a remote module
	// resolves against that remote module's own tree instead of (wrongly)
	// the primary stack repository.
	index map[string]*ci.SourceFile

	// defaultGoogleProject is this module scope's own (non-aliased)
	// `provider "google" { project = ... }` value, resolved once in
	// processModule (R14 finding 3); "" when no default google provider
	// block sets a resolvable project here.
	defaultGoogleProject string
	// googleProjectAmbiguous is true once this module was entered through
	// a module call carrying an explicit `providers = {...}` mapping
	// (propagated to every descendant module too): the "default" google
	// provider can no longer be assumed to be the root's, so
	// defaultGoogleProject is never consulted here.
	googleProjectAmbiguous bool
}

// taggedBlock pairs a parsed HCL block with the source file it came from, so
// every extracted fact can carry an exact file/line citation.
type taggedBlock struct {
	block *hclsyntax.Block
	file  *ci.SourceFile
}

func indexFiles(files []ci.SourceFile) map[string]*ci.SourceFile {
	out := make(map[string]*ci.SourceFile, len(files))
	for i := range files {
		out[files[i].Path] = &files[i]
	}
	return out
}

func normalizeDir(root string) string {
	root = strings.Trim(root, "/")
	if root == "." {
		return ""
	}
	return root
}

// filesUnderDir returns the direct (non-recursive) .tf/.tf.json children of
// dir, matching Terraform's own single-directory module semantics: a
// ".tf.json" sibling is a real, load-bearing Terraform configuration file
// (R14 finding 2), not merely data, so it must be visible here even though
// parseModuleFiles does not statically parse its block structure (see
// "iac.unsupported_tf_json_config").
func filesUnderDir(files map[string]*ci.SourceFile, dir string) map[string]*ci.SourceFile {
	out := map[string]*ci.SourceFile{}
	for p, f := range files {
		if normalizePath(p) != dir {
			continue
		}
		if !strings.HasSuffix(p, ".tf") && !strings.HasSuffix(p, ".tf.json") {
			continue
		}
		out[p] = f
	}
	return out
}

func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "./")
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

// parsedModule is the categorized set of top-level blocks for one module
// directory, in deterministic (path then source order) iteration order.
type parsedModule struct {
	variables []taggedBlock
	locals    []taggedBlock
	resources []taggedBlock
	data      []taggedBlock
	modules   []taggedBlock
	outputs   []taggedBlock
	providers []taggedBlock
	// hasUnsupportedJSON is true when this module directory contains one
	// or more ".tf.json" configuration files (R14 finding 2): their block
	// structure is never statically parsed, so processModule marks every
	// declaration registered directly in this module scope incomplete --
	// any of them could be the target of a grant/trust/boundary attachment
	// this reader could not see.
	hasUnsupportedJSON bool
}

func parseModuleFiles(mf moduleFiles, rn *run) (parsedModule, hcl.Diagnostics) {
	var pm parsedModule
	var diags hcl.Diagnostics

	paths := make([]string, 0, len(mf.files))
	for p := range mf.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		f := mf.files[p]
		if strings.HasSuffix(p, ".tf.json") {
			// R14 finding 2: a ".tf.json" file's own resource/data/module/
			// output/variable block structure is never statically parsed
			// (see the hasUnsupportedJSON doc comment on parsedModule);
			// this is always an explicit, scoped, non-silent gap, never a
			// quiet omission of whatever it declares.
			rn.addGap(ci.Gap{
				Code:    "iac.unsupported_tf_json_config",
				Scope:   mf.addr,
				Message: fmt.Sprintf("%q is a JSON-variant Terraform configuration file; its resource/data/module/output/variable blocks are not statically parsed", f.Path),
				References: []ci.Reference{{
					Repository: mf.pin.Repository,
					Revision:   mf.pin.Revision,
					Path:       f.Path,
					Digest:     f.Digest,
				}},
			})
			pm.hasUnsupportedJSON = true
			continue
		}
		hf, pdiags := hclsyntax.ParseConfig(f.Content, f.Path, hcl.InitialPos)
		diags = append(diags, pdiags...)
		if hf == nil || hf.Body == nil {
			continue
		}
		body, ok := hf.Body.(*hclsyntax.Body)
		if !ok {
			rn.addGap(ci.Gap{
				Code:    "iac.unsupported_syntax",
				Scope:   mf.addr,
				Message: "file body is not native HCL syntax (JSON variant terraform files are not statically supported)",
				References: []ci.Reference{{
					Repository: mf.pin.Repository,
					Revision:   mf.pin.Revision,
					Path:       f.Path,
					Digest:     f.Digest,
				}},
			})
			continue
		}
		for _, blk := range body.Blocks {
			tb := taggedBlock{block: blk, file: f}
			switch blk.Type {
			case "variable":
				pm.variables = append(pm.variables, tb)
			case "locals":
				pm.locals = append(pm.locals, tb)
			case "resource":
				pm.resources = append(pm.resources, tb)
			case "data":
				pm.data = append(pm.data, tb)
			case "module":
				pm.modules = append(pm.modules, tb)
			case "output":
				pm.outputs = append(pm.outputs, tb)
			case "provider":
				pm.providers = append(pm.providers, tb)
			default:
				// terraform/moved/import/check blocks carry no
				// identity-relevant static facts for this analyzer.
			}
		}
	}
	return pm, diags
}
