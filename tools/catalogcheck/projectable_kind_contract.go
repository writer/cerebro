package main

import (
	"fmt"
	"strings"
)

// An event's source and family come from its kind: the append-log subject is
// "<prefix>.<kind>" and the Rust consumer reads it back as
// "<prefix>.<source>.<family>" (see eventTaxonomy in
// internal/sourcehttp/organizationalgraph). A kind that does not split into two
// non-empty segments has no derivable family, so every event of that kind fails
// projection and takes the whole source-runtime sync down with it.
//
// The kind's own first segment is the source, which is how shared namespaces
// work: `asset.data_sensitivity` belongs to the `asset` source whichever cloud
// connector emits it. So this deliberately does not take the emitting catalog's
// id: the kind alone determines the source.
func checkProjectableKind(path, kind string) []issue {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return nil
	}
	source, family, found := strings.Cut(kind, ".")
	if found && source != "" && family != "" {
		return nil
	}
	return []issue{{
		path: path,
		message: fmt.Sprintf(
			"emitted kind %q is not projectable: the organizational projection reads a kind as \"<source>.<family>\", so it must have two non-empty segments",
			kind,
		),
	}}
}
