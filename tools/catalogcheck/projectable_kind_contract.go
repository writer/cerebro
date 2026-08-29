package main

import (
	"fmt"
	"strings"
)

// The organizational projection derives a family id by stripping the "<source
// id>." prefix from an event kind (see eventFamily in
// internal/sourcehttp/organizationalgraph). A kind that does not carry its own
// source's prefix has no derivable family, so every event of that kind fails
// projection with `source event kind %q does not belong to source %q` and takes
// the whole source-runtime sync down with it.
//
// unprojectableEmittedKinds records the kinds that predate this rule. They are
// real defects, not approved exceptions: the three cloud sources emit the shared
// `asset.*` namespace, which `internal/findings/data_signal_rule.go` models as
// its own logical source ("asset") while the event itself is stamped with the
// emitting cloud's source id. Resolving that split changes the event contract,
// the finding rules, and the compiled Rust catalog together, so it is tracked
// separately. This list must only ever shrink.
var unprojectableEmittedKinds = map[string]map[string]bool{
	"asset.data_sensitivity": {
		"aws":   true,
		"azure": true,
		"gcp":   true,
	},
}

// checkProjectableKind reports an emitted kind that the organizational
// projection cannot derive a family from.
func checkProjectableKind(path, sourceID, kind string) []issue {
	sourceID = strings.TrimSpace(sourceID)
	kind = strings.TrimSpace(kind)
	if sourceID == "" || kind == "" {
		return nil
	}
	prefix := sourceID + "."
	if strings.HasPrefix(kind, prefix) && len(kind) > len(prefix) {
		return nil
	}
	if unprojectableEmittedKinds[kind][sourceID] {
		return nil
	}
	return []issue{{
		path: path,
		message: fmt.Sprintf(
			"emitted kind %q is not projectable by source %q: the organizational projection derives a family by stripping the %q prefix, so this kind fails every sync",
			kind, sourceID, prefix,
		),
	}}
}
