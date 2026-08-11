//! Fail-closed policy for APOC calls admitted into agent-authored read queries.
//!
//! Keep this list deliberately narrower than APOC Core. Namespaces that can
//! execute Cypher, perform I/O, schedule work, mutate the graph, or sleep are
//! not admitted. Unknown function namespaces and procedure names stay
//! unsupported until they are classified.

const SAFE_FUNCTION_PREFIXES: &[&str] = &[
    "apoc.agg.",
    "apoc.any.",
    "apoc.bitwise.",
    "apoc.coll.",
    "apoc.convert.",
    "apoc.date.",
    "apoc.diff.",
    "apoc.json.",
    "apoc.map.",
    "apoc.math.",
    "apoc.number.",
    "apoc.rel.",
    "apoc.text.",
];

const SAFE_FUNCTIONS: &[&str] = &[
    "apoc.hashing.fingerprint",
    "apoc.hashing.fingerprinting",
    "apoc.label.exists",
    "apoc.node.degree",
    "apoc.node.degree.in",
    "apoc.node.degree.out",
    "apoc.node.id",
    "apoc.node.labels",
    "apoc.node.relationship.exists",
    "apoc.node.relationship.types",
    "apoc.version",
];

const BLOCKED_FUNCTIONS: &[&str] = &[
    "apoc.coll.combinations",
    "apoc.coll.fill",
    "apoc.coll.randomitem",
    "apoc.coll.randomitems",
    "apoc.coll.shuffle",
    "apoc.date.currenttimestamp",
    "apoc.date.systemtimezone",
    "apoc.map.fromnodes",
    "apoc.text.lpad",
    "apoc.text.random",
    "apoc.text.repeat",
    "apoc.text.rpad",
];

// These procedures only transform already-bound values. The Go graph-store
// read guard carries the same allowlist as a second enforcement layer.
const SAFE_PROCEDURES: &[&str] = &[
    "apoc.coll.elements",
    "apoc.coll.pairwithoffset",
    "apoc.coll.partition",
    "apoc.coll.split",
    "apoc.coll.ziptorows",
    "apoc.convert.totree",
];

pub(crate) fn is_safe_function(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !BLOCKED_FUNCTIONS.contains(&name.as_str())
        && (SAFE_FUNCTIONS.contains(&name.as_str())
            || SAFE_FUNCTION_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix)))
}

pub(crate) fn is_safe_procedure(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SAFE_PROCEDURES.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_stays_read_only_and_fail_closed() {
        for name in [
            "apoc.convert.fromJsonMap",
            "APOC.COLL.FLATTEN",
            "apoc.text.join",
            "apoc.version",
        ] {
            assert!(is_safe_function(name), "{name}");
        }
        for name in [
            "apoc.util.sleep",
            "apoc.cypher.runFirstColumn",
            "apoc.load.json",
            "apoc.custom.asFunction",
            "apoc.coll.combinations",
            "apoc.date.currentTimestamp",
            "apoc.map.fromNodes",
            "apoc.text.random",
            "apoc.unknown.futureFunction",
        ] {
            assert!(!is_safe_function(name), "{name}");
        }
        for name in [
            "apoc.coll.elements",
            "APOC.CONVERT.TOTREE",
            "apoc.coll.partition",
        ] {
            assert!(is_safe_procedure(name), "{name}");
        }
        for name in [
            "apoc.periodic.iterate",
            "apoc.trigger.add",
            "apoc.path.expandConfig",
            "apoc.meta.stats",
            "apoc.unknown.futureProcedure",
        ] {
            assert!(!is_safe_procedure(name), "{name}");
        }
    }
}
