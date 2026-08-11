//! Fail-closed APOC Core policy for agent-authored read queries.
//!
//! The catalog is pinned to APOC Core 5.26, matching Cerebro's Neo4j 5
//! compatibility line. Keep names exact: namespace prefixes would silently
//! admit future functions without classification.

use crate::lexer::{Token, TokenKind};

pub(crate) const APOC_CORE_CATALOG_VERSION: &str = "5.26";
const MAX_TRAVERSAL_HOPS: u64 = 6;

const SAFE_FUNCTIONS: &[&str] = &[
    "apoc.agg.first",
    "apoc.agg.graph",
    "apoc.agg.last",
    "apoc.agg.maxitems",
    "apoc.agg.median",
    "apoc.agg.minitems",
    "apoc.agg.nth",
    "apoc.agg.percentiles",
    "apoc.agg.product",
    "apoc.agg.slice",
    "apoc.agg.statistics",
    "apoc.any.isdeleted",
    "apoc.any.properties",
    "apoc.any.property",
    "apoc.bitwise.op",
    "apoc.coll.avg",
    "apoc.coll.contains",
    "apoc.coll.containsall",
    "apoc.coll.containsallsorted",
    "apoc.coll.containsduplicates",
    "apoc.coll.containssorted",
    "apoc.coll.different",
    "apoc.coll.disjunction",
    "apoc.coll.dropduplicateneighbors",
    "apoc.coll.duplicates",
    "apoc.coll.duplicateswithcount",
    "apoc.coll.flatten",
    "apoc.coll.frequencies",
    "apoc.coll.frequenciesasmap",
    "apoc.coll.indexof",
    "apoc.coll.insert",
    "apoc.coll.insertall",
    "apoc.coll.intersection",
    "apoc.coll.isequalcollection",
    "apoc.coll.max",
    "apoc.coll.min",
    "apoc.coll.occurrences",
    "apoc.coll.pairs",
    "apoc.coll.pairsmin",
    "apoc.coll.pairwithoffset",
    "apoc.coll.partition",
    "apoc.coll.remove",
    "apoc.coll.removeall",
    "apoc.coll.runningtotal",
    "apoc.coll.set",
    "apoc.coll.sort",
    "apoc.coll.sortmaps",
    "apoc.coll.sortmulti",
    "apoc.coll.sortnodes",
    "apoc.coll.sorttext",
    "apoc.coll.stdev",
    "apoc.coll.subtract",
    "apoc.coll.sum",
    "apoc.coll.sumlongs",
    "apoc.coll.toset",
    "apoc.coll.union",
    "apoc.coll.unionall",
    "apoc.coll.zip",
    "apoc.convert.fromjsonlist",
    "apoc.convert.fromjsonmap",
    "apoc.convert.getjsonproperty",
    "apoc.convert.getjsonpropertymap",
    "apoc.convert.tojson",
    "apoc.convert.tolist",
    "apoc.convert.tomap",
    "apoc.convert.tonode",
    "apoc.convert.tonodelist",
    "apoc.convert.torelationship",
    "apoc.convert.torelationshiplist",
    "apoc.convert.toset",
    "apoc.convert.tosortedjsonmap",
    "apoc.date.add",
    "apoc.date.convert",
    "apoc.date.convertformat",
    "apoc.date.field",
    "apoc.date.fields",
    "apoc.date.format",
    "apoc.date.fromiso8601",
    "apoc.date.parse",
    "apoc.date.toiso8601",
    "apoc.date.toyears",
    "apoc.diff.nodes",
    "apoc.hashing.fingerprint",
    "apoc.hashing.fingerprinting",
    "apoc.json.path",
    "apoc.label.exists",
    "apoc.map.clean",
    "apoc.map.flatten",
    "apoc.map.fromlists",
    "apoc.map.frompairs",
    "apoc.map.fromvalues",
    "apoc.map.get",
    "apoc.map.groupby",
    "apoc.map.groupbymulti",
    "apoc.map.merge",
    "apoc.map.mergelist",
    "apoc.map.mget",
    "apoc.map.removekey",
    "apoc.map.removekeys",
    "apoc.map.setentry",
    "apoc.map.setkey",
    "apoc.map.setlists",
    "apoc.map.setpairs",
    "apoc.map.setvalues",
    "apoc.map.sortedproperties",
    "apoc.map.submap",
    "apoc.map.unflatten",
    "apoc.map.updatetree",
    "apoc.map.values",
    "apoc.math.cosh",
    "apoc.math.coth",
    "apoc.math.csch",
    "apoc.math.maxbyte",
    "apoc.math.maxdouble",
    "apoc.math.maxint",
    "apoc.math.maxlong",
    "apoc.math.minbyte",
    "apoc.math.mindouble",
    "apoc.math.minint",
    "apoc.math.minlong",
    "apoc.math.sech",
    "apoc.math.sigmoid",
    "apoc.math.sigmoidprime",
    "apoc.math.sinh",
    "apoc.math.tanh",
    "apoc.node.degree",
    "apoc.node.degree.in",
    "apoc.node.degree.out",
    "apoc.node.id",
    "apoc.node.labels",
    "apoc.node.relationship.exists",
    "apoc.node.relationship.types",
    "apoc.node.relationships.exist",
    "apoc.nodes.connected",
    "apoc.nodes.isdense",
    "apoc.number.arabictoroman",
    "apoc.number.exact.add",
    "apoc.number.exact.div",
    "apoc.number.exact.mul",
    "apoc.number.exact.sub",
    "apoc.number.exact.toexact",
    "apoc.number.exact.tofloat",
    "apoc.number.exact.tointeger",
    "apoc.number.format",
    "apoc.number.parsefloat",
    "apoc.number.parseint",
    "apoc.number.romantoarabic",
    "apoc.path.combine",
    "apoc.path.create",
    "apoc.path.elements",
    "apoc.path.slice",
    "apoc.rel.endnode",
    "apoc.rel.id",
    "apoc.rel.startnode",
    "apoc.rel.type",
    "apoc.text.base64decode",
    "apoc.text.base64encode",
    "apoc.text.base64urldecode",
    "apoc.text.base64urlencode",
    "apoc.text.bytecount",
    "apoc.text.bytes",
    "apoc.text.camelcase",
    "apoc.text.capitalize",
    "apoc.text.capitalizeall",
    "apoc.text.charat",
    "apoc.text.clean",
    "apoc.text.code",
    "apoc.text.comparecleaned",
    "apoc.text.decapitalize",
    "apoc.text.decapitalizeall",
    "apoc.text.distance",
    "apoc.text.doublemetaphone",
    "apoc.text.format",
    "apoc.text.fuzzymatch",
    "apoc.text.hammingdistance",
    "apoc.text.hexcharat",
    "apoc.text.hexvalue",
    "apoc.text.indexesof",
    "apoc.text.indexof",
    "apoc.text.jarowinklerdistance",
    "apoc.text.join",
    "apoc.text.levenshteindistance",
    "apoc.text.levenshteinsimilarity",
    "apoc.text.phonetic",
    "apoc.text.regexgroups",
    "apoc.text.regexgroupsbyname",
    "apoc.text.regreplace",
    "apoc.text.replace",
    "apoc.text.slug",
    "apoc.text.snakecase",
    "apoc.text.sorensendicesimilarity",
    "apoc.text.split",
    "apoc.text.swapcase",
    "apoc.text.tocypher",
    "apoc.text.touppercase",
    "apoc.text.uppercamelcase",
    "apoc.text.urldecode",
    "apoc.text.urlencode",
    "apoc.version",
];

const VALUE_PROCEDURES: &[&str] = &[
    "apoc.coll.elements",
    "apoc.coll.pairwithoffset",
    "apoc.coll.partition",
    "apoc.coll.split",
    "apoc.coll.ziptorows",
    "apoc.paths.tojsontree",
];

const PATH_PROCEDURES: &[&str] = &["apoc.path.expandconfig", "apoc.path.subgraphnodes"];
const NEIGHBOR_PROCEDURES: &[&str] = &[
    "apoc.neighbors.athop",
    "apoc.neighbors.byhop",
    "apoc.neighbors.tohop",
];

pub(crate) fn is_safe_function(name: &str) -> bool {
    debug_assert_eq!(APOC_CORE_CATALOG_VERSION, "5.26");
    SAFE_FUNCTIONS.contains(&name.to_ascii_lowercase().as_str())
}

pub(crate) fn is_safe_procedure(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    VALUE_PROCEDURES.contains(&name.as_str())
        || PATH_PROCEDURES.contains(&name.as_str())
        || NEIGHBOR_PROCEDURES.contains(&name.as_str())
}

pub(crate) fn is_safe_procedure_invocation(
    tokens: &[Token],
    name_index: usize,
    max_rows: u64,
) -> bool {
    let name = tokens[name_index].text.to_ascii_lowercase();
    let Some((arguments, close_index)) = call_arguments(tokens, name_index) else {
        return false;
    };
    if VALUE_PROCEDURES.contains(&name.as_str()) {
        return true;
    }
    if PATH_PROCEDURES.contains(&name.as_str()) {
        return validate_path_procedure(&name, &arguments, tokens, close_index, max_rows);
    }
    if NEIGHBOR_PROCEDURES.contains(&name.as_str()) {
        return validate_neighbor_procedure(&name, &arguments, tokens, close_index);
    }
    false
}

fn validate_path_procedure(
    name: &str,
    arguments: &[&[Token]],
    tokens: &[Token],
    close_index: usize,
    max_rows: u64,
) -> bool {
    if arguments.len() != 2 || !simple_variable(arguments[0]) {
        return false;
    }
    let Some(config) = LiteralMap::parse(arguments[1]) else {
        return false;
    };
    if !config.has_only(&[
        "bfs",
        "filterstartnode",
        "labelfilter",
        "limit",
        "maxlevel",
        "minlevel",
        "relationshipfilter",
        "uniqueness",
    ]) || config.string("labelfilter") != Some("+Entity")
        || config.boolean("bfs") != Some(true)
        || config.boolean("filterstartnode") != Some(true)
        || config.string("uniqueness") != Some("NODE_GLOBAL")
        || !config
            .string("relationshipfilter")
            .is_some_and(valid_relationship_filter)
    {
        return false;
    }
    let Some(max_level) = config.integer("maxlevel") else {
        return false;
    };
    let Some(min_level) = config.integer("minlevel") else {
        return false;
    };
    let Some(limit) = config.integer("limit") else {
        return false;
    };
    if !(1..=MAX_TRAVERSAL_HOPS).contains(&max_level)
        || min_level > max_level
        || limit == 0
        || limit > max_rows
    {
        return false;
    }
    if name == "apoc.path.expandconfig" {
        has_path_output_guard(tokens, close_index)
    } else {
        has_node_output_guard(tokens, close_index)
    }
}

fn validate_neighbor_procedure(
    name: &str,
    arguments: &[&[Token]],
    tokens: &[Token],
    close_index: usize,
) -> bool {
    if arguments.len() != 3
        || !simple_variable(arguments[0])
        || !single_string(arguments[1]).is_some_and(valid_relationship_filter)
        || !single_integer(arguments[2])
            .is_some_and(|value| (1..=MAX_TRAVERSAL_HOPS).contains(&value))
    {
        return false;
    }
    if name == "apoc.neighbors.byhop" {
        has_node_list_output_guard(tokens, close_index)
    } else {
        has_node_output_guard(tokens, close_index)
    }
}

fn valid_relationship_filter(value: &str) -> bool {
    !value.is_empty()
        && value.split('|').all(|part| {
            let part = part.trim();
            let name = part
                .strip_prefix('<')
                .or_else(|| part.strip_suffix('>'))
                .unwrap_or(part);
            !name.is_empty()
                && name.eq_ignore_ascii_case("RELATION")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn has_path_output_guard(tokens: &[Token], close_index: usize) -> bool {
    guarded_then_projected(
        tokens,
        close_index + 1,
        &[
            "YIELD",
            "path",
            "WHERE",
            "all",
            "(",
            "node",
            "IN",
            "nodes",
            "(",
            "path",
            ")",
            "WHERE",
            "node.tenant_id",
            "=",
            "$tenant_id",
            ")",
            "AND",
            "all",
            "(",
            "rel",
            "IN",
            "relationships",
            "(",
            "path",
            ")",
            "WHERE",
            "rel.tenant_id",
            "=",
            "$tenant_id",
            ")",
        ],
    )
}

fn has_node_output_guard(tokens: &[Token], close_index: usize) -> bool {
    guarded_then_projected(
        tokens,
        close_index + 1,
        &[
            "YIELD",
            "node",
            "WHERE",
            "node.tenant_id",
            "=",
            "$tenant_id",
        ],
    )
}

fn has_node_list_output_guard(tokens: &[Token], close_index: usize) -> bool {
    guarded_then_projected(
        tokens,
        close_index + 1,
        &[
            "YIELD",
            "nodes",
            "WHERE",
            "all",
            "(",
            "node",
            "IN",
            "nodes",
            "WHERE",
            "node.tenant_id",
            "=",
            "$tenant_id",
            ")",
        ],
    )
}

fn guarded_then_projected(tokens: &[Token], start: usize, expected: &[&str]) -> bool {
    let matches = tokens
        .get(start..start + expected.len())
        .is_some_and(|actual| {
            actual
                .iter()
                .zip(expected)
                .all(|(token, expected)| token.text.eq_ignore_ascii_case(expected))
        });
    matches
        && tokens.get(start + expected.len()).is_some_and(|token| {
            token.text.eq_ignore_ascii_case("WITH") || token.text.eq_ignore_ascii_case("RETURN")
        })
}

fn simple_variable(tokens: &[Token]) -> bool {
    tokens.len() == 1 && tokens[0].kind == TokenKind::Identifier && !tokens[0].text.contains('.')
}

fn single_string(tokens: &[Token]) -> Option<&str> {
    (tokens.len() == 1 && tokens[0].kind == TokenKind::String).then_some(tokens[0].text.as_str())
}

fn single_integer(tokens: &[Token]) -> Option<u64> {
    (tokens.len() == 1 && tokens[0].kind == TokenKind::Number)
        .then(|| tokens[0].text.parse().ok())
        .flatten()
}

fn call_arguments<'a>(tokens: &'a [Token], name_index: usize) -> Option<(Vec<&'a [Token]>, usize)> {
    if tokens.get(name_index + 1)?.text != "(" {
        return None;
    }
    let mut stack = Vec::new();
    let mut arguments = Vec::new();
    let mut start = name_index + 2;
    let mut index = start;
    while index < tokens.len() {
        let text = tokens[index].text.as_str();
        match text {
            "(" | "[" | "{" => stack.push(text),
            ")" if stack.is_empty() => {
                if index > start || !arguments.is_empty() {
                    arguments.push(tokens.get(start..index)?);
                }
                return Some((arguments, index));
            }
            ")" => {
                if stack.pop() != Some("(") {
                    return None;
                }
            }
            "]" => {
                if stack.pop() != Some("[") {
                    return None;
                }
            }
            "}" => {
                if stack.pop() != Some("{") {
                    return None;
                }
            }
            "," if stack.is_empty() => {
                if index == start {
                    return None;
                }
                arguments.push(tokens.get(start..index)?);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    None
}

struct LiteralMap<'a> {
    entries: Vec<(String, &'a [Token])>,
}

impl<'a> LiteralMap<'a> {
    fn parse(tokens: &'a [Token]) -> Option<Self> {
        if tokens.first()?.text != "{" || tokens.last()?.text != "}" {
            return None;
        }
        let mut entries = Vec::new();
        let mut start = 1;
        let mut depth = 0_u64;
        for index in 1..tokens.len() - 1 {
            match tokens[index].text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth = depth.checked_sub(1)?,
                "," if depth == 0 => {
                    Self::push_entry(&mut entries, tokens.get(start..index)?)?;
                    start = index + 1;
                }
                _ => {}
            }
        }
        if start < tokens.len() - 1 {
            Self::push_entry(&mut entries, tokens.get(start..tokens.len() - 1)?)?;
        }
        Some(Self { entries })
    }

    fn push_entry(entries: &mut Vec<(String, &'a [Token])>, entry: &'a [Token]) -> Option<()> {
        if entry.len() < 3
            || !matches!(entry[0].kind, TokenKind::Identifier | TokenKind::String)
            || entry[1].text != ":"
        {
            return None;
        }
        let key = entry[0].text.to_ascii_lowercase();
        if entries.iter().any(|(existing, _)| existing == &key) {
            return None;
        }
        entries.push((key, entry.get(2..)?));
        Some(())
    }

    fn value(&self, key: &str) -> Option<&'a [Token]> {
        self.entries
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(*value))
    }

    fn has_only(&self, keys: &[&str]) -> bool {
        !self.entries.is_empty()
            && self
                .entries
                .iter()
                .all(|(key, _)| keys.contains(&key.as_str()))
    }

    fn string(&self, key: &str) -> Option<&str> {
        single_string(self.value(key)?)
    }

    fn integer(&self, key: &str) -> Option<u64> {
        single_integer(self.value(key)?)
    }

    fn boolean(&self, key: &str) -> Option<bool> {
        let value = self.value(key)?;
        if value.len() != 1 || value[0].kind != TokenKind::Identifier {
            return None;
        }
        match value[0].text.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex_cypher;

    #[test]
    fn exact_catalog_is_versioned_sorted_and_unique() {
        assert_eq!(APOC_CORE_CATALOG_VERSION, "5.26");
        assert!(SAFE_FUNCTIONS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn function_catalog_is_fail_closed_inside_known_namespaces() {
        for name in [
            "apoc.convert.fromJsonMap",
            "APOC.COLL.FLATTEN",
            "apoc.path.elements",
            "apoc.nodes.connected",
        ] {
            assert!(is_safe_function(name), "{name}");
        }
        for name in [
            "apoc.coll.futureDangerousFunction",
            "apoc.coll.combinations",
            "apoc.date.currentTimestamp",
            "apoc.map.fromNodes",
            "apoc.text.random",
            "apoc.algo.dijkstra",
        ] {
            assert!(!is_safe_function(name), "{name}");
        }
    }

    #[test]
    fn bounded_path_invocation_requires_literal_caps_and_tenant_guards() {
        let accepted = "CALL apoc.path.expandConfig(e, {relationshipFilter:'RELATION>', labelFilter:'+Entity', minLevel:1, maxLevel:6, uniqueness:'NODE_GLOBAL', bfs:true, filterStartNode:true, limit:25}) YIELD path WHERE all(node IN nodes(path) WHERE node.tenant_id = $tenant_id) AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id) RETURN path LIMIT 25";
        let tokens = lex_cypher(accepted);
        let name_index = tokens
            .iter()
            .position(|token| token.text.eq_ignore_ascii_case("apoc.path.expandConfig"))
            .expect("procedure");
        assert!(is_safe_procedure_invocation(&tokens, name_index, 100));

        for rejected in [
            accepted.replace("maxLevel:6", "maxLevel:7"),
            accepted.replace("limit:25", "limit:$limit"),
            accepted.replace("relationshipFilter:'RELATION>'", "relationshipFilter:'*'"),
            accepted.replace("NODE_GLOBAL", "RELATIONSHIP_PATH"),
            accepted.replace("rel.tenant_id = $tenant_id", "rel.tenant_id = other"),
        ] {
            let tokens = lex_cypher(&rejected);
            let name_index = tokens
                .iter()
                .position(|token| token.text.eq_ignore_ascii_case("apoc.path.expandConfig"))
                .expect("procedure");
            assert!(!is_safe_procedure_invocation(&tokens, name_index, 100));
        }
    }
}
