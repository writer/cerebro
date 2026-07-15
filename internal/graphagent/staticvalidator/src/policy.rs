use crate::lexer::{Token, TokenKind, lex_cypher, scrub_cypher};
use crate::syntax::{
    all_node_patterns_tenant_scoped, function_name_token, has_variable_length_relationship_pattern,
    keyword_token, keyword_token_at, symbol_token_at,
};
use crate::{Decision, MAX_QUERY_BYTES, Validation};

#[derive(Default)]
struct LimitScope {
    branch_limit: Option<u64>,
    max_limit: Option<u64>,
    saw_union: bool,
}

pub fn validate(query: &str, max_rows: u64) -> Validation {
    if query.len() > MAX_QUERY_BYTES {
        return Validation::refuse_with_detail(Decision::QueryTooLarge, query.len() as u64);
    }
    let query = query.trim();
    if query.is_empty() {
        return Validation::refuse(Decision::CypherRequired);
    }
    let safe_query = scrub_cypher(query);
    let tokens = lex_cypher(query);
    if has_forbidden_write_or_bulk_load(&tokens) {
        return Validation::refuse(Decision::UnsafeClause);
    }
    if has_forbidden_apoc_call(&tokens) {
        return Validation::refuse(Decision::UnsafeApoc);
    }
    if has_apoc_invocation(&tokens) {
        return Validation::refuse(Decision::ApocNotAllowed);
    }
    if has_procedure_call(&tokens) {
        return Validation::refuse(Decision::ProcedureCallNotAllowed);
    }
    if has_variable_length_relationship_pattern(&safe_query) {
        return Validation::refuse(Decision::VariableLengthRelationshipNotAllowed);
    }
    if has_forbidden_expansion(&tokens) {
        return Validation::refuse(Decision::ExpansionNotAllowed);
    }
    let Some(limit) = query_limit(&tokens) else {
        return Validation::refuse(Decision::LimitRequired);
    };
    if limit > max_rows {
        return Validation::refuse_with_detail(Decision::LimitExceeded, limit);
    }
    if let Some(oversized) = oversized_limit(&tokens, max_rows) {
        return Validation::refuse_with_detail(Decision::LimitExceeded, oversized);
    }
    if !all_node_patterns_tenant_scoped(&safe_query) {
        return Validation::refuse(Decision::TenantScopeRequired);
    }
    Validation::allow(limit)
}

fn has_forbidden_write_or_bulk_load(tokens: &[Token]) -> bool {
    for (i, token) in tokens.iter().enumerate() {
        if token.kind != TokenKind::Identifier {
            continue;
        }
        match token.text.to_ascii_uppercase().as_str() {
            "CREATE" | "MERGE" | "DELETE" | "REMOVE" | "SET" | "DROP" | "FOREACH" => return true,
            "LOAD" if keyword_token_at(tokens, i + 1, "CSV") => return true,
            "USING" if keyword_token_at(tokens, i + 1, "PERIODIC") => return true,
            _ => {}
        }
    }
    false
}

fn has_forbidden_apoc_call(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(i, token)| {
        keyword_token(token, "CALL")
            && tokens.get(i + 1).is_some_and(|procedure| {
                let procedure = procedure.text.to_ascii_lowercase();
                procedure.starts_with("apoc.trigger.") || procedure.starts_with("apoc.periodic.")
            })
    })
}

fn has_apoc_invocation(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(i, token)| {
        function_name_token(token)
            && token.text.to_ascii_lowercase().starts_with("apoc.")
            && symbol_token_at(tokens, i + 1, "(")
    })
}

fn query_limit(tokens: &[Token]) -> Option<u64> {
    let mut scopes = vec![LimitScope::default()];
    for (i, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Symbol && token.text == "{" {
            scopes.push(LimitScope::default());
            continue;
        }
        if token.kind == TokenKind::Symbol && token.text == "}" {
            if scopes.len() == 1 {
                return None;
            }
            let scope = scopes.pop()?;
            if scope.saw_union && scope.branch_limit.is_none() {
                return None;
            }
            continue;
        }
        if keyword_token(token, "LIMIT") {
            let Some(limit) = numeric_limit_at(tokens, i) else {
                continue;
            };
            let scope = scopes.last_mut()?;
            scope.branch_limit = Some(
                scope
                    .branch_limit
                    .map_or(limit, |current| current.max(limit)),
            );
            continue;
        }
        if keyword_token(token, "UNION") {
            let scope = scopes.last_mut()?;
            let branch_limit = scope.branch_limit?;
            scope.max_limit = Some(
                scope
                    .max_limit
                    .map_or(branch_limit, |current| current.max(branch_limit)),
            );
            scope.branch_limit = None;
            scope.saw_union = true;
        }
    }
    if scopes.len() != 1 {
        return None;
    }
    let scope = scopes.pop()?;
    let branch_limit = scope.branch_limit?;
    Some(
        scope
            .max_limit
            .map_or(branch_limit, |current| current.max(branch_limit)),
    )
}

fn oversized_limit(tokens: &[Token], max_rows: u64) -> Option<u64> {
    tokens.iter().enumerate().find_map(|(i, token)| {
        if !keyword_token(token, "LIMIT") {
            return None;
        }
        numeric_limit_at(tokens, i).filter(|limit| *limit > max_rows)
    })
}

fn numeric_limit_at(tokens: &[Token], limit_index: usize) -> Option<u64> {
    let value = tokens.get(limit_index + 1)?;
    if value.kind != TokenKind::Number || !limit_value_terminated(tokens, limit_index + 2) {
        return None;
    }
    u64::try_from(value.text.parse::<i64>().ok()?).ok()
}

fn limit_value_terminated(tokens: &[Token], index: usize) -> bool {
    let Some(token) = tokens.get(index) else {
        return true;
    };
    token.kind == TokenKind::Symbol && matches!(token.text.as_str(), "}" | ";")
        || token.kind == TokenKind::Identifier
            && matches!(
                token.text.to_ascii_uppercase().as_str(),
                "UNION" | "MATCH" | "OPTIONAL" | "WITH" | "RETURN" | "CALL" | "ORDER" | "SKIP"
            )
}

fn has_procedure_call(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .enumerate()
        .any(|(i, token)| keyword_token(token, "CALL") && !symbol_token_at(tokens, i + 1, "{"))
}

fn has_forbidden_expansion(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(i, token)| {
        keyword_token(token, "UNWIND")
            || function_name_token(token)
                && symbol_token_at(tokens, i + 1, "(")
                && matches!(
                    token.text.to_ascii_lowercase().as_str(),
                    "range" | "collect"
                )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_golden_cases_match_native_validator() {
        for (line_number, line) in include_str!("../testdata/abi_golden.tsv")
            .lines()
            .enumerate()
        {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 5, "line {}", line_number + 1);
            let max_rows = fields[0].parse().expect("max rows");
            let expected_decision = fields[1].parse::<u32>().expect("decision");
            let expected_limit = fields[2].parse().expect("limit");
            let expected_detail = fields[3].parse().expect("detail");
            let query = if fields[4] == "<empty>" {
                ""
            } else {
                fields[4]
            };
            let actual = validate(query, max_rows);
            assert_eq!(actual.decision as u32, expected_decision, "{query}");
            assert_eq!(actual.limit, expected_limit, "{query}");
            assert_eq!(actual.detail, expected_detail, "{query}");
        }
    }

    #[test]
    fn query_size_limit_is_inclusive_and_fails_closed() {
        let accepted = " ".repeat(MAX_QUERY_BYTES);
        assert_ne!(validate(&accepted, 100).decision, Decision::QueryTooLarge);

        let oversized = " ".repeat(MAX_QUERY_BYTES + 1);
        let result = validate(&oversized, 100);
        assert_eq!(result.decision, Decision::QueryTooLarge);
        assert_eq!(result.detail, (MAX_QUERY_BYTES + 1) as u64);
    }

    #[test]
    fn arbitrary_utf8_inputs_never_panic() {
        let mut state = 0x5eed_u64;
        for length in [0, 1, 2, 7, 31, 255, 1024, 4096] {
            for _ in 0..64 {
                let mut query = String::with_capacity(length);
                while query.len() < length {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let value = char::from_u32(((state >> 32) as u32) % 0x80).unwrap();
                    query.push(value);
                }
                assert!(std::panic::catch_unwind(|| validate(&query, 100)).is_ok());
            }
        }
    }

    #[test]
    fn abi_discriminants_are_stable() {
        let decisions = [
            Decision::Allow,
            Decision::CypherRequired,
            Decision::UnsafeClause,
            Decision::UnsafeApoc,
            Decision::ApocNotAllowed,
            Decision::ProcedureCallNotAllowed,
            Decision::VariableLengthRelationshipNotAllowed,
            Decision::ExpansionNotAllowed,
            Decision::LimitRequired,
            Decision::LimitExceeded,
            Decision::TenantScopeRequired,
            Decision::QueryTooLarge,
        ];
        for (expected, decision) in decisions.into_iter().enumerate() {
            assert_eq!(decision as usize, expected);
        }
    }

    #[test]
    fn preserves_guardrail_decisions_and_limits() {
        let cases = [
            ("", Decision::CypherRequired, 0),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) CREATE (x) RETURN e LIMIT 1",
                Decision::UnsafeClause,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) CALL apoc.periodic.iterate('a','b',{}) RETURN e LIMIT 1",
                Decision::UnsafeApoc,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN apoc.convert.fromJsonMap(e.x) LIMIT 1",
                Decision::ApocNotAllowed,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) CALL db.labels() RETURN e LIMIT 1",
                Decision::ProcedureCallNotAllowed,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id})-[r:R*]->(x:Entity {tenant_id:$tenant_id}) RETURN x LIMIT 1",
                Decision::VariableLengthRelationshipNotAllowed,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) UNWIND range(1,2) AS x RETURN e LIMIT 1",
                Decision::ExpansionNotAllowed,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e",
                Decision::LimitRequired,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 101",
                Decision::LimitExceeded,
                101,
            ),
            (
                "MATCH (e:Entity) RETURN e LIMIT 1",
                Decision::TenantScopeRequired,
                0,
            ),
            (
                "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25",
                Decision::Allow,
                0,
            ),
        ];
        for (query, decision, detail) in cases {
            let result = validate(query, 100);
            assert_eq!(result.decision, decision, "{query}");
            assert_eq!(result.detail, detail, "{query}");
        }
    }

    #[test]
    fn preserves_scope_across_projection_and_subquery() {
        let accepted = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e MATCH (e)-[:R]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) CALL { WITH e MATCH (e)-[:R]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 25 } RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, [(e)-[:`a]b`]->(c:Entity {tenant_id:$tenant_id}) | c] AS xs RETURN e LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, EXISTS { WITH e AS `}` MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } AS found RETURN e LIMIT 25",
        ];
        for query in accepted {
            assert_eq!(validate(query, 100).decision, Decision::Allow, "{query}")
        }

        let rejected = "MATCH (e:Entity {tenant_id:$tenant_id}) WITH count(*) AS n MATCH (e) RETURN e LIMIT 25";
        assert_eq!(
            validate(rejected, 100).decision,
            Decision::TenantScopeRequired
        );
    }

    #[test]
    fn comments_and_literals_cannot_hide_unsafe_tokens() {
        let query = "MATCH (a:Entity {tenant_id:$tenant_id}) WITH 'x //' AS c CREATE (b:Entity) RETURN b LIMIT 25";
        assert_eq!(validate(query, 100).decision, Decision::UnsafeClause);
        let query = "MATCH (a:Entity {tenant_id:$tenant_id}) WITH 'CREATE' AS c RETURN a LIMIT 25";
        assert_eq!(validate(query, 100).decision, Decision::Allow);
    }

    #[test]
    fn escaped_identifiers_cannot_hide_scrubbed_security_checks() {
        let variable_length = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x/*` OPTIONAL MATCH (b:Entity {tenant_id:$tenant_id})-[:R*1..9999]->(c:Entity {tenant_id:$tenant_id}) RETURN c LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x//` OPTIONAL MATCH (b:Entity {tenant_id:$tenant_id})-[:R*1..9999]->(c:Entity {tenant_id:$tenant_id}) RETURN c LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x``/*` OPTIONAL MATCH (b:Entity {tenant_id:$tenant_id})-[:R*1..9999]->(c:Entity {tenant_id:$tenant_id}) RETURN c LIMIT 1",
        ];
        for query in variable_length {
            assert_eq!(
                validate(query, 100).decision,
                Decision::VariableLengthRelationshipNotAllowed,
                "{query}"
            );
        }

        let unscoped = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x/*` OPTIONAL MATCH (b:Entity)-[:R]->(c:Entity) RETURN c LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x//` OPTIONAL MATCH (b:Entity)-[:R]->(c:Entity) RETURN c LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS `x) (b:Entity {tenant_id:$tenant_id})` MATCH (b) RETURN b LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) CALL { MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b AS `}` } MATCH (b) RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, [(e)-[:`a]b`]->(c:Entity {tenant_id:$tenant_id}) | c] AS xs MATCH (c) RETURN c LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, EXISTS { WITH e AS `}` MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } AS found MATCH (b) RETURN b LIMIT 25",
        ];
        for query in unscoped {
            assert_eq!(
                validate(query, 100).decision,
                Decision::TenantScopeRequired,
                "{query}"
            );
        }
    }

    #[test]
    fn match_keyword_adjacency_does_not_hide_node_scope() {
        let scoped = "MATCH(e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25";
        assert_eq!(validate(scoped, 100).decision, Decision::Allow);

        let queries = [
            "MATCH(e:Entity) MATCH (b:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25",
            "MATCH (b:Entity {tenant_id:$tenant_id}) OPTIONAL MATCH(e:Entity) RETURN e LIMIT 25",
        ];
        for query in queries {
            assert_eq!(
                validate(query, 100).decision,
                Decision::TenantScopeRequired,
                "{query}"
            );
        }
    }

    #[test]
    fn limit_arithmetic_is_not_a_numeric_row_bound() {
        let queries = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 2 * 1000",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 2 + 1000",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT (5)",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT (1 + 2)",
        ];
        for query in queries {
            assert_eq!(
                validate(query, 100).decision,
                Decision::LimitRequired,
                "{query}"
            );
        }
    }

    #[test]
    fn every_union_branch_requires_a_numeric_row_bound() {
        let missing_branch_limits = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e UNION MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION ALL MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b",
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION ALL MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b UNION MATCH (c:Entity {tenant_id:$tenant_id}) RETURN c LIMIT 1",
            "CALL { MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } RETURN e LIMIT 25",
            "CALL { MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 } RETURN e UNION MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
        ];
        for query in missing_branch_limits {
            assert_eq!(
                validate(query, 100).decision,
                Decision::LimitRequired,
                "{query}"
            );
        }

        let bounded = "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION ALL MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 25";
        let validation = validate(bounded, 100);
        assert_eq!(validation.decision, Decision::Allow);
        assert_eq!(validation.limit, 25);

        let oversized = "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 101 UNION MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        let validation = validate(oversized, 100);
        assert_eq!(validation.decision, Decision::LimitExceeded);
        assert_eq!(validation.detail, 101);

        let nested_bounded =
            lex_cypher("CALL { RETURN 1 LIMIT 1 UNION RETURN 2 LIMIT 2 } RETURN 1 LIMIT 25");
        assert_eq!(query_limit(&nested_bounded), Some(25));
    }

    #[test]
    fn limit_named_identifiers_do_not_hide_numeric_row_bounds() {
        let bounded = "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS limit RETURN e, limit + 1 LIMIT 100";
        let validation = validate(bounded, 100);
        assert_eq!(validation.decision, Decision::Allow);
        assert_eq!(validation.limit, 100);

        let unbounded =
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 1 AS limit RETURN e, limit + 1";
        assert_eq!(validate(unbounded, 100).decision, Decision::LimitRequired);

        let arithmetic_limit = "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 2 + 1000";
        assert_eq!(
            validate(arithmetic_limit, 100).decision,
            Decision::LimitRequired
        );
    }

    #[test]
    fn parenthesized_pattern_variables_do_not_escape_the_expression() {
        let queries = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, size((e)-[:R]->(b:Entity {tenant_id:$tenant_id})) AS count MATCH (b) RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, shortestPath((e)-[:R]->(b:Entity {tenant_id:$tenant_id})) AS path MATCH (b) RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, allShortestPaths((e)-[:R]->(b:Entity {tenant_id:$tenant_id})) AS paths MATCH (b) RETURN b LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, coalesce(size((e)-[:R]->(b:Entity {tenant_id:$tenant_id})), 0) AS count MATCH (b) RETURN b LIMIT 25",
        ];
        for query in queries {
            assert_eq!(
                validate(query, 100).decision,
                Decision::TenantScopeRequired,
                "{query}"
            );
        }

        let already_scoped = "MATCH (e:Entity {tenant_id:$tenant_id}), (b:Entity {tenant_id:$tenant_id}) WITH e, b, size((e)-[:R]->(b)) AS count RETURN b LIMIT 25";
        assert_eq!(validate(already_scoped, 100).decision, Decision::Allow);

        let anonymous = "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, size((e)-[:R]->(:Entity {tenant_id:$tenant_id})) AS count RETURN e LIMIT 25";
        assert_eq!(validate(anonymous, 100).decision, Decision::Allow);
    }

    #[test]
    fn expression_local_with_aliases_do_not_escape_the_expression() {
        let queries = [
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, EXISTS { WITH e AS x MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } AS found MATCH (x) RETURN x LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, COUNT { WITH e AS x MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } AS n MATCH (x) RETURN x LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, COLLECT { WITH e AS x MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b } AS xs MATCH (x) RETURN x LIMIT 25",
        ];
        for query in queries {
            assert_eq!(
                validate(query, 100).decision,
                Decision::TenantScopeRequired,
                "{query}"
            );
        }
    }

    #[test]
    fn relationship_bracket_matching_tracks_nested_lists_and_fails_closed() {
        let bypass = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R*1..9999 {x:[1]}]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(
            validate(bypass, 100).decision,
            Decision::VariableLengthRelationshipNotAllowed
        );

        let finite = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R {x:[1]}]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(validate(finite, 100).decision, Decision::Allow);

        let unclosed = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R {x:[1]} RETURN a LIMIT 1";
        assert_eq!(
            validate(unclosed, 100).decision,
            Decision::VariableLengthRelationshipNotAllowed
        );
    }

    #[test]
    fn escaped_relationship_types_cannot_hide_variable_length_traversals() {
        let fixed_length = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:`R]`]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(validate(fixed_length, 100).decision, Decision::Allow);
        let fixed_star = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:`R*`]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(validate(fixed_star, 100).decision, Decision::Allow);

        let variable_length = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:`R]`*1..9999]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(
            validate(variable_length, 100).decision,
            Decision::VariableLengthRelationshipNotAllowed
        );
        let variable_star = "MATCH (a:Entity {tenant_id:$tenant_id})-[r:`R*`*1..9999]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(
            validate(variable_star, 100).decision,
            Decision::VariableLengthRelationshipNotAllowed
        );
    }

    #[test]
    fn node_patterns_accept_nested_property_syntax_without_weakening_scope() {
        let accepted = [
            "MATCH (e:Entity {tenant_id:$tenant_id, id: toString($id)}) RETURN e LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id, meta: {key: 'val'}}) RETURN e LIMIT 25",
            "MATCH (e:`Entity` {tenant_id:$tenant_id, meta: {key: 'val'}}) RETURN e LIMIT 25",
        ];
        for query in accepted {
            assert_eq!(validate(query, 100).decision, Decision::Allow, "{query}");
        }

        for query in [
            "MATCH (e:Entity {meta: {tenant_id:$tenant_id}}) RETURN e LIMIT 25",
            "MATCH (e:Entity {tenant_id:$tenant_id, id: toString($id)}) MATCH (b:Entity) RETURN b LIMIT 25",
            "MATCH (e:`Not:Entity` {tenant_id:$tenant_id}) RETURN e LIMIT 25",
        ] {
            assert_eq!(
                validate(query, 100).decision,
                Decision::TenantScopeRequired,
                "{query}"
            );
        }
    }

    #[test]
    fn quantified_relationships_are_variable_length_traversals() {
        let fixed_length = "MATCH (a:Entity {tenant_id:$tenant_id})-->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_eq!(validate(fixed_length, 100).decision, Decision::Allow);

        let queries = [
            "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R]->{1,9999}(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R]->+(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R]->*(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})-[r:R]->?(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})-->{1,9999}(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})--+(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})-->?(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})<--*(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
            "MATCH (a:Entity {tenant_id:$tenant_id})<--?(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1",
        ];
        for query in queries {
            assert_eq!(
                validate(query, 100).decision,
                Decision::VariableLengthRelationshipNotAllowed,
                "{query}"
            );
        }
    }

    #[test]
    fn quantified_path_patterns_fail_closed() {
        let query = "MATCH (a:Entity {tenant_id:$tenant_id}) ((x:Entity {tenant_id:$tenant_id})-[r:R]->(y:Entity {tenant_id:$tenant_id})){1,9999} (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 1";
        assert_ne!(validate(query, 100).decision, Decision::Allow);
    }

    #[test]
    fn non_ascii_input_fails_closed_without_panicking() {
        let query = "MATCH (é:Entity {tenant_id:$tenant_id}) RETURN é LIMIT 1";
        assert_eq!(validate(query, 100).decision, Decision::TenantScopeRequired);
    }
}
