use cerebro_graphagent_staticvalidator::{ABI_VERSION, Decision, MAX_QUERY_BYTES, validate};

const MAX_ROWS: u64 = 100;
const KEYWORDS: &[&str] = &[
    "ALL", "AS", "CALL", "COLLECT", "CREATE", "CSV", "DELETE", "DROP", "EXISTS", "FOREACH",
    "LIMIT", "LOAD", "MATCH", "MERGE", "OPTIONAL", "ORDER", "PERIODIC", "REMOVE", "RETURN", "SET",
    "SKIP", "UNION", "UNWIND", "USING", "WITH",
];

#[test]
fn arbitrary_utf8_never_panics() {
    let mut state = 0x7a11_da7a_f022_u64;
    for length in [0, 1, 2, 7, 31, 255, 1024, 4096] {
        for _ in 0..64 {
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                bytes.push((state >> 32) as u8);
            }
            let query = String::from_utf8_lossy(&bytes);
            assert!(
                std::panic::catch_unwind(|| validate(&query, MAX_ROWS)).is_ok(),
                "validator panicked for deterministic input of {length} bytes"
            );
        }
    }

    let maximum = " ".repeat(MAX_QUERY_BYTES);
    assert!(std::panic::catch_unwind(|| validate(&maximum, MAX_ROWS)).is_ok());
    let oversized = format!("{maximum}x");
    assert!(std::panic::catch_unwind(|| validate(&oversized, MAX_ROWS)).is_ok());
}

#[test]
fn safe_formatting_cannot_weaken_refusals() {
    let refused = [
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) CREATE (x:Entity) RETURN e LIMIT 1",
            Decision::UnsafeClause,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) CALL apoc.periodic.iterate('a','b',{}) RETURN e LIMIT 1",
            Decision::UnsafeApoc,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN apoc.convert.fromJsonMap(e.data) LIMIT 1",
            Decision::ApocNotAllowed,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) CALL db.labels() RETURN e LIMIT 1",
            Decision::ProcedureCallNotAllowed,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id})-[r:R*]->(x:Entity {tenant_id:$tenant_id}) RETURN x LIMIT 1",
            Decision::VariableLengthRelationshipNotAllowed,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) UNWIND range(1,2) AS item RETURN e LIMIT 1",
            Decision::ExpansionNotAllowed,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e",
            Decision::LimitRequired,
        ),
        (
            "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 101",
            Decision::LimitExceeded,
        ),
        (
            "MATCH (e:Entity) RETURN e LIMIT 1",
            Decision::TenantScopeRequired,
        ),
    ];

    for (query, expected) in refused {
        for variant in safe_format_variants(query) {
            assert_eq!(validate(&variant, MAX_ROWS).decision, expected, "{variant}");
        }
    }
}

#[test]
fn accepted_queries_are_stable_under_safe_formatting() {
    let accepted = [
        "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25",
        "MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 1 UNION ALL MATCH (b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 25",
        "MATCH (e:Entity {tenant_id:$tenant_id}) CALL { WITH e MATCH (e)-[:R]->(b:Entity {tenant_id:$tenant_id}) RETURN b LIMIT 10 } RETURN b LIMIT 25",
    ];

    for query in accepted {
        let baseline = validate(query, MAX_ROWS);
        assert_eq!(baseline.decision, Decision::Allow, "{query}");
        for variant in safe_format_variants(query) {
            let actual = validate(&variant, MAX_ROWS);
            assert_eq!(actual.decision, Decision::Allow, "{variant}");
            assert_eq!(actual.limit, baseline.limit, "{variant}");
            assert_eq!(actual.detail, baseline.detail, "{variant}");
        }
    }
}

#[test]
fn literal_contents_do_not_change_policy_decisions() {
    let accepted =
        "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 'safe literal' AS note RETURN e LIMIT 25";
    let refused = "MATCH (e:Entity {tenant_id:$tenant_id}) WITH e, 'safe literal' AS note CREATE (x:Entity) RETURN e LIMIT 25";
    for replacement in [
        "CREATE DELETE CALL apoc.periodic.iterate",
        "/* MATCH (x:Entity) */ // RETURN LIMIT 9999",
        "''quoted'' \\ escaped",
    ] {
        let accepted_variant = accepted.replace("safe literal", replacement);
        assert_eq!(
            validate(&accepted_variant, MAX_ROWS).decision,
            Decision::Allow,
            "{accepted_variant}"
        );
        let refused_variant = refused.replace("safe literal", replacement);
        assert_eq!(
            validate(&refused_variant, MAX_ROWS).decision,
            Decision::UnsafeClause,
            "{refused_variant}"
        );
    }
}

#[test]
fn raising_max_rows_preserves_an_allowed_query_and_its_limit() {
    for limit in [0, 1, 25, 100, 101, 1_000, u32::MAX as u64] {
        let query = format!("MATCH (e:Entity {{tenant_id:$tenant_id}}) RETURN e LIMIT {limit}");
        for maximum in [0, 1, 25, 100, 101, 1_000, u32::MAX as u64, u64::MAX] {
            let result = validate(&query, maximum);
            if maximum < limit {
                assert_eq!(result.decision, Decision::LimitExceeded, "{query}");
                assert_eq!(result.detail, limit, "{query}");
                continue;
            }
            assert_eq!(result.decision, Decision::Allow, "{query}");
            assert_eq!(result.limit, limit, "{query}");
            for raised in [maximum, maximum.saturating_add(1), u64::MAX] {
                let raised_result = validate(&query, raised);
                assert_eq!(raised_result.decision, Decision::Allow, "{query}");
                assert_eq!(raised_result.limit, limit, "{query}");
            }
        }
    }
}

#[test]
fn abi_version_and_decision_discriminants_are_stable() {
    assert_eq!(ABI_VERSION, 2);
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

fn safe_format_variants(query: &str) -> [String; 3] {
    [
        transform_keywords(query, KeywordTransform::AlternatingCase),
        transform_whitespace(query),
        transform_keywords(query, KeywordTransform::TrailingComment),
    ]
}

#[derive(Clone, Copy)]
enum KeywordTransform {
    AlternatingCase,
    TrailingComment,
}

fn transform_keywords(query: &str, transform: KeywordTransform) -> String {
    let bytes = query.as_bytes();
    let mut output = String::with_capacity(query.len() + 64);
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            cursor = copy_quoted(query, cursor, &mut output);
            continue;
        }
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'_' | b'.'))
            {
                cursor += 1;
            }
            let word = &query[start..cursor];
            if KEYWORDS
                .iter()
                .any(|keyword| word.eq_ignore_ascii_case(keyword))
            {
                match transform {
                    KeywordTransform::AlternatingCase => {
                        for (index, byte) in word.bytes().enumerate() {
                            output.push(char::from(if index % 2 == 0 {
                                byte.to_ascii_lowercase()
                            } else {
                                byte.to_ascii_uppercase()
                            }));
                        }
                    }
                    KeywordTransform::TrailingComment => {
                        output.push_str(word);
                        output.push_str("/*property*/");
                    }
                }
            } else {
                output.push_str(word);
            }
            continue;
        }
        output.push(char::from(bytes[cursor]));
        cursor += 1;
    }
    output
}

fn transform_whitespace(query: &str) -> String {
    let bytes = query.as_bytes();
    let mut output = String::with_capacity(query.len() * 2);
    let mut cursor = 0;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\'' | b'"' | b'`') {
            cursor = copy_quoted(query, cursor, &mut output);
            continue;
        }
        if bytes[cursor] == b' ' {
            output.push_str(" \n\t");
        } else {
            output.push(char::from(bytes[cursor]));
        }
        cursor += 1;
    }
    output
}

fn copy_quoted(query: &str, start: usize, output: &mut String) -> usize {
    let bytes = query.as_bytes();
    let quote = bytes[start];
    let mut cursor = start;
    output.push(char::from(bytes[cursor]));
    cursor += 1;
    while cursor < bytes.len() {
        output.push(char::from(bytes[cursor]));
        if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
            cursor += 1;
            output.push(char::from(bytes[cursor]));
        } else if bytes[cursor] == quote {
            if cursor + 1 < bytes.len() && bytes[cursor + 1] == quote {
                cursor += 1;
                output.push(char::from(bytes[cursor]));
            } else {
                return cursor + 1;
            }
        }
        cursor += 1;
    }
    cursor
}
