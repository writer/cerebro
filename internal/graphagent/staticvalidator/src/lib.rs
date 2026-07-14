use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

pub const ABI_VERSION: u32 = 1;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow = 0,
    CypherRequired = 1,
    UnsafeClause = 2,
    UnsafeApoc = 3,
    ApocNotAllowed = 4,
    ProcedureCallNotAllowed = 5,
    VariableLengthRelationshipNotAllowed = 6,
    ExpansionNotAllowed = 7,
    LimitRequired = 8,
    LimitExceeded = 9,
    TenantScopeRequired = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validation {
    pub decision: Decision,
    pub limit: u64,
    pub detail: u64,
}

impl Validation {
    const fn allow(limit: u64) -> Self {
        Self {
            decision: Decision::Allow,
            limit,
            detail: 0,
        }
    }

    const fn refuse(decision: Decision) -> Self {
        Self {
            decision,
            limit: 0,
            detail: 0,
        }
    }

    const fn refuse_with_detail(decision: Decision, detail: u64) -> Self {
        Self {
            decision,
            limit: 0,
            detail,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier,
    EscapedIdentifier,
    Number,
    Symbol,
    Parameter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    text: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NodePattern {
    variable: String,
    labels: String,
    properties: String,
}

#[derive(Clone, Debug)]
struct SubqueryScope {
    outer: HashSet<String>,
    imports: HashSet<String>,
    body_start: usize,
    end: usize,
}

pub fn validate(query: &str, max_rows: u64) -> Validation {
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

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_abi_version() -> u32 {
    ABI_VERSION
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_alloc(length: u32) -> u32 {
    let mut bytes = vec![0_u8; length as usize];
    let pointer = bytes.as_mut_ptr() as usize;
    std::mem::forget(bytes);
    u32::try_from(pointer).unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_validate(
    query_pointer: u32,
    query_length: u32,
    max_rows: u64,
    result_pointer: u32,
) -> u32 {
    let query_start = query_pointer as usize;
    let result_start = result_pointer as usize;
    let Some(query_end) = query_start.checked_add(query_length as usize) else {
        return 1;
    };
    let Some(result_end) = result_start.checked_add(24) else {
        return 1;
    };
    let memory_size = core::arch::wasm32::memory_size(0) * 65_536;
    if query_end > memory_size || result_end > memory_size {
        return 1;
    }

    // SAFETY: Both ranges were checked against the current linear-memory size. The host allocates
    // disjoint query and result ranges through cerebro_validator_alloc before invoking this export.
    let query_bytes =
        unsafe { std::slice::from_raw_parts(query_pointer as *const u8, query_length as usize) };
    let Ok(query) = std::str::from_utf8(query_bytes) else {
        return 1;
    };
    let validation = validate(query, max_rows);
    let mut result = [0_u8; 24];
    result[0..4].copy_from_slice(&(validation.decision as u32).to_le_bytes());
    result[8..16].copy_from_slice(&validation.limit.to_le_bytes());
    result[16..24].copy_from_slice(&validation.detail.to_le_bytes());
    // SAFETY: result_pointer..result_pointer+24 was checked against linear memory above.
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_pointer as *mut u8, result.len())
    };
    0
}

fn scrub_cypher(query: &str) -> String {
    let bytes = query.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                output.extend_from_slice(b"''");
                i = skip_quoted_literal(bytes, i, bytes[i]) + 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                output.push(b' ');
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                output.push(b' ');
                i += 2;
                while i + 1 < bytes.len() && (bytes[i] != b'*' || bytes[i + 1] != b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            byte => {
                output.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(output).expect("scrubbing preserves UTF-8")
}

fn skip_quoted_literal(query: &[u8], start: usize, quote: u8) -> usize {
    let mut i = start + 1;
    while i < query.len() {
        if query[i] == b'\\' && i + 1 < query.len() {
            i += 2;
            continue;
        }
        if query[i] == quote {
            if i + 1 < query.len() && query[i + 1] == quote {
                i += 2;
                continue;
            }
            return i;
        }
        i += 1;
    }
    query.len().saturating_sub(1)
}

fn lex_cypher(query: &str) -> Vec<Token> {
    let bytes = query.as_bytes();
    let mut tokens = Vec::with_capacity(bytes.len() / 4);
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        if is_whitespace(ch) {
            i += 1;
        } else if ch == b'\'' || ch == b'"' {
            i = skip_quoted_literal(bytes, i, ch) + 1;
        } else if ch == b'`' {
            let (text, end) = escaped_identifier_token(bytes, i);
            tokens.push(Token {
                kind: TokenKind::EscapedIdentifier,
                text,
            });
            i = end + 1;
        } else if ch == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
        } else if ch == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && (bytes[i] != b'*' || bytes[i + 1] != b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if ch == b'$' {
            let start = i;
            i += 1;
            while i < bytes.len() && is_identifier_byte(bytes[i]) {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Parameter,
                text: query[start..i].to_owned(),
            });
        } else if is_identifier_start(ch) {
            let start = i;
            while i < bytes.len() && (is_identifier_byte(bytes[i]) || bytes[i] == b'.') {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Identifier,
                text: query[start..i].to_owned(),
            });
        } else if ch.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Number,
                text: query[start..i].to_owned(),
            });
        } else {
            tokens.push(Token {
                kind: TokenKind::Symbol,
                text: char::from(ch).to_string(),
            });
            i += 1;
        }
    }
    tokens
}

fn escaped_identifier_token(query: &[u8], start: usize) -> (String, usize) {
    let mut output = Vec::new();
    let mut i = start + 1;
    while i < query.len() {
        if query[i] == b'`' {
            if i + 1 < query.len() && query[i + 1] == b'`' {
                output.push(b'`');
                i += 2;
                continue;
            }
            return (String::from_utf8_lossy(&output).into_owned(), i);
        }
        output.push(query[i]);
        i += 1;
    }
    (
        String::from_utf8_lossy(&output).into_owned(),
        query.len().saturating_sub(1),
    )
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
    let mut limit = None;
    for (i, token) in tokens.iter().enumerate() {
        if keyword_token(token, "LIMIT") {
            let value = tokens.get(i + 1)?;
            if value.kind != TokenKind::Number {
                return None;
            }
            limit = Some(u64::try_from(value.text.parse::<i64>().ok()?).ok()?);
        }
    }
    limit
}

fn oversized_limit(tokens: &[Token], max_rows: u64) -> Option<u64> {
    tokens.iter().enumerate().find_map(|(i, token)| {
        if !keyword_token(token, "LIMIT") {
            return None;
        }
        let value = tokens.get(i + 1)?;
        if value.kind != TokenKind::Number {
            return None;
        }
        u64::try_from(value.text.parse::<i64>().ok()?)
            .ok()
            .filter(|limit| *limit > max_rows)
    })
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

fn has_variable_length_relationship_pattern(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'[' || !relationship_dash_before(bytes, i) {
            i += 1;
            continue;
        }
        let Some(close) = matching_square_bracket(bytes, i) else {
            return true;
        };
        if relationship_dash_after(bytes, close) && bytes[i + 1..close].contains(&b'*') {
            return true;
        }
        i = close + 1;
    }
    false
}

fn matching_square_bracket(query: &[u8], open: usize) -> Option<usize> {
    let mut depth = 1;
    for (index, byte) in query.iter().enumerate().skip(open + 1) {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn relationship_dash_before(query: &[u8], index: usize) -> bool {
    query[..index]
        .iter()
        .rev()
        .find(|byte| !is_whitespace(**byte))
        .is_some_and(|byte| *byte == b'-')
}

fn relationship_dash_after(query: &[u8], index: usize) -> bool {
    query[index + 1..]
        .iter()
        .find(|byte| !is_whitespace(**byte))
        .is_some_and(|byte| *byte == b'-')
}

fn all_node_patterns_tenant_scoped(query: &str) -> bool {
    if !match_clauses_contain_only_node_patterns(query) {
        return false;
    }
    let mut scoped = HashSet::new();
    let mut pending_call_imports: Option<HashSet<String>> = None;
    let mut subqueries: Vec<SubqueryScope> = Vec::new();
    let mut saw_node = false;
    let mut i = 0;
    while i < query.len() {
        if subqueries.last().is_some_and(|scope| i == scope.end) {
            let current = subqueries.pop().expect("subquery exists");
            scoped = merge_scoped_variables(
                &current.outer,
                &scoped_variables_after_return(&query[current.body_start..current.end], &scoped),
            );
            pending_call_imports = None;
            i += 1;
            continue;
        }
        if keyword_at(query, i, "CALL") {
            let Some(brace) = subquery_start_brace(query, i + 4) else {
                return false;
            };
            let Some(end) = matching_brace(query, brace) else {
                return false;
            };
            let imports = scoped.clone();
            pending_call_imports = Some(imports.clone());
            subqueries.push(SubqueryScope {
                outer: imports.clone(),
                imports,
                body_start: brace + 1,
                end,
            });
            scoped.clear();
            i += 4;
            continue;
        }
        if keyword_at(query, i, "WITH") {
            let base = pending_call_imports.as_ref().unwrap_or(&scoped);
            scoped = scoped_variables_after_with(query, i + 4, base);
            pending_call_imports = None;
            i += 4;
            continue;
        }
        if pending_call_imports.is_some() && !is_whitespace_or_subquery_start(query.as_bytes()[i]) {
            pending_call_imports = None;
        }
        if keyword_at(query, i, "UNION") {
            scoped.clear();
            pending_call_imports = subqueries.last().map(|scope| scope.imports.clone());
            i += 5;
            continue;
        }
        let (pattern, found, valid) = node_pattern_at(query, i);
        if !found {
            i += 1;
            continue;
        }
        if !valid {
            return false;
        }
        saw_node = true;
        if node_pattern_has_inline_tenant_scope(&pattern) {
            if !pattern.variable.is_empty() && !expression_local_pattern(query, i, subqueries.len())
            {
                scoped.insert(pattern.variable);
            }
            i += 1;
            continue;
        }
        if pattern.is_bare_variable_reference() && scoped.contains(&pattern.variable) {
            i += 1;
            continue;
        }
        return false;
    }
    saw_node
}

fn match_clause_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(r"(?i-u:\b(?:OPTIONAL\s+MATCH|MATCH)\b)").expect("valid regex"))
}

fn match_clause_end_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(r"(?i-u:\b(?:WHERE|RETURN|WITH|ORDER\s+BY|LIMIT|UNWIND|CALL|UNION|CREATE|MERGE|DELETE|SET|REMOVE|DROP|FOREACH)\b)").expect("valid regex"))
}

fn node_body_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| Regex::new(r"^[ \t\r\n\f]*([A-Za-z_][A-Za-z0-9_]*)?[ \t\r\n\f]*((?::[ \t\r\n\f]*[A-Za-z_][A-Za-z0-9_]*)*)[ \t\r\n\f]*(\{[^{}]*\})?[ \t\r\n\f]*$").expect("valid regex"))
}

fn inline_tenant_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE
        .get_or_init(|| Regex::new(r"(?i-u:\btenant_id\s*:\s*\$tenant_id\b)").expect("valid regex"))
}

fn match_clauses_contain_only_node_patterns(query: &str) -> bool {
    let clauses: Vec<_> = match_clause_pattern().find_iter(query).collect();
    for (index, clause) in clauses.iter().enumerate() {
        let start = clause.end();
        let mut end = clauses
            .get(index + 1)
            .map_or(query.len(), regex::Match::start);
        if let Some(boundary) = match_clause_end_pattern().find(&query[start..end]) {
            end = start + boundary.start();
        }
        if !node_patterns_in_text(&query[start..end], true).1 {
            return false;
        }
    }
    true
}

fn node_patterns_in_text(text: &str, require_valid: bool) -> (Vec<NodePattern>, bool) {
    let bytes = text.as_bytes();
    let mut patterns = Vec::new();
    for i in 0..bytes.len() {
        if bytes[i] != b'(' || i > 0 && is_identifier_byte(bytes[i - 1]) {
            continue;
        }
        let Some(close) = bytes[i + 1..].iter().position(|byte| *byte == b')') else {
            return (Vec::new(), !require_valid);
        };
        let body = &text[i + 1..i + 1 + close];
        let Some(pattern) = parse_node_pattern(body) else {
            if require_valid {
                return (Vec::new(), false);
            }
            continue;
        };
        patterns.push(pattern);
    }
    (patterns, true)
}

fn node_pattern_at(text: &str, index: usize) -> (NodePattern, bool, bool) {
    let bytes = text.as_bytes();
    if bytes[index] != b'(' || index > 0 && is_identifier_byte(bytes[index - 1]) {
        return (NodePattern::default(), false, false);
    }
    let Some(close) = bytes[index + 1..].iter().position(|byte| *byte == b')') else {
        return (NodePattern::default(), true, false);
    };
    parse_node_pattern(&text[index + 1..index + 1 + close])
        .map_or((NodePattern::default(), true, false), |pattern| {
            (pattern, true, true)
        })
}

fn parse_node_pattern(body: &str) -> Option<NodePattern> {
    let captures = node_body_pattern().captures(body)?;
    Some(NodePattern {
        variable: captures
            .get(1)
            .map_or("", |value| value.as_str())
            .trim()
            .to_owned(),
        labels: captures
            .get(2)
            .map_or("", |value| value.as_str())
            .to_owned(),
        properties: captures
            .get(3)
            .map_or("", |value| value.as_str())
            .to_owned(),
    })
}

fn node_pattern_has_inline_tenant_scope(pattern: &NodePattern) -> bool {
    node_has_entity_label(&pattern.labels) && inline_tenant_pattern().is_match(&pattern.properties)
}

impl NodePattern {
    fn is_bare_variable_reference(&self) -> bool {
        !self.variable.is_empty()
            && self.labels.trim().is_empty()
            && self.properties.trim().is_empty()
    }
}

fn node_has_entity_label(labels: &str) -> bool {
    labels
        .split(':')
        .any(|label| label.trim().eq_ignore_ascii_case("Entity"))
}

fn subquery_start_brace(query: &str, start: usize) -> Option<usize> {
    query
        .as_bytes()
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(i, byte)| {
            if is_whitespace(*byte) {
                None
            } else if *byte == b'{' {
                Some(i)
            } else {
                Some(usize::MAX)
            }
        })
        .filter(|index| *index != usize::MAX)
}

fn matching_brace(query: &str, start: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, byte) in query.as_bytes().iter().enumerate().skip(start) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn scoped_variables_after_with(
    query: &str,
    start: usize,
    scoped: &HashSet<String>,
) -> HashSet<String> {
    projected_variables(&query[start..with_projection_end(query, start)], scoped)
}

fn scoped_variables_after_return(query: &str, scoped: &HashSet<String>) -> HashSet<String> {
    let Some(start) = last_keyword_index(query, "RETURN") else {
        return HashSet::new();
    };
    let start = start + 6;
    projected_variables(&query[start..with_projection_end(query, start)], scoped)
}

fn projected_variables(clause: &str, scoped: &HashSet<String>) -> HashSet<String> {
    let mut next = HashSet::new();
    for item in split_projection_items(clause) {
        project_scoped_variable(&mut next, scoped, item.trim());
    }
    next
}

fn last_keyword_index(query: &str, keyword: &str) -> Option<usize> {
    let mut result = None;
    let mut i = 0;
    while i < query.len() {
        if keyword_at(query, i, keyword) {
            result = Some(i);
            i += keyword.len();
        } else {
            i += 1
        }
    }
    result
}

fn merge_scoped_variables(left: &HashSet<String>, right: &HashSet<String>) -> HashSet<String> {
    left.union(right).cloned().collect()
}

fn with_projection_end(query: &str, start: usize) -> usize {
    let mut depth = 0;
    for i in start..query.len() {
        match query.as_bytes()[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            _ => {}
        }
        if depth == 0 && with_clause_end_at(query, i) {
            return i;
        }
    }
    query.len()
}

fn with_clause_end_at(query: &str, index: usize) -> bool {
    [
        "OPTIONAL MATCH",
        "MATCH",
        "RETURN",
        "UNION",
        "CALL",
        "WHERE",
        "ORDER",
        "LIMIT",
        "SKIP",
    ]
    .iter()
    .any(|keyword| keyword_at(query, index, keyword))
}

fn split_projection_items(clause: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, byte) in clause.as_bytes().iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            b',' if depth == 0 => {
                items.push(&clause[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&clause[start..]);
    items
}

fn project_scoped_variable(next: &mut HashSet<String>, scoped: &HashSet<String>, item: &str) {
    let item = trim_leading_keyword(item, "DISTINCT");
    if item == "*" {
        next.extend(scoped.iter().cloned());
        return;
    }
    let fields: Vec<_> = item.split_whitespace().collect();
    if fields.len() == 1 && scoped.contains(fields[0]) {
        next.insert(fields[0].to_owned());
    } else if fields.len() == 3
        && fields[1].eq_ignore_ascii_case("AS")
        && scoped.contains(fields[0])
    {
        next.insert(fields[2].to_owned());
    }
}

fn trim_leading_keyword<'a>(text: &'a str, keyword: &str) -> &'a str {
    let text = text.trim();
    if keyword_at(text, 0, keyword) {
        text[keyword.len()..].trim()
    } else {
        text
    }
}

fn keyword_at(query: &str, index: usize, keyword: &str) -> bool {
    let bytes = query.as_bytes();
    if index + keyword.len() > bytes.len()
        || !bytes[index..index + keyword.len()].eq_ignore_ascii_case(keyword.as_bytes())
    {
        return false;
    }
    if index > 0 && is_identifier_byte(bytes[index - 1]) {
        return false;
    }
    let next = index + keyword.len();
    next >= bytes.len() || !is_identifier_byte(bytes[next])
}

fn keyword_token_at(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| keyword_token(token, keyword))
}

fn keyword_token(token: &Token, keyword: &str) -> bool {
    token.kind == TokenKind::Identifier && token.text.eq_ignore_ascii_case(keyword)
}

fn function_name_token(token: &Token) -> bool {
    matches!(
        token.kind,
        TokenKind::Identifier | TokenKind::EscapedIdentifier
    )
}

fn symbol_token_at(tokens: &[Token], index: usize, symbol: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.kind == TokenKind::Symbol && token.text == symbol)
}

fn is_whitespace_or_subquery_start(value: u8) -> bool {
    is_whitespace(value) || value == b'{'
}
fn is_whitespace(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\n' | b'\r')
}
fn is_identifier_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}
fn is_identifier_start(value: u8) -> bool {
    value.is_ascii_alphabetic() || value == b'_'
}

fn square_bracket_depth_at(query: &str, index: usize) -> usize {
    let mut depth = 0;
    for byte in &query.as_bytes()[..index] {
        match byte {
            b'[' => depth += 1,
            b']' if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn brace_depth_at(query: &str, index: usize) -> usize {
    let mut depth = 0;
    for byte in &query.as_bytes()[..index] {
        match byte {
            b'{' => depth += 1,
            b'}' if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn expression_local_pattern(query: &str, index: usize, call_subquery_depth: usize) -> bool {
    square_bracket_depth_at(query, index) > 0 || brace_depth_at(query, index) > call_subquery_depth
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn non_ascii_input_fails_closed_without_panicking() {
        let query = "MATCH (é:Entity {tenant_id:$tenant_id}) RETURN é LIMIT 1";
        assert_eq!(validate(query, 100).decision, Decision::TenantScopeRequired);
    }
}
