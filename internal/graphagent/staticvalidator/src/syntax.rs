use crate::lexer::{Token, TokenKind, escaped_identifier_token, lex_cypher};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

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

pub(crate) fn has_variable_length_relationship_pattern(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'[' || !relationship_dash_before(bytes, i) {
            i += 1;
            continue;
        }
        let Some(close) = matching_delimiter(bytes, i, b'[', b']') else {
            return true;
        };
        let Some(relationship_end) = relationship_end_after(bytes, close) else {
            i = close + 1;
            continue;
        };
        if relationship_body_has_quantifier(bytes, i + 1, close)
            || has_postfix_pattern_quantifier(bytes, relationship_end)
        {
            return true;
        }
        i = close + 1;
    }
    has_quantified_abbreviated_relationship(query)
}

fn relationship_body_has_quantifier(query: &[u8], start: usize, end: usize) -> bool {
    let mut cursor = start;
    while cursor < end {
        if query[cursor] == b'`' {
            let (_, escaped_end) = escaped_identifier_token(query, cursor);
            if escaped_end >= end || query[escaped_end] != b'`' {
                return true;
            }
            cursor = escaped_end + 1;
            continue;
        }
        if query[cursor] == b'*' {
            return true;
        }
        cursor += 1;
    }
    false
}

fn matching_delimiter(query: &[u8], open: usize, opening: u8, closing: u8) -> Option<usize> {
    if query.get(open) != Some(&opening) {
        return None;
    }
    let mut depth = 1;
    let mut cursor = open + 1;
    while cursor < query.len() {
        if query[cursor] == b'`' {
            let (_, end) = escaped_identifier_token(query, cursor);
            if end <= cursor || query.get(end) != Some(&b'`') {
                return None;
            }
            cursor = end + 1;
            continue;
        }
        if query[cursor] == opening {
            depth += 1;
        } else if query[cursor] == closing {
            depth -= 1;
            if depth == 0 {
                return Some(cursor);
            }
        }
        cursor += 1;
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

fn relationship_end_after(query: &[u8], index: usize) -> Option<usize> {
    let dash = query[index + 1..]
        .iter()
        .position(|byte| !is_whitespace(*byte))?
        + index
        + 1;
    if query[dash] != b'-' {
        return None;
    }
    let Some(next) = next_non_whitespace_index(query, dash + 1) else {
        return Some(dash);
    };
    Some(if query[next] == b'>' { next } else { dash })
}

fn has_postfix_pattern_quantifier(query: &[u8], pattern_end: usize) -> bool {
    next_non_whitespace_index(query, pattern_end + 1)
        .is_some_and(|index| matches!(query[index], b'*' | b'+' | b'?' | b'{'))
}

fn has_quantified_abbreviated_relationship(query: &str) -> bool {
    let bytes = query.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b')' {
            return false;
        }
        let Some(start) = next_non_whitespace_index(bytes, index + 1) else {
            return false;
        };
        let relationship_end = match bytes[start] {
            b'-' => {
                let Some(second_dash) = next_non_whitespace_index(bytes, start + 1) else {
                    return false;
                };
                if bytes[second_dash] != b'-' {
                    return false;
                }
                next_non_whitespace_index(bytes, second_dash + 1)
                    .filter(|next| bytes[*next] == b'>')
                    .unwrap_or(second_dash)
            }
            b'<' => {
                let Some(first_dash) = next_non_whitespace_index(bytes, start + 1) else {
                    return false;
                };
                let Some(second_dash) = next_non_whitespace_index(bytes, first_dash + 1) else {
                    return false;
                };
                if bytes[first_dash] != b'-' || bytes[second_dash] != b'-' {
                    return false;
                }
                second_dash
            }
            _ => return false,
        };
        has_postfix_pattern_quantifier(bytes, relationship_end)
    })
}

fn next_non_whitespace_index(query: &[u8], start: usize) -> Option<usize> {
    query
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, byte)| (!is_whitespace(*byte)).then_some(index))
}

pub(crate) fn all_node_patterns_tenant_scoped(query: &str) -> bool {
    if !match_clauses_contain_only_node_patterns(query) {
        return false;
    }
    let mut scoped = HashSet::new();
    let mut pending_call_imports: Option<HashSet<String>> = None;
    let mut subqueries: Vec<SubqueryScope> = Vec::new();
    let mut paren_function_context = Vec::new();
    let mut saw_node = false;
    let mut i = 0;
    while i < query.len() {
        if query.as_bytes()[i] == b'`' {
            let (_, end) = escaped_identifier_token(query.as_bytes(), i);
            i = end + 1;
            continue;
        }
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
            if expression_local_pattern(query, i, subqueries.len()) {
                i += 4;
                continue;
            }
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
            match query.as_bytes()[i] {
                b'(' => {
                    let inside_function = paren_function_context.last().copied().unwrap_or(false)
                        || function_call_open_at(query, i);
                    paren_function_context.push(inside_function);
                }
                b')' => {
                    paren_function_context.pop();
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        if !valid {
            return false;
        }
        saw_node = true;
        let inside_function = paren_function_context.last().copied().unwrap_or(false);
        paren_function_context.push(inside_function);
        if node_pattern_has_inline_tenant_scope(&pattern) {
            if !pattern.variable.is_empty() {
                if inside_function && !scoped.contains(&pattern.variable) {
                    return false;
                }
                if !inside_function && !expression_local_pattern(query, i, subqueries.len()) {
                    scoped.insert(pattern.variable);
                }
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
    VALUE.get_or_init(|| Regex::new(r"(?s)^[ \t\r\n\f]*([A-Za-z_][A-Za-z0-9_]*)?[ \t\r\n\f]*((?::[ \t\r\n\f]*(?:[A-Za-z_][A-Za-z0-9_]*|`(?:``|[^`])*`))*)[ \t\r\n\f]*(\{.*\})?[ \t\r\n\f]*$").expect("valid regex"))
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
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let (_, end) = escaped_identifier_token(bytes, i);
            if end <= i || bytes.get(end) != Some(&b'`') {
                return (Vec::new(), !require_valid);
            }
            i = end + 1;
            continue;
        }
        if bytes[i] != b'(' || i > 0 && is_identifier_byte(bytes[i - 1]) {
            i += 1;
            continue;
        }
        let Some(close) = matching_delimiter(bytes, i, b'(', b')') else {
            return (Vec::new(), !require_valid);
        };
        let body = &text[i + 1..close];
        let Some(pattern) = parse_node_pattern(body) else {
            if require_valid {
                return (Vec::new(), false);
            }
            i = close + 1;
            continue;
        };
        patterns.push(pattern);
        i = close + 1;
    }
    (patterns, true)
}

fn node_pattern_at(text: &str, index: usize) -> (NodePattern, bool, bool) {
    let bytes = text.as_bytes();
    if bytes[index] != b'('
        || index > 0
            && is_identifier_byte(bytes[index - 1])
            && !keyword_ends_at(text, index, "MATCH")
    {
        return (NodePattern::default(), false, false);
    }
    let Some(close) = matching_delimiter(bytes, index, b'(', b')') else {
        return (NodePattern::default(), true, false);
    };
    parse_node_pattern(&text[index + 1..close])
        .map_or((NodePattern::default(), true, false), |pattern| {
            (pattern, true, true)
        })
}

fn keyword_ends_at(query: &str, end: usize, keyword: &str) -> bool {
    end >= keyword.len() && keyword_at(query, end - keyword.len(), keyword)
}

fn parse_node_pattern(body: &str) -> Option<NodePattern> {
    let captures = node_body_pattern().captures(body)?;
    let properties = captures.get(3).map_or("", |value| value.as_str());
    if !properties.is_empty() && matching_brace(properties, 0) != Some(properties.len() - 1) {
        return None;
    }
    Some(NodePattern {
        variable: captures
            .get(1)
            .map_or("", |value| value.as_str())
            .to_owned(),
        labels: captures
            .get(2)
            .map_or("", |value| value.as_str())
            .to_owned(),
        properties: properties.to_owned(),
    })
}

fn node_pattern_has_inline_tenant_scope(pattern: &NodePattern) -> bool {
    node_has_entity_label(&pattern.labels) && has_inline_tenant_scope(&pattern.properties)
}

impl NodePattern {
    fn is_bare_variable_reference(&self) -> bool {
        !self.variable.is_empty()
            && self.labels.trim().is_empty()
            && self.properties.trim().is_empty()
    }
}

fn node_has_entity_label(labels: &str) -> bool {
    lex_cypher(labels).iter().any(|token| {
        matches!(
            token.kind,
            TokenKind::Identifier | TokenKind::EscapedIdentifier
        ) && token.text.eq_ignore_ascii_case("Entity")
    })
}

fn has_inline_tenant_scope(properties: &str) -> bool {
    let tokens = lex_cypher(properties);
    let (mut braces, mut brackets, mut parentheses) = (0_usize, 0_usize, 0_usize);
    for (index, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Symbol {
            match token.text.as_str() {
                "{" => braces += 1,
                "}" => braces = braces.saturating_sub(1),
                "[" => brackets += 1,
                "]" => brackets = brackets.saturating_sub(1),
                "(" => parentheses += 1,
                ")" => parentheses = parentheses.saturating_sub(1),
                _ => {}
            }
            continue;
        }
        let previous_is_delimiter = index.checked_sub(1).is_some_and(|previous| {
            symbol_token_at(&tokens, previous, "{") || symbol_token_at(&tokens, previous, ",")
        });
        if braces == 1
            && brackets == 0
            && parentheses == 0
            && previous_is_delimiter
            && keyword_token(token, "tenant_id")
            && symbol_token_at(&tokens, index + 1, ":")
            && tokens.get(index + 2).is_some_and(|value| {
                value.kind == TokenKind::Parameter && value.text.eq_ignore_ascii_case("$tenant_id")
            })
            && (symbol_token_at(&tokens, index + 3, ",")
                || symbol_token_at(&tokens, index + 3, "}"))
        {
            return true;
        }
    }
    false
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
    matching_delimiter(query.as_bytes(), start, b'{', b'}')
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

pub(crate) fn keyword_token_at(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| keyword_token(token, keyword))
}

pub(crate) fn keyword_token(token: &Token, keyword: &str) -> bool {
    token.kind == TokenKind::Identifier && token.text.eq_ignore_ascii_case(keyword)
}

pub(crate) fn function_name_token(token: &Token) -> bool {
    matches!(
        token.kind,
        TokenKind::Identifier | TokenKind::EscapedIdentifier
    )
}

pub(crate) fn symbol_token_at(tokens: &[Token], index: usize, symbol: &str) -> bool {
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
fn delimiter_depth_at(query: &str, index: usize, opening: u8, closing: u8) -> usize {
    let (bytes, mut depth, mut i) = (query.as_bytes(), 0_usize, 0);
    while i < index {
        if bytes[i] == b'`' {
            let (_, end) = escaped_identifier_token(bytes, i);
            i = end + 1;
            continue;
        }
        if bytes[i] == opening {
            depth += 1;
        } else if bytes[i] == closing {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    depth
}

fn function_call_open_at(query: &str, open: usize) -> bool {
    let bytes = query.as_bytes();
    let mut end = open;
    while end > 0 && is_whitespace(bytes[end - 1]) {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && (is_identifier_byte(bytes[start - 1]) || bytes[start - 1] == b'.') {
        start -= 1;
    }
    if start == end {
        return false;
    }
    !matches!(
        query[start..end].to_ascii_uppercase().as_str(),
        "MATCH"
            | "OPTIONAL"
            | "WHERE"
            | "RETURN"
            | "WITH"
            | "CALL"
            | "UNION"
            | "ORDER"
            | "BY"
            | "LIMIT"
            | "SKIP"
            | "AS"
    )
}

fn expression_local_pattern(query: &str, index: usize, call_subquery_depth: usize) -> bool {
    delimiter_depth_at(query, index, b'[', b']') > 0
        || delimiter_depth_at(query, index, b'{', b'}') > call_subquery_depth
}
