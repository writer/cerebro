#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TokenKind {
    Identifier,
    EscapedIdentifier,
    Number,
    Symbol,
    Parameter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) text: String,
}

pub(crate) fn scrub_cypher(query: &str) -> String {
    let bytes = query.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                output.extend_from_slice(b"''");
                i = skip_quoted_literal(bytes, i, bytes[i]) + 1;
            }
            b'`' => {
                let (_, end) = escaped_identifier_token(bytes, i);
                output.extend_from_slice(&bytes[i..=end]);
                i = end + 1;
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

pub(crate) fn skip_quoted_literal(query: &[u8], start: usize, quote: u8) -> usize {
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

pub(crate) fn lex_cypher(query: &str) -> Vec<Token> {
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

pub(crate) fn escaped_identifier_token(query: &[u8], start: usize) -> (String, usize) {
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

fn is_whitespace(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_identifier_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}

fn is_identifier_start(value: u8) -> bool {
    value.is_ascii_alphabetic() || value == b'_'
}
