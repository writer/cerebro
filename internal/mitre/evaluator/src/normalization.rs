use regex::Regex;
use std::sync::OnceLock;

const ATTACK_TACTICS: &[(&str, &str)] = &[
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
];

pub(crate) fn split_values(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        for part in value.trim().split([',', ';', '\n', '\t', '|']) {
            let part = part.trim();
            if !part.is_empty() {
                output.push(part.to_string());
            }
        }
    }
    output
}

pub(crate) fn defend_id_and_name(raw: &str) -> (String, String) {
    let value = raw.trim();
    if value.is_empty() {
        return (String::new(), String::new());
    }
    let mut candidate = value.trim_end_matches(['#', '/']);
    if let Some(index) = candidate.rfind(['#', '/'])
        && index < candidate.len() - 1
    {
        candidate = &candidate[index + 1..];
    }
    for prefix in ["d3f:", "D3F:", "d3fend:", "D3FEND:"] {
        if let Some(stripped) = candidate.strip_prefix(prefix) {
            candidate = stripped;
        }
    }
    candidate = candidate.trim();
    if candidate.is_empty() || candidate.contains(' ') {
        return (String::new(), value.to_string());
    }
    (candidate.to_string(), candidate.to_string())
}

pub(crate) fn normalize_key(value: &str) -> String {
    let mut normalized = simple_lowercase(value.trim());
    for prefix in ["attack.", "mitre-", "mitre_"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            normalized = stripped.to_string();
        }
    }
    normalized = normalized.replace(['_', '-'], " ");
    let mut collapsed = String::with_capacity(normalized.len());
    let mut previous_was_space = false;
    for character in normalized.chars() {
        if matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{000c}') {
            if !previous_was_space {
                collapsed.push(' ');
            }
            previous_was_space = true;
        } else {
            collapsed.push(character);
            previous_was_space = false;
        }
    }
    collapsed.trim().replace(' ', "-")
}

// Go's unicode.ToLower applies one simple case mapping per rune. Rust's
// str::to_lowercase applies full mappings and can expand one character into
// several, which would change duplicate keys and first-value precedence.
pub(crate) fn simple_lowercase(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

pub(crate) fn attack_tactic_by_id(id: &str) -> Option<&'static str> {
    ATTACK_TACTICS
        .iter()
        .find_map(|(candidate, name)| (*candidate == id).then_some(*name))
}

pub(crate) fn attack_tactic_by_name(key: &str) -> Option<(&'static str, &'static str)> {
    ATTACK_TACTICS.iter().find_map(|(id, name)| {
        let primary = normalize_key(name);
        let without_and = normalize_key(&name.replace(" and ", " "));
        (key == primary || key == without_and).then_some((*id, *name))
    })
}

pub(crate) fn attack_technique_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i-u)\bT[0-9]{4}(?:\.[0-9]{3})?\b").expect("valid regex"))
}

pub(crate) fn attack_subtechnique_url_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i-u)/techniques/(T[0-9]{4})/([0-9]{3})(?:/|\b)").expect("valid regex")
    })
}

pub(crate) fn attack_tactic_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i-u)\bTA[0-9]{4}\b").expect("valid regex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_preserves_simple_unicode_case_mapping() {
        assert_eq!(simple_lowercase("İD"), "id");
        assert_eq!(
            normalize_key(" MITRE_Command_and_Control "),
            "command-and-control"
        );
    }

    #[test]
    fn defend_identifiers_keep_url_and_label_precedence() {
        assert_eq!(
            defend_id_and_name("https://d3fend.mitre.org/technique/d3f:CredentialHardening/"),
            (
                "CredentialHardening".to_owned(),
                "CredentialHardening".to_owned()
            )
        );
        assert_eq!(
            defend_id_and_name("Credential Hardening"),
            (String::new(), "Credential Hardening".to_owned())
        );
    }
}
