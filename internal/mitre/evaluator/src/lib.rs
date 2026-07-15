use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

pub const ABI_VERSION: u32 = 1;

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

#[derive(Debug, Default, Deserialize)]
pub struct ContextInput {
    #[serde(default)]
    attack_tactic_values: Vec<String>,
    #[serde(default)]
    attack_technique_values: Vec<String>,
    #[serde(default)]
    attack_technique_id_values: Vec<String>,
    #[serde(default)]
    defend_tactic_values: Vec<String>,
    #[serde(default)]
    defend_technique_values: Vec<String>,
    #[serde(default)]
    defend_artifact_values: Vec<String>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ContextOutput {
    attack_tactics: Vec<AttackTactic>,
    attack_techniques: Vec<AttackTechnique>,
    defend_tactics: Vec<DefendTactic>,
    defend_techniques: Vec<DefendTechnique>,
    defend_artifacts: Vec<DefendArtifact>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttackTactic {
    id: String,
    name: String,
    source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttackTechnique {
    id: String,
    name: String,
    source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendTactic {
    id: String,
    name: String,
    source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendTechnique {
    id: String,
    name: String,
    source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendArtifact {
    id: String,
    name: String,
    source_value: String,
}

pub fn evaluate(input: ContextInput) -> ContextOutput {
    let attack_tactics = extract_attack_tactics(&input.attack_tactic_values);
    let mut attack_techniques = extract_attack_techniques(true, &input.attack_technique_values);
    attack_techniques.extend(extract_attack_techniques(
        false,
        &input.attack_technique_id_values,
    ));
    ContextOutput {
        attack_tactics,
        attack_techniques,
        defend_tactics: extract_defend_tactics(&input.defend_tactic_values),
        defend_techniques: extract_defend_techniques(&input.defend_technique_values),
        defend_artifacts: extract_defend_artifacts(&input.defend_artifact_values),
    }
}

fn extract_attack_tactics(values: &[String]) -> Vec<AttackTactic> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for raw in split_values(values) {
        for matched in attack_tactic_pattern().find_iter(&raw) {
            let id = matched.as_str().to_uppercase();
            let name = attack_tactic_by_id(&id).unwrap_or(&id).to_string();
            add_attack_tactic(
                &mut output,
                &mut seen,
                AttackTactic {
                    id,
                    name,
                    source_value: raw.clone(),
                },
            );
        }
        if let Some((id, name)) =
            attack_tactic_by_name(&normalize_key(raw.strip_prefix("attack.").unwrap_or(&raw)))
        {
            add_attack_tactic(
                &mut output,
                &mut seen,
                AttackTactic {
                    id: id.to_string(),
                    name: name.to_string(),
                    source_value: raw.clone(),
                },
            );
        }
        if let Some((tactic_name, _)) = raw.split_once(':')
            && let Some((id, name)) = attack_tactic_by_name(&normalize_key(tactic_name))
        {
            add_attack_tactic(
                &mut output,
                &mut seen,
                AttackTactic {
                    id: id.to_string(),
                    name: name.to_string(),
                    source_value: raw.clone(),
                },
            );
        }
    }
    output
}

fn extract_attack_techniques(allow_labels: bool, values: &[String]) -> Vec<AttackTechnique> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for raw in split_values(values) {
        let mut matched_id = false;
        for captures in attack_subtechnique_url_pattern().captures_iter(&raw) {
            let (Some(parent), Some(child)) = (captures.get(1), captures.get(2)) else {
                continue;
            };
            matched_id = true;
            let id = format!("{}.{}", parent.as_str(), child.as_str()).to_uppercase();
            add_attack_technique(
                &mut output,
                &mut seen,
                AttackTechnique {
                    id: id.clone(),
                    name: id,
                    source_value: raw.clone(),
                },
            );
        }
        if matched_id {
            continue;
        }
        for matched in attack_technique_pattern().find_iter(&raw) {
            matched_id = true;
            let id = matched.as_str().to_uppercase();
            add_attack_technique(
                &mut output,
                &mut seen,
                AttackTechnique {
                    id: id.clone(),
                    name: id,
                    source_value: raw.clone(),
                },
            );
        }
        if matched_id || !allow_labels {
            continue;
        }
        let label = raw.trim();
        if label.is_empty()
            || attack_tactic_pattern().is_match(label)
            || attack_technique_pattern().is_match(label)
            || attack_tactic_by_name(&normalize_key(label)).is_some()
        {
            continue;
        }
        add_attack_technique(
            &mut output,
            &mut seen,
            AttackTechnique {
                id: String::new(),
                name: label.to_string(),
                source_value: raw,
            },
        );
    }
    output
}

fn extract_defend_tactics(values: &[String]) -> Vec<DefendTactic> {
    extract_defend(values)
        .into_iter()
        .map(|value| DefendTactic {
            id: value.id,
            name: value.name,
            source_value: value.source_value,
        })
        .collect()
}

fn extract_defend_techniques(values: &[String]) -> Vec<DefendTechnique> {
    extract_defend(values)
        .into_iter()
        .map(|value| DefendTechnique {
            id: value.id,
            name: value.name,
            source_value: value.source_value,
        })
        .collect()
}

fn extract_defend_artifacts(values: &[String]) -> Vec<DefendArtifact> {
    extract_defend(values)
        .into_iter()
        .map(|value| DefendArtifact {
            id: value.id,
            name: value.name,
            source_value: value.source_value,
        })
        .collect()
}

struct DefendValue {
    id: String,
    name: String,
    source_value: String,
}

fn extract_defend(values: &[String]) -> Vec<DefendValue> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for raw in split_values(values) {
        let (id, name) = defend_id_and_name(&raw);
        if id.is_empty() && name.is_empty() {
            continue;
        }
        let key = if id.is_empty() {
            normalize_key(&name)
        } else {
            id.clone()
        };
        if !seen.insert(key) {
            continue;
        }
        output.push(DefendValue {
            id,
            name,
            source_value: raw,
        });
    }
    output
}

fn split_values(values: &[String]) -> Vec<String> {
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

fn add_attack_tactic(
    output: &mut Vec<AttackTactic>,
    seen: &mut HashSet<String>,
    tactic: AttackTactic,
) {
    let key = if tactic.id.is_empty() {
        normalize_key(&tactic.name)
    } else {
        tactic.id.clone()
    };
    if !key.is_empty() && seen.insert(key) {
        output.push(tactic);
    }
}

fn add_attack_technique(
    output: &mut Vec<AttackTechnique>,
    seen: &mut HashSet<String>,
    technique: AttackTechnique,
) {
    let key = if technique.id.is_empty() {
        normalize_key(&technique.name)
    } else {
        technique.id.clone()
    };
    if !key.is_empty() && seen.insert(key) {
        output.push(technique);
    }
}

fn defend_id_and_name(raw: &str) -> (String, String) {
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

fn normalize_key(value: &str) -> String {
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
fn simple_lowercase(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

fn attack_tactic_by_id(id: &str) -> Option<&'static str> {
    ATTACK_TACTICS
        .iter()
        .find_map(|(candidate, name)| (*candidate == id).then_some(*name))
}

fn attack_tactic_by_name(key: &str) -> Option<(&'static str, &'static str)> {
    ATTACK_TACTICS.iter().find_map(|(id, name)| {
        let primary = normalize_key(name);
        let without_and = normalize_key(&name.replace(" and ", " "));
        (key == primary || key == without_and).then_some((*id, *name))
    })
}

fn attack_technique_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i-u)\bT[0-9]{4}(?:\.[0-9]{3})?\b").expect("valid regex"))
}

fn attack_subtechnique_url_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i-u)/techniques/(T[0-9]{4})/([0-9]{3})(?:/|\b)").expect("valid regex")
    })
}

fn attack_tactic_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i-u)\bTA[0-9]{4}\b").expect("valid regex"))
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_mitre_abi_version() -> u32 {
    ABI_VERSION
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_mitre_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc(length)
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_mitre_evaluate(
    request_pointer: u32,
    request_length: u32,
    result_pointer: u32,
) -> u32 {
    cerebro_wasm_guest::with_input_and_output::<
        _,
        { cerebro_wasm_guest::JSON_RESULT_DESCRIPTOR_SIZE },
    >(
        request_pointer,
        request_length,
        result_pointer,
        |request_bytes| {
            let request: ContextInput = match serde_json::from_slice(request_bytes) {
                Ok(request) => request,
                Err(_) => return 1,
            };
            let output = match serde_json::to_vec(&evaluate(request)) {
                Ok(output) => output,
                Err(_) => return 2,
            };
            if cerebro_wasm_guest::write_json_result(result_pointer, output) {
                0
            } else {
                2
            }
        },
    )
    .unwrap_or(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn evaluates_all_context_categories_and_preserves_cross_group_duplicates() {
        let output = evaluate(ContextInput {
            attack_tactic_values: strings(&["Defense Evasion", "mitre-ta0011", "Collection:T1530"]),
            attack_technique_values: strings(&["T1190", "Native API"]),
            attack_technique_id_values: strings(&[
                "attack.t1190",
                "https://attack.mitre.org/techniques/T1098/003/",
            ]),
            defend_tactic_values: strings(&["d3f:Model"]),
            defend_technique_values: strings(&[
                "https://d3fend.mitre.org/technique/ProcessScreenshot/",
                "Process Termination",
            ]),
            defend_artifact_values: strings(&["d3f:Credential"]),
        });
        assert_eq!(
            output
                .attack_tactics
                .iter()
                .map(|value| value.id.as_str())
                .collect::<Vec<_>>(),
            ["TA0005", "TA0011", "TA0009"]
        );
        assert_eq!(
            output
                .attack_techniques
                .iter()
                .map(|value| value.id.as_str())
                .collect::<Vec<_>>(),
            ["T1190", "", "T1190", "T1098.003"]
        );
        assert_eq!(output.defend_tactics[0].id, "Model");
        assert_eq!(output.defend_techniques[0].id, "ProcessScreenshot");
        assert_eq!(output.defend_techniques[1].id, "");
        assert_eq!(output.defend_artifacts[0].id, "Credential");
    }

    #[test]
    fn preserves_attack_url_precedence_labels_and_ascii_identifier_rules() {
        let output = evaluate(ContextInput {
            attack_technique_values: strings(&[
                "https://attack.mitre.org/techniques/T1098/003/ and T1190",
                "Initial Access",
                "T١١٩٠",
            ]),
            attack_technique_id_values: strings(&["Native API", "T1562.001"]),
            ..ContextInput::default()
        });
        assert_eq!(output.attack_techniques.len(), 3);
        assert_eq!(output.attack_techniques[0].id, "T1098.003");
        assert_eq!(output.attack_techniques[1].name, "T١١٩٠");
        assert_eq!(output.attack_techniques[2].id, "T1562.001");
    }

    #[test]
    fn keeps_first_value_within_each_extraction_group() {
        let output = evaluate(ContextInput {
            attack_tactic_values: strings(&["Initial Access", "TA0001"]),
            attack_technique_values: strings(&["t1190", "T1190", "Native API", "native-api"]),
            defend_technique_values: strings(&["TokenBinding", "TokenBinding", "tokenbinding"]),
            ..ContextInput::default()
        });
        assert_eq!(output.attack_tactics.len(), 1);
        assert_eq!(output.attack_tactics[0].source_value, "Initial Access");
        assert_eq!(output.attack_techniques.len(), 2);
        assert_eq!(output.attack_techniques[0].source_value, "t1190");
        assert_eq!(output.attack_techniques[1].source_value, "Native API");
        assert_eq!(output.defend_techniques.len(), 2);
    }

    #[test]
    fn uses_simple_unicode_lowercase_for_duplicate_keys() {
        let output = evaluate(ContextInput {
            attack_technique_values: strings(&["İ", "i"]),
            ..ContextInput::default()
        });
        assert_eq!(output.attack_techniques.len(), 1);
        assert_eq!(output.attack_techniques[0].source_value, "İ");
    }
}
