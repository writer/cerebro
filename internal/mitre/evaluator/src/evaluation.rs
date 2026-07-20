use std::collections::HashSet;

use crate::model::{
    AttackTactic, AttackTechnique, ContextInput, ContextOutput, DefendArtifact, DefendTactic,
    DefendTechnique,
};
use crate::normalization::{
    attack_subtechnique_url_pattern, attack_tactic_by_id, attack_tactic_by_name,
    attack_tactic_pattern, attack_technique_pattern, defend_id_and_name, normalize_key,
    split_values,
};

pub const ABI_VERSION: u32 = 1;
#[cfg(target_arch = "wasm32")]
pub(crate) const MAX_INPUT_BYTES: usize = 1 << 20;
#[cfg(target_arch = "wasm32")]
pub(crate) const MAX_OUTPUT_BYTES: usize = 2 << 20;

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
