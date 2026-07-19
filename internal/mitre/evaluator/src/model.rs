use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextInput {
    #[serde(default)]
    pub(crate) attack_tactic_values: Vec<String>,
    #[serde(default)]
    pub(crate) attack_technique_values: Vec<String>,
    #[serde(default)]
    pub(crate) attack_technique_id_values: Vec<String>,
    #[serde(default)]
    pub(crate) defend_tactic_values: Vec<String>,
    #[serde(default)]
    pub(crate) defend_technique_values: Vec<String>,
    #[serde(default)]
    pub(crate) defend_artifact_values: Vec<String>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ContextOutput {
    pub(crate) attack_tactics: Vec<AttackTactic>,
    pub(crate) attack_techniques: Vec<AttackTechnique>,
    pub(crate) defend_tactics: Vec<DefendTactic>,
    pub(crate) defend_techniques: Vec<DefendTechnique>,
    pub(crate) defend_artifacts: Vec<DefendArtifact>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttackTactic {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttackTechnique {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendTactic {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendTechnique {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) source_value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DefendArtifact {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) source_value: String,
}
