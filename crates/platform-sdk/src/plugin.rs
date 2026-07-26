use serde::Serialize;

use crate::{ContentDigest, PluginId, SdkError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    GraphSnapshotRead,
    FactQueryEvaluation,
    AssertionEvaluation,
    SimulationScoring,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginLimits {
    pub memory_bytes: u64,
    pub execution_millis: u32,
    pub input_bytes: u32,
    pub output_bytes: u32,
}

impl PluginLimits {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.memory_bytes == 0
            || self.execution_millis == 0
            || self.input_bytes == 0
            || self.output_bytes == 0
        {
            return Err(SdkError::OutOfRange("plugin limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisPluginManifest {
    pub plugin_id: PluginId,
    pub abi_version: String,
    pub artifact_digest: ContentDigest,
    pub capabilities: Vec<PluginCapability>,
    pub limits: PluginLimits,
    pub zero_imports_required: bool,
    pub deterministic_output_required: bool,
}

impl AnalysisPluginManifest {
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.abi_version.trim() != self.abi_version || self.abi_version.is_empty() {
            return Err(SdkError::Invalid("plugin ABI version"));
        }
        if self.capabilities.is_empty() {
            return Err(SdkError::Empty("plugin capabilities"));
        }
        if !self.zero_imports_required || !self.deterministic_output_required {
            return Err(SdkError::Invalid("plugin safety requirements"));
        }
        self.limits.validate()
    }
}
