//! Portable manifest and resource-limit contracts for analysis plugins.
//!
//! Manifests declare what an artifact may do and the sandbox constraints it
//! requires. They do not verify artifact bytes, attest determinism, negotiate
//! ABI compatibility, or create the sandbox that enforces those declarations.

use serde::Serialize;

use crate::{ContentDigest, PluginId, SdkError};

const MAX_PLUGIN_ABI_VERSION_BYTES: usize = 128;

/// Analysis operation a plugin declares it can perform.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Read a bounded graph snapshot supplied by the host.
    GraphSnapshotRead,
    /// Evaluate a bounded fact query.
    FactQueryEvaluation,
    /// Evaluate an assertion definition.
    AssertionEvaluation,
    /// Score a proposed simulation result.
    SimulationScoring,
}

/// Per-invocation sandbox ceilings declared by a plugin manifest.
///
/// Validation requires every value to be non-zero but applies no global maxima.
/// The trusted execution host must compare these requests with platform policy
/// and meter actual memory, time, input, and output consumption.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginLimits {
    /// Maximum sandbox memory in bytes.
    pub memory_bytes: u64,
    /// Maximum host-metered execution time in milliseconds.
    pub execution_millis: u32,
    /// Maximum input payload size in bytes.
    pub input_bytes: u32,
    /// Maximum output payload size in bytes.
    pub output_bytes: u32,
}

impl PluginLimits {
    /// Validates that every declared ceiling is usable and non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::OutOfRange`] if any limit is zero.
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

/// Declarative contract for one content-addressed analysis plugin.
///
/// Capabilities must be non-empty, but this shape currently permits duplicate
/// capability values. Safety booleans are mandatory policy declarations rather
/// than evidence that the artifact actually has zero imports or deterministic
/// output; artifact inspection and sandbox enforcement remain host duties.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisPluginManifest {
    /// Stable identity of the plugin contract.
    pub plugin_id: PluginId,
    /// Exact host-defined ABI version, preserved without normalization.
    pub abi_version: String,
    /// Caller-supplied digest of the executable artifact bytes.
    pub artifact_digest: ContentDigest,
    /// Non-empty operations the host may dispatch to the plugin.
    pub capabilities: Vec<PluginCapability>,
    /// Resource ceilings requested for each invocation.
    pub limits: PluginLimits,
    /// Mandatory declaration that the artifact must execute without imports.
    pub zero_imports_required: bool,
    /// Mandatory declaration that identical inputs must produce identical output.
    pub deterministic_output_required: bool,
}

impl AnalysisPluginManifest {
    /// Validates ABI syntax, capability presence, safety policy, and limits.
    ///
    /// ABI strings must be non-empty, have no surrounding whitespace, and fit
    /// within 128 bytes. This method does not verify ABI support, deduplicate
    /// capabilities, hash artifact bytes, or inspect the artifact's imports.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] for malformed ABI text or disabled safety
    /// requirements, [`SdkError::TooLong`] for an ABI string over 128 bytes,
    /// [`SdkError::Empty`] for no capabilities, or the limit validation error.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.abi_version.trim() != self.abi_version || self.abi_version.is_empty() {
            return Err(SdkError::Invalid("plugin ABI version"));
        }
        if self.abi_version.len() > MAX_PLUGIN_ABI_VERSION_BYTES {
            return Err(SdkError::TooLong("plugin ABI version"));
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
