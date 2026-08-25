//! Credential-free DeepSeek source kernel.

#[path = "deepseek/catalog.rs"]
mod catalog;
#[path = "deepseek/error.rs"]
mod error;
#[path = "deepseek/family.rs"]
mod family;
#[path = "deepseek/normalize.rs"]
mod normalize;
#[path = "deepseek/projection.rs"]
mod projection;
#[path = "deepseek/request.rs"]
mod request;
#[path = "deepseek/response.rs"]
mod response;
#[path = "deepseek/source_execution.rs"]
mod source_execution;
#[cfg(test)]
#[path = "deepseek/tests.rs"]
mod tests;
#[path = "deepseek/types.rs"]
mod types;

pub use catalog::{DeepSeekEventContract, DeepSeekRuntimeDefinition};
pub use error::DeepSeekError;
pub use family::DeepSeekFamily;
pub use projection::{
    DeepSeekEntityFact, DeepSeekProjectionFacts, DeepSeekRelationFact, project_deepseek_records,
};
pub(crate) use source_execution::DEEPSEEK_SOURCE_EXECUTION_ADAPTERS;
pub use types::{
    DeepSeekCheckpointCandidate, DeepSeekKernel, DeepSeekPage, DeepSeekRecord, DeepSeekRequest,
};
