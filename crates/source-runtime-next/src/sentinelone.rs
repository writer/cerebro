//! SentinelOne request, response, and application-fanout provider kernel.
//!
//! SentinelOne exposes six directly paginated collection endpoints and one
//! application inventory endpoint that must first enumerate agents. This
//! module owns that credential-free provider state machine. Its normalized
//! records still require the shared source-execution adapter, compiler mapping,
//! event admission, and projection path before they can reach the graph.

mod cursor;
mod kernel;
mod model;
mod response;
mod source_execution_adapter;

pub(crate) use source_execution_adapter::{
    SentinelOneAgentSourceExecutionAdapter, durable_checkpoint_cursor,
};

pub use kernel::SentinelOneKernel;
pub use model::{
    SentinelOneError, SentinelOneFamily, SentinelOneFilters, SentinelOneOutcome, SentinelOnePage,
    SentinelOneRecord, SentinelOneRequest,
};

#[cfg(test)]
mod tests;
