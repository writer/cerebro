//! SentinelOne request, response, and application-fanout runtime kernel.
//!
//! SentinelOne exposes six directly paginated collection endpoints and one
//! application inventory endpoint that must first enumerate agents. This
//! module keeps that provider-specific state machine out of the generic HTTP
//! grammar while producing records that can cross the shared graph boundary.

mod cursor;
mod kernel;
mod model;
mod response;

pub use kernel::SentinelOneKernel;
pub use model::{
    SentinelOneError, SentinelOneFamily, SentinelOneFilters, SentinelOneOutcome, SentinelOnePage,
    SentinelOneRecord, SentinelOneRequest,
};

#[cfg(test)]
mod tests;
