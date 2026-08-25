//! Credential-free PagerDuty responder-topology provider kernel.

mod cursor;
mod error;
mod model;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;
mod source_execution;

pub use error::PagerDutyError;
pub use model::{PagerDutyFamily, PagerDutyFilters, PagerDutyPage, PagerDutyPlan, PagerDutyRecord};
pub use projection::{
    PagerDutyEntityFact, PagerDutyProjectionFacts, PagerDutyRelationFact, project_pagerduty_records,
};
pub use request::{PagerDutyKernel, PagerDutyRequest};

pub(crate) use source_execution::{PAGERDUTY_SOURCE_EXECUTION_ADAPTERS, durable_checkpoint_cursor};

#[cfg(test)]
mod tests;
