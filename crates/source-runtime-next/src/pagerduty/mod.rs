//! Credential-free PagerDuty responder-topology provider kernel.

mod cursor;
mod error;
mod model;
mod normalize;
mod origin;
mod projection;
mod request;
mod response;

pub use error::PagerDutyError;
pub use model::{PagerDutyFamily, PagerDutyFilters, PagerDutyPage, PagerDutyPlan, PagerDutyRecord};
pub use projection::{
    PagerDutyEntityFact, PagerDutyProjectionFacts, PagerDutyRelationFact, project_pagerduty_records,
};
pub use request::{PagerDutyKernel, PagerDutyRequest};

#[cfg(test)]
mod tests;
