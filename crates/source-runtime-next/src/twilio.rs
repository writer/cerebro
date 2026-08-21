//! Credential-free Twilio provider kernel facade.

mod cursor;
mod error;
mod family;
mod model;
mod normalize;
mod origin;
mod request;
mod response;

#[cfg(test)]
mod tests;

pub use error::TwilioError;
pub use model::{TwilioFamily, TwilioFilters, TwilioPage, TwilioRecord};
pub use request::{TwilioKernel, TwilioRequest};
