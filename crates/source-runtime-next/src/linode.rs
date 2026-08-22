//! Credential-free Linode managed-issue kernel facade.

#[path = "linode/cursor.rs"]
mod cursor;
#[path = "linode/error.rs"]
mod error;
#[path = "linode/identity.rs"]
mod identity;
#[path = "linode/model.rs"]
mod model;
#[path = "linode/normalize.rs"]
mod normalize;
#[path = "linode/origin.rs"]
mod origin;
#[path = "linode/request.rs"]
mod request;
#[path = "linode/response.rs"]
mod response;
#[path = "linode/time.rs"]
mod time;
#[path = "linode/wire.rs"]
mod wire;

pub use error::LinodeError;
pub use model::{LinodePage, LinodeRecord};
pub use request::{LinodeKernel, LinodeRequest};
