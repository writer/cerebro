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
#[path = "linode/source_execution.rs"]
mod source_execution;
#[path = "linode/time.rs"]
mod time;
#[path = "linode/wire.rs"]
mod wire;

pub use error::LinodeError;
pub use model::{LinodePage, LinodeRecord};
pub use request::{LinodeKernel, LinodeRequest};

pub(crate) use source_execution::{
    LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER, durable_checkpoint_cursor,
};
