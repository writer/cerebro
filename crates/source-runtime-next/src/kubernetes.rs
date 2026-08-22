//! Credential-free Kubernetes provider kernel.

mod cursor;
mod error;
mod family;
mod model;
mod normalize;
mod projection;
mod request;
mod response;

#[cfg(test)]
mod tests;

pub use error::KubernetesError;
pub use family::{KubernetesFamily, KubernetesRuntimeDefinition};
pub use model::{KubernetesPage, KubernetesRecord};
pub use projection::{KubernetesProjection, KubernetesProjectionEntity, KubernetesProjectionLink};
pub use request::{KubernetesConfig, KubernetesKernel, KubernetesRequest};
