//! Kubernetes opaque continuation and two-stage RBAC cursor handling.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use super::{KubernetesError, KubernetesFamily};

const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RbacStage {
    Role,
    ClusterRole,
    RoleBinding,
    ClusterRoleBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RbacCursor {
    pub(super) stage: RbacStage,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) token: String,
}

pub(super) fn bounded_token(value: Option<&str>) -> Result<Option<String>, KubernetesError> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    if value.is_some_and(|value| {
        value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_control)
            || value.starts_with("http://")
            || value.starts_with("https://")
    }) {
        return Err(KubernetesError::InvalidCursor);
    }
    Ok(value.map(str::to_owned))
}

pub(super) fn decode_rbac_cursor(
    family: KubernetesFamily,
    value: Option<&str>,
) -> Result<RbacCursor, KubernetesError> {
    let initial = match family {
        KubernetesFamily::RbacRole => RbacStage::Role,
        KubernetesFamily::RbacBinding => RbacStage::RoleBinding,
        _ => return Err(KubernetesError::InvalidCursor),
    };
    let Some(value) = bounded_token(value)? else {
        return Ok(RbacCursor {
            stage: initial,
            token: String::new(),
        });
    };
    let raw = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| KubernetesError::InvalidCursor)?;
    if raw.len() > MAX_CURSOR_BYTES {
        return Err(KubernetesError::InvalidCursor);
    }
    let cursor: RbacCursor =
        serde_json::from_slice(&raw).map_err(|_| KubernetesError::InvalidCursor)?;
    let valid_stage = matches!(
        (family, cursor.stage),
        (
            KubernetesFamily::RbacRole,
            RbacStage::Role | RbacStage::ClusterRole
        ) | (
            KubernetesFamily::RbacBinding,
            RbacStage::RoleBinding | RbacStage::ClusterRoleBinding
        )
    );
    if !valid_stage || bounded_token(Some(&cursor.token))?.as_deref() != nonempty(&cursor.token) {
        return Err(KubernetesError::InvalidCursor);
    }
    Ok(cursor)
}

pub(super) fn encode_rbac_cursor(cursor: &RbacCursor) -> Result<String, KubernetesError> {
    bounded_token(Some(&cursor.token))?;
    let payload = serde_json::to_vec(cursor).map_err(|_| KubernetesError::InvalidCursor)?;
    if payload.len() > MAX_CURSOR_BYTES {
        return Err(KubernetesError::InvalidCursor);
    }
    Ok(URL_SAFE_NO_PAD.encode(payload))
}

fn nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
