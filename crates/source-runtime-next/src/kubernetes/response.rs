//! Bounded Kubernetes response decoding, status classification, and continuation.

use std::collections::HashMap;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesPage, KubernetesRequest,
    cursor::{RbacCursor, RbacStage, bounded_token, encode_rbac_cursor},
    normalize::{normalize_cluster, normalize_object},
    request::max_response_bytes,
};

const MAX_NORMALIZED_RECORDS: usize = 500;

impl KubernetesKernel {
    /// Decode one provider response after the trusted host has enforced the body bound.
    pub fn decode(
        &self,
        request: &KubernetesRequest,
        status: u16,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<KubernetesPage, KubernetesError> {
        self.validate_request(request)?;
        classify_status(status)?;
        if body.len() > max_response_bytes() {
            return Err(KubernetesError::ResponseTooLarge);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| KubernetesError::MalformedResponse)?;
        if self.family == KubernetesFamily::Cluster {
            let record = normalize_cluster(self, value, observed_at)?;
            self.validate_record_contract(&record)?;
            return Ok(KubernetesPage {
                records: vec![record],
                next_cursor: None,
                proposed_checkpoint: None,
            });
        }
        let object = value
            .as_object()
            .ok_or(KubernetesError::MalformedResponse)?;
        let items = object
            .get("items")
            .and_then(Value::as_array)
            .ok_or(KubernetesError::MalformedResponse)?;
        if items.len() > self.page_size {
            return Err(KubernetesError::TooManyRecords);
        }
        let mut records = Vec::new();
        let mut seen = HashMap::<String, usize>::new();
        for item in items {
            for record in normalize_object(self, request, item.clone(), observed_at)? {
                self.validate_record_contract(&record)?;
                if let Some(index) = seen.get(&record.provider_id).copied() {
                    if records.get(index) != Some(&record) {
                        return Err(KubernetesError::ConflictingProviderIdentity);
                    }
                    continue;
                }
                seen.insert(record.provider_id.clone(), records.len());
                records.push(record);
                if records.len() > MAX_NORMALIZED_RECORDS {
                    return Err(KubernetesError::TooManyRecords);
                }
            }
        }
        let provider_cursor = object
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("continue"))
            .and_then(Value::as_str);
        let next_cursor = self.next_cursor(request, provider_cursor)?;
        Ok(KubernetesPage {
            records,
            proposed_checkpoint: next_cursor.clone(),
            next_cursor,
        })
    }

    fn next_cursor(
        &self,
        request: &KubernetesRequest,
        provider_cursor: Option<&str>,
    ) -> Result<Option<String>, KubernetesError> {
        let provider_cursor = bounded_token(provider_cursor)?;
        let Some(stage) = request.rbac_stage else {
            return Ok(provider_cursor);
        };
        if let Some(token) = provider_cursor {
            return encode_rbac_cursor(&RbacCursor { stage, token }).map(Some);
        }
        let next_stage = match stage {
            RbacStage::Role => Some(RbacStage::ClusterRole),
            RbacStage::RoleBinding => Some(RbacStage::ClusterRoleBinding),
            RbacStage::ClusterRole | RbacStage::ClusterRoleBinding => None,
        };
        next_stage
            .map(|stage| {
                encode_rbac_cursor(&RbacCursor {
                    stage,
                    token: String::new(),
                })
            })
            .transpose()
    }

    fn validate_record_contract(
        &self,
        record: &super::KubernetesRecord,
    ) -> Result<(), KubernetesError> {
        if record.family != self.family
            || record.event_kind != self.family.event_kind()
            || record.schema_ref != self.family.schema_ref()
        {
            return Err(KubernetesError::MalformedResponse);
        }
        for field in self.family.required_attributes() {
            if record
                .attributes
                .get(*field)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(KubernetesError::MissingRequiredAttribute(field));
            }
        }
        for field in self.family.required_payload_fields() {
            if record.payload.get(*field).is_none_or(Value::is_null) {
                return Err(KubernetesError::MissingRequiredPayloadField(field));
            }
        }
        Ok(())
    }
}

fn classify_status(status: u16) -> Result<(), KubernetesError> {
    match status {
        200 => Ok(()),
        401 => Err(KubernetesError::AuthenticationRejected),
        403 => Err(KubernetesError::PermissionDenied),
        429 => Err(KubernetesError::RateLimited),
        500..=599 => Err(KubernetesError::ProviderUnavailable),
        other => Err(KubernetesError::UnexpectedProviderStatus(other)),
    }
}
