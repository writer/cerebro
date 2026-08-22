use serde_json::Value;

use super::{
    DockerHubCheckpointCandidate, DockerHubError, DockerHubKernel, DockerHubPage, DockerHubRequest,
    normalize::normalize, request::MAX_RESPONSE_BYTES,
};

impl DockerHubKernel {
    /// Classify status and normalize one bounded provider response.
    pub fn decode_http(
        &self,
        request: &DockerHubRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
        observed_at: &str,
    ) -> Result<DockerHubPage, DockerHubError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DockerHubError::ResponseTooLarge);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(DockerHubError::InvalidRetryAfter);
        }
        match status {
            200 => {}
            401 => return Err(DockerHubError::AuthenticationRejected),
            403 => return Err(DockerHubError::RequiredScopeMissing),
            404 => return Err(DockerHubError::ProviderResourceNotFound),
            429 => {
                return Err(DockerHubError::RateLimited {
                    retry_after_seconds,
                });
            }
            500..=599 => return Err(DockerHubError::ProviderUnavailable { status }),
            _ => return Err(DockerHubError::UnexpectedStatus { status }),
        }
        let raw: Value =
            serde_json::from_slice(body).map_err(|_| DockerHubError::MalformedResponse)?;
        let record = normalize(self, request, raw, observed_at)?;
        Ok(DockerHubPage {
            records: vec![record],
            next_cursor: None,
        })
    }

    /// Validate terminal progress for persistence after append and projection.
    pub fn checkpoint_candidate(
        &self,
        page: &DockerHubPage,
    ) -> Result<DockerHubCheckpointCandidate, DockerHubError> {
        if page.next_cursor.is_some() || page.records.len() != 1 {
            return Err(DockerHubError::InvalidCursor);
        }
        let record = &page.records[0];
        if record.tenant_id != self.tenant_id || record.family != self.family {
            return Err(DockerHubError::TenantMismatch);
        }
        Ok(DockerHubCheckpointCandidate {
            tenant_id: self.tenant_id.clone(),
            family: self.family,
            cursor: None,
            watermark: record.occurred_at.clone(),
        })
    }
}
