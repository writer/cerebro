use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    GitHubActorResolution, GitHubCheckpointCandidate, GitHubContinuation, GitHubError,
    GitHubFamily, GitHubKernel, GitHubPage, GitHubRequest, GitHubRequestKind,
    cursor::encode_cursor,
    normalize::{normalize_record, scalar_at},
    request::MAX_RESPONSE_BYTES,
};

impl GitHubKernel {
    /// Validate a page's durable progress candidate.
    ///
    /// This does not mutate a checkpoint. The trusted host must append and
    /// project first, re-check its lease fence, and only then persist it.
    pub fn checkpoint_candidate(
        &self,
        request: &GitHubRequest,
        page: &GitHubPage,
        prior_watermark: Option<&str>,
    ) -> Result<GitHubCheckpointCandidate, GitHubError> {
        self.validate_request(request)?;
        if page.records.iter().any(|record| {
            record.tenant_id != self.tenant_id || record.family != self.family.as_str()
        }) {
            return Err(GitHubError::TenantMismatch);
        }
        if let Some(cursor) = &page.next_cursor {
            self.plan(Some(cursor))?;
        }
        let prior_watermark = prior_watermark.map(validate_watermark).transpose()?;
        let watermark = page
            .records
            .iter()
            .map(|record| record.occurred_at.clone())
            .chain(prior_watermark)
            .max();
        Ok(GitHubCheckpointCandidate {
            tenant_id: self.tenant_id.clone(),
            family: self.family,
            cursor: page.next_cursor.clone(),
            watermark,
        })
    }

    /// Classify a family response and normalize its bounded provider records.
    ///
    /// The trusted host owns DNS, connection establishment, egress policy,
    /// deadlines, redirects, credential application, and response buffering.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_http(
        &self,
        request: &GitHubRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        continuation: GitHubContinuation,
        body: &[u8],
        observed_at: Option<&str>,
        actor_resolutions: &[GitHubActorResolution],
    ) -> Result<GitHubPage, GitHubError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GitHubError::ResponseTooLarge);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(GitHubError::InvalidRetryAfter);
        }
        match status {
            200 => self.decode_success(request, continuation, body, observed_at, actor_resolutions),
            401 => Err(GitHubError::AuthenticationRejected),
            403 if retry_after_seconds.is_some() => Err(GitHubError::RateLimited {
                retry_after_seconds,
            }),
            403 => Err(GitHubError::RequiredScopeMissing),
            404 if self.family == GitHubFamily::Repository
                && self.repository.is_none()
                && request.kind == GitHubRequestKind::Family =>
            {
                Err(GitHubError::OrganizationNotFound)
            }
            429 => Err(GitHubError::RateLimited {
                retry_after_seconds,
            }),
            500..=599 => Err(GitHubError::ProviderUnavailable { status }),
            _ => Err(GitHubError::UnexpectedStatus { status }),
        }
    }

    /// Decode one successful family response.
    pub fn decode(
        &self,
        request: &GitHubRequest,
        continuation: GitHubContinuation,
        body: &[u8],
        observed_at: Option<&str>,
        actor_resolutions: &[GitHubActorResolution],
    ) -> Result<GitHubPage, GitHubError> {
        self.decode_http(
            request,
            200,
            None,
            continuation,
            body,
            observed_at,
            actor_resolutions,
        )
    }

    /// Decode a separately planned audit-actor public lookup.
    pub fn decode_actor_resolution(
        &self,
        request: &GitHubRequest,
        status: u16,
        body: &[u8],
    ) -> Result<GitHubActorResolution, GitHubError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(GitHubError::ResponseTooLarge);
        }
        if self.family != GitHubFamily::Audit
            || request.kind != GitHubRequestKind::AuditActor
            || request.family != self.family
        {
            return Err(GitHubError::RequestScopeMismatch);
        }
        let actor = request
            .url
            .path_segments()
            .and_then(Iterator::last)
            .filter(|value| !value.is_empty())
            .ok_or(GitHubError::RequestScopeMismatch)?
            .to_owned();
        if status == 404 {
            return Ok(GitHubActorResolution {
                actor,
                actor_type: "Unresolved".to_owned(),
                actor_id: None,
                actor_email: None,
            });
        }
        match status {
            200 => {}
            401 => return Err(GitHubError::AuthenticationRejected),
            403 => return Err(GitHubError::RequiredScopeMissing),
            429 => {
                return Err(GitHubError::RateLimited {
                    retry_after_seconds: None,
                });
            }
            500..=599 => return Err(GitHubError::ProviderUnavailable { status }),
            _ => return Err(GitHubError::UnexpectedStatus { status }),
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| GitHubError::MalformedResponse)?;
        reject_credential_material(&value)?;
        let values = value.as_object().ok_or(GitHubError::MalformedResponse)?;
        let login = scalar_at(values, "login").ok_or(GitHubError::InvalidProviderRecord)?;
        if !login.eq_ignore_ascii_case(&actor) {
            return Err(GitHubError::RequestScopeMismatch);
        }
        let actor_type = scalar_at(values, "type").unwrap_or_else(|| "User".to_owned());
        let actor_id = values
            .get("id")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0);
        let actor_email = scalar_at(values, "email");
        Ok(GitHubActorResolution {
            actor: login,
            actor_type,
            actor_id,
            actor_email,
        })
    }

    fn decode_success(
        &self,
        request: &GitHubRequest,
        continuation: GitHubContinuation,
        body: &[u8],
        observed_at: Option<&str>,
        actor_resolutions: &[GitHubActorResolution],
    ) -> Result<GitHubPage, GitHubError> {
        if continuation.after.is_some() && continuation.page.is_some() {
            return Err(GitHubError::InvalidCursor);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| GitHubError::MalformedResponse)?;
        reject_credential_material(&value)?;
        let records = response_records(self.family, request.stage, value)?;
        if records.len() > self.per_page {
            return Err(GitHubError::TooManyRecords);
        }
        let mut seen = BTreeMap::<String, Value>::new();
        let mut normalized = Vec::with_capacity(records.len());
        for raw in records {
            let record = normalize_record(
                self,
                request.stage,
                raw.clone(),
                observed_at,
                actor_resolutions,
            )?;
            match seen.get(&record.provider_id) {
                Some(previous) if previous == &raw => continue,
                Some(_) => return Err(GitHubError::ConflictingDuplicate),
                None => {
                    seen.insert(record.provider_id.clone(), raw);
                    normalized.push(record);
                }
            }
        }
        let next_cursor = self.next_cursor(request, continuation)?;
        Ok(GitHubPage {
            records: normalized,
            next_cursor,
        })
    }

    fn next_cursor(
        &self,
        request: &GitHubRequest,
        continuation: GitHubContinuation,
    ) -> Result<Option<String>, GitHubError> {
        let stage = match request.stage {
            "primary" | "singleton" => "primary",
            "members" => "members",
            "outside_collaborators" => "outside",
            "installations" => "installations",
            _ => return Err(GitHubError::RequestScopeMismatch),
        };
        if let Some(cursor) =
            encode_cursor(stage, continuation.after.as_deref(), continuation.page)?
        {
            return Ok(Some(cursor));
        }
        if self.family != GitHubFamily::OrganizationInventory {
            return Ok(None);
        }
        match request.stage {
            "members" => Ok(Some("github-v1|outside|page|1".to_owned())),
            "outside_collaborators" => Ok(Some("github-v1|installations|page|1".to_owned())),
            "installations" => Ok(None),
            _ => Err(GitHubError::RequestScopeMismatch),
        }
    }

    fn validate_request(&self, request: &GitHubRequest) -> Result<(), GitHubError> {
        let expected = match request.kind {
            GitHubRequestKind::Family => self.plan(request.cursor.as_deref())?,
            GitHubRequestKind::RepositoryUserFallback => {
                let primary = self.plan(request.cursor.as_deref())?;
                self.plan_repository_user_fallback(&primary)?
            }
            GitHubRequestKind::AuditActor => return Err(GitHubError::RequestScopeMismatch),
        };
        if &expected != request {
            return Err(GitHubError::RequestScopeMismatch);
        }
        Ok(())
    }
}

fn validate_watermark(value: &str) -> Result<String, GitHubError> {
    let values = serde_json::Map::from_iter([("watermark".to_owned(), Value::from(value))]);
    super::normalize::timestamp_optional(&values, "watermark")?
        .ok_or(GitHubError::InvalidProviderRecord)
}

fn response_records(
    family: GitHubFamily,
    stage: &str,
    value: Value,
) -> Result<Vec<Value>, GitHubError> {
    if family == GitHubFamily::Repository && stage == "singleton" {
        return value
            .is_object()
            .then(|| vec![value])
            .ok_or(GitHubError::MalformedResponse);
    }
    if family == GitHubFamily::OrganizationInventory && stage == "installations" {
        return value
            .as_object()
            .and_then(|values| values.get("installations"))
            .and_then(Value::as_array)
            .cloned()
            .ok_or(GitHubError::MalformedResponse);
    }
    value
        .as_array()
        .cloned()
        .ok_or(GitHubError::MalformedResponse)
}

fn reject_credential_material(value: &Value) -> Result<(), GitHubError> {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                let credential_key = matches!(
                    key.as_str(),
                    "authorization"
                        | "api_key"
                        | "api_token"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "private_key"
                        | "password"
                        | "token"
                        | "secret"
                );
                if credential_key && !empty_value(value) {
                    return Err(GitHubError::CredentialMaterial);
                }
                reject_credential_material(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_credential_material(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn empty_value(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(str::is_empty)
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}
