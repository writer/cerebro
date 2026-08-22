use reqwest::Url;

use super::{
    GitHubError, GitHubFamily, GitHubFilters, GitHubKernel, GitHubRequest, GitHubRequestKind,
    cursor::{CursorState, CursorToken, Stage},
    origin::{name, validate_base_url, validate_tenant_id},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PHRASE_BYTES: usize = 512;

impl GitHubRequest {
    /// HTTP method for every supported read operation.
    pub const fn method(&self) -> &'static str {
        "GET"
    }

    /// Exact provider URL. The trusted host must authorize this origin before I/O.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Planned operation kind.
    pub const fn kind(&self) -> GitHubRequestKind {
        self.kind
    }

    /// Source family owning this request.
    pub const fn family(&self) -> GitHubFamily {
        self.family
    }

    /// Header populated only by the trusted host.
    pub const fn authorization_header(&self) -> &'static str {
        "Authorization"
    }

    /// GitHub accepts a token or an externally minted GitHub App bearer token.
    pub const fn authorization_schemes(&self) -> &'static [&'static str] {
        &["Bearer", "token"]
    }

    /// Public GitHub API version header.
    pub const fn api_version(&self) -> &'static str {
        "2022-11-28"
    }

    /// Required response media type.
    pub const fn accept(&self) -> &'static str {
        "application/vnd.github+json"
    }

    /// Portable requests never contain credential bytes or references.
    pub const fn contains_credentials(&self) -> bool {
        false
    }

    /// Redirects are denied so authentication cannot escape the declared origin.
    pub const fn allows_redirects(&self) -> bool {
        false
    }

    /// Host-side response byte bound.
    pub const fn max_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }

    /// Provider scopes or permissions required by this operation.
    pub const fn required_permissions(&self) -> &'static [&'static str] {
        match self.family {
            GitHubFamily::Audit => &["read:audit_log"],
            GitHubFamily::Repository | GitHubFamily::PullRequest => &["Metadata: read"],
            GitHubFamily::DependabotAlert => &["Dependabot alerts: read"],
            GitHubFamily::OrganizationInventory => &["Members: read"],
            GitHubFamily::SecretScanningAlert => &["Secret scanning alerts: read"],
        }
    }
}

impl GitHubKernel {
    /// Construct one closed GitHub source-family kernel.
    pub fn new(
        base_url: &str,
        tenant_id: &str,
        owner: &str,
        repository: Option<&str>,
        family: GitHubFamily,
        filters: GitHubFilters,
        per_page: Option<usize>,
    ) -> Result<Self, GitHubError> {
        let base_url = validate_base_url(base_url)?;
        let tenant_id = validate_tenant_id(tenant_id)?;
        let owner = name(owner, "owner")?;
        let repository = repository
            .map(|value| name(value, "repository"))
            .transpose()?;
        match family {
            GitHubFamily::DependabotAlert | GitHubFamily::PullRequest if repository.is_none() => {
                return Err(GitHubError::MissingConfiguration("repository"));
            }
            GitHubFamily::Audit
            | GitHubFamily::OrganizationInventory
            | GitHubFamily::SecretScanningAlert
                if repository.is_some() =>
            {
                return Err(GitHubError::InvalidConfiguration("repository"));
            }
            _ => {}
        }
        validate_filters(family, &filters)?;
        let per_page = per_page.unwrap_or(100);
        if !(1..=100).contains(&per_page) {
            return Err(GitHubError::InvalidConfiguration("per_page"));
        }
        Ok(Self {
            base_url,
            tenant_id,
            owner,
            repository,
            family,
            filters,
            per_page,
        })
    }

    /// Plan the next credential-free family operation from a durable cursor.
    pub fn plan(&self, cursor: Option<&str>) -> Result<GitHubRequest, GitHubError> {
        let state = CursorState::decode(self.family, cursor)?;
        let (path, stage) = self.path_for_stage(state.stage)?;
        let mut request = GitHubRequest {
            url: self.endpoint(&path),
            kind: GitHubRequestKind::Family,
            family: self.family,
            stage,
            cursor: cursor.map(ToOwned::to_owned),
        };
        if stage == "singleton" {
            if cursor.is_some() {
                return Err(GitHubError::InvalidCursor);
            }
            return Ok(request);
        }
        {
            let mut query = request.url.query_pairs_mut();
            query.append_pair("per_page", &self.per_page.to_string());
            match state.token {
                Some(CursorToken::After(value)) => query.append_pair("after", &value),
                Some(CursorToken::Page(value)) => query.append_pair("page", &value.to_string()),
                None => &mut query,
            };
            match self.family {
                GitHubFamily::Audit => {
                    query.append_pair(
                        "include",
                        self.filters.audit_include.as_deref().unwrap_or("all"),
                    );
                    query.append_pair(
                        "order",
                        self.filters.audit_order.as_deref().unwrap_or("desc"),
                    );
                    if let Some(phrase) = &self.filters.audit_phrase {
                        query.append_pair("phrase", phrase);
                    }
                }
                GitHubFamily::Repository => {
                    query.append_pair("sort", "updated");
                    query.append_pair("direction", "desc");
                    query.append_pair("type", "all");
                }
                GitHubFamily::DependabotAlert => {
                    if let Some(state) = &self.filters.dependabot_state {
                        query.append_pair("state", state);
                    }
                    query.append_pair("sort", "updated");
                    query.append_pair("direction", "desc");
                }
                GitHubFamily::PullRequest => {
                    query.append_pair(
                        "state",
                        self.filters.pull_request_state.as_deref().unwrap_or("all"),
                    );
                    query.append_pair("sort", "updated");
                    query.append_pair("direction", "desc");
                }
                GitHubFamily::SecretScanningAlert => {
                    if let Some(state) = &self.filters.secret_scanning_state {
                        query.append_pair("state", state);
                    }
                    query.append_pair("sort", "updated");
                    query.append_pair("direction", "desc");
                }
                GitHubFamily::OrganizationInventory => {}
            }
        }
        Ok(request)
    }

    /// Plan the declared repository user fallback after an organization-list 404.
    pub fn plan_repository_user_fallback(
        &self,
        failed: &GitHubRequest,
    ) -> Result<GitHubRequest, GitHubError> {
        if self.family != GitHubFamily::Repository
            || self.repository.is_some()
            || failed != &self.plan(failed.cursor.as_deref())?
        {
            return Err(GitHubError::RequestScopeMismatch);
        }
        let mut request = failed.clone();
        request.kind = GitHubRequestKind::RepositoryUserFallback;
        request.url = self.endpoint(&format!("/users/{}/repos", self.owner));
        let state = CursorState::decode(self.family, failed.cursor.as_deref())?;
        {
            let mut query = request.url.query_pairs_mut();
            query.append_pair("per_page", &self.per_page.to_string());
            if let Some(CursorToken::Page(page)) = state.token {
                query.append_pair("page", &page.to_string());
            }
            query.append_pair("sort", "updated");
            query.append_pair("direction", "desc");
            query.append_pair("type", "all");
        }
        Ok(request)
    }

    /// Plan the bounded public user lookup required for a GitHub audit actor.
    pub fn plan_actor_resolution(&self, actor: &str) -> Result<GitHubRequest, GitHubError> {
        if self.family != GitHubFamily::Audit {
            return Err(GitHubError::RequestScopeMismatch);
        }
        let actor = name(actor, "actor")?;
        Ok(GitHubRequest {
            url: self.endpoint(&format!("/users/{actor}")),
            kind: GitHubRequestKind::AuditActor,
            family: self.family,
            stage: "actor",
            cursor: None,
        })
    }

    fn path_for_stage(&self, stage: Stage) -> Result<(String, &'static str), GitHubError> {
        let value = match (self.family, stage) {
            (GitHubFamily::Audit, Stage::Primary) => {
                (format!("/orgs/{}/audit-log", self.owner), "primary")
            }
            (GitHubFamily::Repository, Stage::Primary) if self.repository.is_some() => (
                format!(
                    "/repos/{}/{}",
                    self.owner,
                    self.repository.as_deref().unwrap_or_default()
                ),
                "singleton",
            ),
            (GitHubFamily::Repository, Stage::Primary) => {
                (format!("/orgs/{}/repos", self.owner), "primary")
            }
            (GitHubFamily::DependabotAlert, Stage::Primary) => (
                format!(
                    "/repos/{}/{}/dependabot/alerts",
                    self.owner,
                    self.repository.as_deref().unwrap_or_default()
                ),
                "primary",
            ),
            (GitHubFamily::PullRequest, Stage::Primary) => (
                format!(
                    "/repos/{}/{}/pulls",
                    self.owner,
                    self.repository.as_deref().unwrap_or_default()
                ),
                "primary",
            ),
            (GitHubFamily::SecretScanningAlert, Stage::Primary) => (
                format!("/orgs/{}/secret-scanning/alerts", self.owner),
                "primary",
            ),
            (GitHubFamily::OrganizationInventory, Stage::Members) => {
                (format!("/orgs/{}/members", self.owner), "members")
            }
            (GitHubFamily::OrganizationInventory, Stage::Outside) => (
                format!("/orgs/{}/outside_collaborators", self.owner),
                "outside_collaborators",
            ),
            (GitHubFamily::OrganizationInventory, Stage::Installations) => (
                format!("/orgs/{}/installations", self.owner),
                "installations",
            ),
            _ => return Err(GitHubError::InvalidCursor),
        };
        Ok(value)
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "{}{}",
            self.base_url.path().trim_end_matches('/'),
            path
        ));
        url.set_query(None);
        url.set_fragment(None);
        url
    }
}

fn validate_filters(family: GitHubFamily, filters: &GitHubFilters) -> Result<(), GitHubError> {
    if filters
        .audit_phrase
        .as_ref()
        .is_some_and(|value| value.len() > MAX_PHRASE_BYTES || value.chars().any(char::is_control))
    {
        return Err(GitHubError::InvalidConfiguration("audit_phrase"));
    }
    allowed(
        filters.audit_include.as_deref(),
        &["all", "web", "git"],
        "audit_include",
    )?;
    allowed(
        filters.audit_order.as_deref(),
        &["asc", "desc"],
        "audit_order",
    )?;
    allowed(
        filters.pull_request_state.as_deref(),
        &["all", "open", "closed"],
        "pull_request_state",
    )?;
    allowed(
        filters.dependabot_state.as_deref(),
        &["auto_dismissed", "dismissed", "fixed", "open"],
        "dependabot_state",
    )?;
    allowed(
        filters.secret_scanning_state.as_deref(),
        &["open", "resolved"],
        "secret_scanning_state",
    )?;
    let audit = filters.audit_include.is_some()
        || filters.audit_phrase.is_some()
        || filters.audit_order.is_some();
    if audit && family != GitHubFamily::Audit {
        return Err(GitHubError::InvalidConfiguration("audit_filters"));
    }
    if filters.pull_request_state.is_some() && family != GitHubFamily::PullRequest {
        return Err(GitHubError::InvalidConfiguration("pull_request_state"));
    }
    if filters.dependabot_state.is_some() && family != GitHubFamily::DependabotAlert {
        return Err(GitHubError::InvalidConfiguration("dependabot_state"));
    }
    if filters.secret_scanning_state.is_some() && family != GitHubFamily::SecretScanningAlert {
        return Err(GitHubError::InvalidConfiguration("secret_scanning_state"));
    }
    Ok(())
}

fn allowed(value: Option<&str>, allowed: &[&str], field: &'static str) -> Result<(), GitHubError> {
    if value.is_some_and(|value| !allowed.contains(&value.trim())) {
        return Err(GitHubError::InvalidConfiguration(field));
    }
    Ok(())
}
