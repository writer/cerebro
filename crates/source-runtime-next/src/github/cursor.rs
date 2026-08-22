use super::{GitHubError, GitHubFamily};

const MAX_CURSOR_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    Primary,
    Members,
    Outside,
    Installations,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CursorToken {
    After(String),
    Page(u32),
}

pub(super) struct CursorState {
    pub(super) stage: Stage,
    pub(super) token: Option<CursorToken>,
}

impl CursorState {
    pub(super) fn decode(family: GitHubFamily, cursor: Option<&str>) -> Result<Self, GitHubError> {
        let default_stage = if family == GitHubFamily::OrganizationInventory {
            Stage::Members
        } else {
            Stage::Primary
        };
        let Some(cursor) = cursor else {
            return Ok(Self {
                stage: default_stage,
                token: None,
            });
        };
        if cursor.is_empty()
            || cursor.len() > MAX_CURSOR_BYTES
            || cursor.chars().any(char::is_control)
        {
            return Err(GitHubError::InvalidCursor);
        }
        let parts = cursor.split('|').collect::<Vec<_>>();
        if parts.len() != 4 || parts[0] != "github-v1" {
            return Err(GitHubError::InvalidCursor);
        }
        let stage = match parts[1] {
            "primary" if family != GitHubFamily::OrganizationInventory => Stage::Primary,
            "members" if family == GitHubFamily::OrganizationInventory => Stage::Members,
            "outside" if family == GitHubFamily::OrganizationInventory => Stage::Outside,
            "installations" if family == GitHubFamily::OrganizationInventory => {
                Stage::Installations
            }
            _ => return Err(GitHubError::InvalidCursor),
        };
        let token = match parts[2] {
            "after" if !parts[3].is_empty() => CursorToken::After(parts[3].to_owned()),
            "page" => CursorToken::Page(
                parts[3]
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(GitHubError::InvalidCursor)?,
            ),
            _ => return Err(GitHubError::InvalidCursor),
        };
        if matches!(token, CursorToken::After(_))
            && matches!(
                family,
                GitHubFamily::Repository
                    | GitHubFamily::OrganizationInventory
                    | GitHubFamily::PullRequest
            )
        {
            return Err(GitHubError::InvalidCursor);
        }
        Ok(Self {
            stage,
            token: Some(token),
        })
    }
}

pub(super) fn encode_cursor(
    stage: &'static str,
    after: Option<&str>,
    page: Option<u32>,
) -> Result<Option<String>, GitHubError> {
    if after.is_some() && page.is_some() {
        return Err(GitHubError::InvalidCursor);
    }
    let cursor = match (after, page) {
        (Some(value), None)
            if !value.is_empty()
                && value.len() <= MAX_CURSOR_BYTES / 2
                && !value.contains('|')
                && !value.chars().any(char::is_control) =>
        {
            Some(format!("github-v1|{stage}|after|{value}"))
        }
        (None, Some(value)) if value > 0 => Some(format!("github-v1|{stage}|page|{value}")),
        (None, None) => None,
        _ => return Err(GitHubError::InvalidCursor),
    };
    Ok(cursor)
}
