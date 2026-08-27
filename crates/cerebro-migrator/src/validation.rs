use crate::MigratorError;

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<(), MigratorError> {
    validate_nonempty(value, field)?;
    if value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b':' | b'_' | b'-')
        })
    {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must be at most 256 ASCII identifier characters".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_nonempty(value: &str, field: &'static str) -> Result<(), MigratorError> {
    if value.trim().is_empty() {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must not be empty".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_git_sha(value: &str, field: &'static str) -> Result<(), MigratorError> {
    if value.len() != 40 || !value.bytes().all(is_lower_hex) {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must be a full lowercase 40-character hexadecimal Git commit".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), MigratorError> {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must start with sha256:".to_owned(),
        });
    };
    if encoded.len() != 64 || !encoded.bytes().all(is_lower_hex) {
        return Err(MigratorError::InvalidField {
            field,
            reason: "must contain exactly 64 lowercase hexadecimal characters".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_exact_file_path(path: &str) -> Result<(), MigratorError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".." | ".git"))
        || path.contains('*')
        || path.contains('?')
        || path.contains('[')
        || path.contains(']')
        || path.contains('{')
        || path.contains('}')
    {
        return Err(MigratorError::InvalidField {
            field: "deletion target path",
            reason: format!("{path:?} is not an exact repository-relative file path"),
        });
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}
