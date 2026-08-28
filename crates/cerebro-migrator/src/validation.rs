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

#[cfg(test)]
mod tests {
    use super::{
        validate_digest, validate_exact_file_path, validate_git_sha, validate_identifier,
        validate_nonempty,
    };

    #[test]
    fn closed_scalar_validators_accept_canonical_values() {
        validate_identifier("source/example.items:v1", "unit id").unwrap();
        validate_nonempty("value", "field").unwrap();
        validate_git_sha(&"a".repeat(40), "base SHA").unwrap();
        validate_digest(&format!("sha256:{}", "b".repeat(64)), "digest").unwrap();
        validate_exact_file_path("internal/source/file.go").unwrap();
    }

    #[test]
    fn closed_scalar_validators_reject_noncanonical_values() {
        assert!(validate_identifier("source item", "unit id").is_err());
        assert!(validate_identifier(&"a".repeat(257), "unit id").is_err());
        assert!(validate_nonempty(" \t", "field").is_err());
        assert!(validate_git_sha(&"A".repeat(40), "base SHA").is_err());
        assert!(validate_git_sha("abc", "base SHA").is_err());
        assert!(validate_digest(&"a".repeat(64), "digest").is_err());
        assert!(validate_digest(&format!("sha256:{}", "A".repeat(64)), "digest").is_err());

        for path in [
            "",
            "/absolute.go",
            "directory/",
            "directory\\file.go",
            "directory//file.go",
            "directory/./file.go",
            "directory/../file.go",
            ".git/config",
            "*.go",
            "file?.go",
            "file[0].go",
            "file{old}.go",
        ] {
            assert!(validate_exact_file_path(path).is_err(), "accepted {path:?}");
        }
    }
}
