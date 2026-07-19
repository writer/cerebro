use super::*;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cerebro-graphactiongen-test-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn action(
    id: &str,
    const_name: &str,
    target_kind: &str,
    target_kind_const: &str,
) -> ActionCatalogEntry {
    ActionCatalogEntry {
        id: id.to_owned(),
        const_name: const_name.to_owned(),
        provider: "access-approvals".to_owned(),
        provider_const: "ProviderAccessApprovals".to_owned(),
        provider_action: "suspend".to_owned(),
        provider_action_const: "AccessApprovalsActionSuspend".to_owned(),
        target_kind: target_kind.to_owned(),
        target_kind_const: target_kind_const.to_owned(),
        target_resolver: "OktaUserTargetForFinding".to_owned(),
        eligibility_checker: "FindingAllowsAction".to_owned(),
        effect: "deny_access".to_owned(),
        ..Default::default()
    }
}

#[test]
fn rejects_unknown_reversible_action() {
    let mut entry = action(
        "identity.okta.suspend_user",
        "ActionIdentityOktaSuspendUser",
        "identity.okta.user",
        "TargetKindOktaUser",
    );
    entry.reversible_by = "identity.okta.unsuspend_user".to_owned();
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![entry],
    })
    .unwrap_err();
    assert!(error.to_string().contains("unknown action"), "{error}");
}

#[test]
fn rejects_conflicting_target_kind_constant() {
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![
            action(
                "identity.okta.suspend_user",
                "ActionIdentityOktaSuspendUser",
                "identity.okta.user",
                "TargetKindOktaUser",
            ),
            action(
                "identity.okta.disable_user",
                "ActionIdentityOktaDisableUser",
                "identity.okta.account",
                "TargetKindOktaUser",
            ),
        ],
    })
    .unwrap_err();
    assert!(error.to_string().contains("target_kind_const"), "{error}");
}

#[test]
fn rejects_conflicting_provider_constants() {
    let first = action(
        "identity.okta.suspend_user",
        "ActionIdentityOktaSuspendUser",
        "identity.okta.user",
        "TargetKindOktaUser",
    );
    let mut second = action(
        "identity.generic.lock_user",
        "ActionIdentityGenericLockUser",
        "identity.generic.user",
        "TargetKindGenericUser",
    );
    second.provider = "generic-idp".to_owned();
    second.provider_const = first.provider_const.clone();
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![first, second],
    })
    .unwrap_err();
    assert!(error.to_string().contains("provider_const"), "{error}");
}

#[test]
fn rejects_conflicting_provider_action_constants() {
    let first = action(
        "identity.okta.suspend_user",
        "ActionIdentityOktaSuspendUser",
        "identity.okta.user",
        "TargetKindOktaUser",
    );
    let mut second = action(
        "identity.okta.disable_user",
        "ActionIdentityOktaDisableUser",
        "identity.okta.user",
        "TargetKindOktaUser",
    );
    second.provider_action = "disable".to_owned();
    second.provider_action_const = first.provider_action_const.clone();
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![first, second],
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("provider_action_const"),
        "{error}"
    );
}

#[test]
fn rejects_duplicate_action_ids_and_invalid_go_identifiers() {
    let first = action(
        "identity.okta.suspend_user",
        "ActionIdentityOktaSuspendUser",
        "identity.okta.user",
        "TargetKindOktaUser",
    );
    let mut duplicate = first.clone();
    duplicate.const_name = "ActionIdentityOktaSuspendUserAgain".to_owned();
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![first.clone(), duplicate],
    })
    .unwrap_err();
    assert!(error.to_string().contains("duplicate action id"), "{error}");

    let mut invalid = first;
    invalid.target_resolver = "not-a-go-identifier".to_owned();
    let error = validate_catalog(&ActionCatalog {
        version: "graph-actions.cerebro/v1alpha1".to_owned(),
        actions: vec![invalid],
    })
    .unwrap_err();
    assert!(error.to_string().contains("not a Go identifier"), "{error}");
}

#[test]
fn rejects_oversized_catalog() {
    let root = TestDir::new();
    let path = root.0.join(DEFAULT_CATALOG_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, vec![b'x'; MAX_GENERATED_FILE_BYTES + 1]).unwrap();
    let error = generate(&root.0, Path::new(DEFAULT_CATALOG_PATH)).unwrap_err();
    assert!(error.to_string().contains("exceeds"), "{error}");
}

#[test]
fn bounded_read_error_preserves_the_actual_path() {
    let root = TestDir::new();
    let expected = root.0.join("write-only");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&expected)
        .unwrap();
    let error = read_limited(file, "test file", &expected).unwrap_err();
    match error {
        Error::Io { path, .. } => assert_eq!(path, expected),
        other => panic!("expected an I/O error, got {other}"),
    }
}

#[test]
fn catalog_decode_rejects_unknown_fields() {
    let root = TestDir::new();
    let path = root.0.join(DEFAULT_CATALOG_PATH);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        b"version: graph-actions.cerebro/v1alpha1\nactions: []\nunknown: true\n",
    )
    .unwrap();
    let error = generate(&root.0, Path::new(DEFAULT_CATALOG_PATH)).unwrap_err();
    assert!(matches!(error, Error::CatalogDecode { .. }));
    assert!(error.to_string().contains("unknown field"), "{error}");
}

#[cfg(unix)]
#[test]
fn reports_unix_as_a_supported_generation_platform() {
    ensure_supported_platform().unwrap();
}

#[cfg(not(unix))]
#[test]
fn reports_non_unix_generation_as_unsupported() {
    assert!(matches!(
        ensure_supported_platform(),
        Err(Error::UnsupportedPlatform)
    ));
}

#[cfg(unix)]
#[test]
fn generated_file_io_rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let root = TestDir::new();
    let target = root.0.join("target.go");
    fs::write(&target, b"package p\n").unwrap();
    let link = root.0.join("registry_gen.go");
    symlink(&target, &link).unwrap();
    let write_error = write_generated_file(&link, b"package graphactions\n").unwrap_err();
    assert!(write_error.to_string().contains("symlink"), "{write_error}");
    let read_error = read_generated_file(&link).unwrap_err();
    assert!(read_error.to_string().contains("symlink"), "{read_error}");
}

#[cfg(unix)]
#[test]
fn generated_file_write_is_atomic_and_sets_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = TestDir::new();
    let path = root.0.join("nested/registry_gen.go");
    write_generated_file(&path, b"package graphactions\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"package graphactions\n");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let leftovers = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn checked_in_catalog_matches_generated_registry() {
    let root = Path::new("../..");
    let generated = generate(root, Path::new(DEFAULT_CATALOG_PATH)).unwrap();
    let existing = fs::read(root.join(DEFAULT_OUTPUT_PATH)).unwrap();
    assert_eq!(trim_ascii(&existing), trim_ascii(&generated));
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &value[start..end]
}
