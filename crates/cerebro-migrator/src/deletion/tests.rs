use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::planner::plan_maximum_deletion_for_test;
use crate::{
    BatchPlan, DeletionBenefit, DeletionTarget, MigrationStatus, MigrationUnit, MigrationUnitKind,
    MigrationUnitSpec, MigratorError, PlanObjective, plan_maximum_deletion,
};

const CONTRACT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NEXT_REPOSITORY: AtomicU64 = AtomicU64::new(1);

struct TestRepository {
    root: PathBuf,
}

impl TestRepository {
    fn new(files: &[(&str, &[u8])]) -> Self {
        let sequence = NEXT_REPOSITORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cerebro-migrator-deletion-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        run_git(&root, &["init", "--quiet"]);
        run_git(&root, &["config", "user.name", "Cerebro Migrator Test"]);
        run_git(
            &root,
            &["config", "user.email", "cerebro-migrator@example.invalid"],
        );
        let repository = Self { root };
        for (path, bytes) in files {
            repository.write(path, bytes);
        }
        repository.commit_all("initial fixture");
        repository
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let absolute = self.root.join(path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(absolute, bytes).unwrap();
    }

    fn commit_all(&self, message: &str) {
        run_git(&self.root, &["add", "--all"]);
        run_git(&self.root, &["commit", "--quiet", "-m", message]);
    }

    fn head(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD"])
    }
}

impl Drop for TestRepository {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir())
            && self.root.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("cerebro-migrator-deletion-test-")
            })
        {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn applies_exact_regular_files_and_emits_bound_receipt() {
    let repository =
        TestRepository::new(&[("a.go", b"package a\n"), ("nested/b.go", b"package b\n")]);
    let manifest = manifest(&repository, &["nested/b.go", "a.go"]);

    let preflight = verify_deletion_manifest_for_test(repository.path(), &manifest).unwrap();
    assert_eq!(preflight.target_count(), 2);
    assert_eq!(preflight.total_bytes(), 20);
    assert!(repository.path().join("a.go").is_file());

    let receipt = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap();
    assert_eq!(receipt.deleted_files(), 2);
    assert_eq!(receipt.deleted_bytes(), 20);
    assert_eq!(
        receipt.deleted_paths().collect::<Vec<_>>(),
        vec!["a.go", "nested/b.go"]
    );
    assert!(!repository.path().join("a.go").exists());
    assert!(!repository.path().join("nested/b.go").exists());
    receipt.verify().unwrap();
}

#[test]
fn rejects_before_content_digest_mismatch_without_deleting() {
    let repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let manifest = manifest(&repository, &["a.go"]);
    run_git(
        repository.path(),
        &["update-index", "--assume-unchanged", "a.go"],
    );
    repository.write("a.go", b"changed!!\n");
    assert!(git_stdout(repository.path(), &["status", "--porcelain"]).is_empty());

    let error = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap_err();
    assert!(matches!(error, MigratorError::FileDigestMismatch { .. }));
    assert!(repository.path().join("a.go").is_file());
}

#[test]
fn rejects_dirty_worktree_and_base_mismatch() {
    let dirty_repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let dirty_manifest = manifest(&dirty_repository, &["a.go"]);
    dirty_repository.write("untracked.txt", b"dirty\n");
    let error =
        apply_deletion_manifest_for_test(dirty_repository.path(), &dirty_manifest).unwrap_err();
    assert_eq!(error, MigratorError::DirtyWorktree);
    assert!(dirty_repository.path().join("a.go").is_file());

    let advanced_repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let stale_manifest = manifest(&advanced_repository, &["a.go"]);
    advanced_repository.write("new.go", b"package new\n");
    advanced_repository.commit_all("advance base");
    let error =
        verify_deletion_manifest_for_test(advanced_repository.path(), &stale_manifest).unwrap_err();
    assert!(matches!(error, MigratorError::BaseShaMismatch { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_directory_targets() {
    use std::os::unix::fs::symlink;

    let repository = TestRepository::new(&[("real.go", b"package real\n")]);
    symlink("real.go", repository.path().join("linked.go")).unwrap();
    repository.commit_all("add symlink");
    let error = build_manifest(
        &repository,
        vec![eligible_unit(
            &repository,
            "delete/symlink",
            &["linked.go"],
            1,
        )],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidDeletionTarget { ref reason, .. }
            if reason.contains("symbolic links")
    ));

    fs::create_dir(repository.path().join("empty-directory")).unwrap();
    let error = build_manifest(
        &repository,
        vec![eligible_unit(
            &repository,
            "delete/directory",
            &["empty-directory"],
            1,
        )],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidDeletionTarget { ref reason, .. }
            if reason.contains("not a regular file")
    ));
}

#[test]
fn failed_all_target_preflight_leaves_every_file_intact() {
    let repository = TestRepository::new(&[("a.go", b"package a\n"), ("z.go", b"package z\n")]);
    let manifest = manifest(&repository, &["a.go", "z.go"]);
    run_git(
        repository.path(),
        &["update-index", "--assume-unchanged", "z.go"],
    );
    repository.write("z.go", b"changed!!\n");
    assert!(git_stdout(repository.path(), &["status", "--porcelain"]).is_empty());

    let error = apply_deletion_manifest_for_test(repository.path(), &manifest).unwrap_err();
    assert!(matches!(error, MigratorError::FileDigestMismatch { .. }));
    assert!(repository.path().join("a.go").is_file());
    assert!(repository.path().join("z.go").is_file());
}

#[test]
fn candidate_units_and_symbol_targets_cannot_mint_manifest() {
    let repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let candidate = candidate_unit(&repository, "delete/candidate", &["a.go"], 1);
    let plan =
        plan_maximum_deletion(std::slice::from_ref(&candidate), PlanObjective::default()).unwrap();
    let error = bind_deletion_manifest(repository.path(), plan, vec![candidate]).unwrap_err();
    assert_eq!(error, MigratorError::ManifestIneligible);

    let symbol = eligible_symbol_unit(&repository);
    let plan =
        plan_maximum_deletion_for_test(std::slice::from_ref(&symbol), PlanObjective::default())
            .unwrap();
    let error = bind_deletion_manifest_for_test(repository.path(), plan, vec![symbol]).unwrap_err();
    assert_eq!(
        error,
        MigratorError::UnsupportedDeletionTarget("symbol".to_owned())
    );
}

#[test]
fn forged_eligible_unit_json_is_rejected_by_public_verifiers() {
    let repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let forged = eligible_unit(&repository, "delete/forged", &["a.go"], 1);
    let encoded = serde_json::to_vec(&forged).unwrap();
    let error = MigrationUnit::from_json_slice(&encoded).unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidField {
            field: "migration unit status",
            ..
        }
    ));

    let plan =
        plan_maximum_deletion_for_test(std::slice::from_ref(&forged), PlanObjective::default())
            .unwrap();
    let request_json = serde_json::to_vec(&DeletionManifestBuildRequest {
        plan,
        units: vec![forged.clone()],
    })
    .unwrap();
    let request: DeletionManifestBuildRequest = serde_json::from_slice(&request_json).unwrap();
    let error = request.bind(repository.path()).unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidField {
            field: "migration unit status",
            ..
        }
    ));

    let test_manifest = build_manifest(&repository, vec![forged]).unwrap();
    let error = apply_deletion_manifest(repository.path(), &test_manifest).unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidField {
            field: "migration unit status",
            ..
        }
    ));
    assert!(repository.path().join("a.go").is_file());
}

#[test]
fn plan_and_unit_digest_substitution_cannot_mint_manifest() {
    let repository = TestRepository::new(&[("a.go", b"package a\n")]);
    let original = eligible_unit(&repository, "delete/a", &["a.go"], 1);
    let plan =
        plan_maximum_deletion_for_test(std::slice::from_ref(&original), PlanObjective::default())
            .unwrap();

    let substituted = eligible_unit(&repository, "delete/a", &["a.go"], 2);
    let error = bind_deletion_manifest_for_test(repository.path(), plan.clone(), vec![substituted])
        .unwrap_err();
    assert!(matches!(
        error,
        MigratorError::InvalidField {
            field: "manifest selected unit digests",
            ..
        }
    ));

    let mut tampered_json = serde_json::to_value(&plan).unwrap();
    tampered_json["totals"]["production_lines"] = serde_json::json!(9);
    let tampered_plan: BatchPlan = serde_json::from_value(tampered_json).unwrap();
    let error = bind_deletion_manifest_for_test(repository.path(), tampered_plan, vec![original])
        .unwrap_err();
    assert!(matches!(error, MigratorError::DigestMismatch { .. }));
}

fn manifest(repository: &TestRepository, paths: &[&str]) -> DeletionManifest {
    build_manifest(
        repository,
        vec![eligible_unit(repository, "delete/files", paths, 1)],
    )
    .unwrap()
}

fn build_manifest(
    repository: &TestRepository,
    units: Vec<MigrationUnit>,
) -> Result<DeletionManifest, MigratorError> {
    let plan = plan_maximum_deletion_for_test(&units, PlanObjective::default())?;
    bind_deletion_manifest_for_test(repository.path(), plan, units)
}

fn eligible_unit(
    repository: &TestRepository,
    id: &str,
    paths: &[&str],
    production_lines: u64,
) -> MigrationUnit {
    MigrationUnit::bind_deletion_eligible_for_test(unit_spec(
        repository,
        id,
        paths,
        production_lines,
        MigrationStatus::DeletionEligible,
    ))
    .unwrap()
}

fn candidate_unit(
    repository: &TestRepository,
    id: &str,
    paths: &[&str],
    production_lines: u64,
) -> MigrationUnit {
    MigrationUnit::bind(unit_spec(
        repository,
        id,
        paths,
        production_lines,
        MigrationStatus::Candidate,
    ))
    .unwrap()
}

fn unit_spec(
    repository: &TestRepository,
    id: &str,
    paths: &[&str],
    production_lines: u64,
    status: MigrationStatus,
) -> MigrationUnitSpec {
    MigrationUnitSpec {
        id: id.to_owned(),
        kind: MigrationUnitKind::GoPackageComponent,
        base_sha: repository.head(),
        go_owners: vec![format!("package:{id}")],
        production_entrypoints: vec!["cmd/cerebro".to_owned()],
        rust_operation: format!("replace/{id}"),
        contract_digest: CONTRACT_DIGEST.to_owned(),
        prerequisites: Vec::new(),
        authority_gates: vec!["single-writer".to_owned()],
        required_receipts: vec!["parity".to_owned()],
        deletion_targets: paths
            .iter()
            .map(|path| DeletionTarget::Path {
                path: (*path).to_owned(),
            })
            .collect(),
        benefit: DeletionBenefit {
            production_lines,
            ..DeletionBenefit::default()
        },
        effort: 0,
        status,
        blockers: Vec::new(),
    }
}

fn eligible_symbol_unit(repository: &TestRepository) -> MigrationUnit {
    let mut spec = unit_spec(
        repository,
        "delete/symbol",
        &[],
        1,
        MigrationStatus::DeletionEligible,
    );
    spec.deletion_targets = vec![DeletionTarget::Symbol {
        path: "a.go".to_owned(),
        symbol: "OldWriter".to_owned(),
        expected_before_digest: CONTRACT_DIGEST.to_owned(),
    }];
    MigrationUnit::bind_deletion_eligible_for_test(spec).unwrap()
}

fn run_git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
