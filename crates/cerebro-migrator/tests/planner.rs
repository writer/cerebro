use cerebro_migrator::{
    DeletionBenefit, DeletionTarget, MigrationStatus, MigrationUnit, MigrationUnitKind,
    MigrationUnitSpec, PlanObjective, PlanRequest, plan_maximum_deletion,
};

const BASE_SHA: &str = "d73291696ef32079c1bfa2ff110d12539f89a640";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn unit(
    id: &str,
    prerequisites: &[&str],
    production_lines: u64,
    effort: u64,
    status: MigrationStatus,
) -> MigrationUnit {
    MigrationUnit::bind(MigrationUnitSpec {
        id: id.to_owned(),
        kind: MigrationUnitKind::SourceFamily,
        base_sha: BASE_SHA.to_owned(),
        go_owners: vec![format!("package:{id}")],
        production_entrypoints: vec!["cmd/cerebro".to_owned()],
        rust_operation: format!("migrate_{id}"),
        contract_digest: DIGEST.to_owned(),
        prerequisites: prerequisites
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authority_gates: vec!["single-writer".to_owned()],
        required_receipts: vec!["parity".to_owned()],
        deletion_targets: Vec::new(),
        benefit: DeletionBenefit {
            production_lines,
            ..DeletionBenefit::default()
        },
        effort,
        status,
        blockers: if status == MigrationStatus::Blocked {
            vec!["active-owner".to_owned()]
        } else {
            Vec::new()
        },
    })
    .unwrap()
}

#[test]
fn selects_exact_maximum_weight_prerequisite_closure() {
    let capability = unit("runtime/http", &[], 0, 6, MigrationStatus::Candidate);
    let source = unit(
        "source/openai/models",
        &["runtime/http"],
        10,
        0,
        MigrationStatus::Generated,
    );
    let independent = unit("source/slack/users", &[], 3, 0, MigrationStatus::Qualified);
    let uneconomic = unit(
        "source/bespoke/report",
        &[],
        1,
        5,
        MigrationStatus::Candidate,
    );
    let objective = PlanObjective {
        production_line_weight: 1,
        test_line_weight: 0,
        package_weight: 0,
        runtime_entrypoint_weight: 0,
        effort_weight: 1,
    };

    let plan =
        plan_maximum_deletion(&[capability, source, independent, uneconomic], objective).unwrap();
    assert_eq!(
        plan.selected_unit_ids(),
        &["runtime/http", "source/openai/models", "source/slack/users"]
    );
    assert_eq!(plan.totals().production_lines, 13);
    assert_eq!(plan.totals().effort, 6);
    assert_eq!(plan.totals().objective_score, 7);
    assert_eq!(plan.excluded_units()[0].id, "source/bespoke/report");
    plan.verify().unwrap();
}

#[test]
fn blocked_prerequisite_excludes_dependent_deletion() {
    let blocked = unit("runtime/credential", &[], 0, 0, MigrationStatus::Blocked);
    let dependent = unit(
        "source/provider/records",
        &["runtime/credential"],
        100,
        0,
        MigrationStatus::Qualified,
    );
    let plan = plan_maximum_deletion(&[dependent, blocked], PlanObjective::default()).unwrap();
    assert!(plan.selected_unit_ids().is_empty());
    assert_eq!(plan.excluded_units().len(), 2);
    assert_eq!(plan.excluded_units()[0].id, "runtime/credential");
    assert!(plan.excluded_units()[0].reason.starts_with("blocked:"));
}

#[test]
fn normalized_units_and_plans_are_deterministic() {
    let first = unit("source/a/records", &[], 12, 1, MigrationStatus::Candidate);
    let second = unit("source/b/records", &[], 7, 1, MigrationStatus::Candidate);
    let objective = PlanObjective::default();
    let forward = plan_maximum_deletion(&[first.clone(), second.clone()], objective).unwrap();
    let reverse = plan_maximum_deletion(&[second, first], objective).unwrap();
    assert_eq!(forward, reverse);

    let encoded = serde_json::to_vec(&forward).unwrap();
    let decoded: cerebro_migrator::BatchPlan = serde_json::from_slice(&encoded).unwrap();
    decoded.verify().unwrap();
}

#[test]
fn bound_unit_rejects_content_substitution() {
    let original = unit("source/a/records", &[], 12, 1, MigrationStatus::Candidate);
    let mut encoded = serde_json::to_value(&original).unwrap();
    encoded["unit"]["benefit"]["production_lines"] = serde_json::json!(13);
    let error = MigrationUnit::from_json_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap_err();
    assert!(matches!(
        error,
        cerebro_migrator::MigratorError::DigestMismatch { .. }
    ));
}

#[test]
fn bound_plan_rejects_content_substitution() {
    let source = unit("source/a/records", &[], 12, 1, MigrationStatus::Candidate);
    let plan = plan_maximum_deletion(&[source], PlanObjective::default()).unwrap();
    let mut encoded = serde_json::to_value(&plan).unwrap();
    encoded["totals"]["production_lines"] = serde_json::json!(13);
    let error =
        cerebro_migrator::BatchPlan::from_json_slice(&serde_json::to_vec(&encoded).unwrap())
            .unwrap_err();
    assert!(matches!(
        error,
        cerebro_migrator::MigratorError::DigestMismatch { .. }
    ));
}

#[test]
fn migration_unit_rejects_non_exact_deletion_paths() {
    let mut spec = unit("source/a/records", &[], 12, 1, MigrationStatus::Candidate)
        .spec()
        .clone();
    spec.deletion_targets = vec![DeletionTarget::Path {
        path: "internal/sourceprojection/**/*.go".to_owned(),
    }];
    let error = MigrationUnit::bind(spec).unwrap_err();
    assert!(matches!(
        error,
        cerebro_migrator::MigratorError::InvalidField {
            field: "deletion target path",
            ..
        }
    ));
}

#[test]
fn raw_unit_binding_cannot_assert_deletion_authority() {
    let mut spec = unit("source/a/records", &[], 12, 1, MigrationStatus::Candidate)
        .spec()
        .clone();
    spec.status = MigrationStatus::DeletionEligible;
    let error = MigrationUnit::bind(spec).unwrap_err();
    assert!(matches!(
        error,
        cerebro_migrator::MigratorError::InvalidField {
            field: "migration unit status",
            ..
        }
    ));

    let mut request_spec = unit("source/b/records", &[], 12, 1, MigrationStatus::Candidate)
        .spec()
        .clone();
    request_spec.status = MigrationStatus::DeletionEligible;
    let error = PlanRequest {
        objective: PlanObjective::default(),
        units: vec![request_spec],
    }
    .plan()
    .unwrap_err();
    assert!(matches!(
        error,
        cerebro_migrator::MigratorError::InvalidField {
            field: "migration unit status",
            ..
        }
    ));
}
