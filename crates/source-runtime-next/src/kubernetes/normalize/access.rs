//! Service-account, workload-identity, and RBAC normalization.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::kubernetes::{
    KubernetesError, KubernetesFamily, KubernetesKernel, KubernetesRecord, KubernetesRequest,
    cursor::RbacStage, request::first_nonempty,
};

use super::common::*;

pub(super) fn normalize_service_account(
    kernel: &KubernetesKernel,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let mut attributes = base_attributes(kernel, "service_account", uid, name, namespace);
    attributes.insert("service_account_name".to_owned(), name.to_owned());
    attributes.insert("uid".to_owned(), uid.to_owned());
    if let Some(value) = object
        .get("automountServiceAccountToken")
        .and_then(Value::as_bool)
    {
        attributes.insert("automount_token".to_owned(), bool_string(value).to_owned());
    }
    let annotations = annotations(metadata);
    insert_nonempty(
        &mut attributes,
        "aws_role_arn",
        annotations
            .get("eks.amazonaws.com/role-arn")
            .map_or("", String::as_str),
    );
    insert_nonempty(
        &mut attributes,
        "gcp_service_account",
        annotations
            .get("iam.gke.io/gcp-service-account")
            .map_or("", String::as_str),
    );
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "automount_service_account_token": object.get("automountServiceAccountToken").cloned().unwrap_or(Value::Null),
        "annotations": serde_json::to_value(&annotations).unwrap_or_else(|_| json!({})),
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::ServiceAccount,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-service-account-{}",
                sha256(&format!("{}/{namespace}/{name}", kernel.cluster_id))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_service_account",
                &[&kernel.cluster_id, namespace, name],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}

pub(super) fn normalize_workload_identity(
    kernel: &KubernetesKernel,
    _object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<Vec<KubernetesRecord>, KubernetesError> {
    let name = required(metadata, "name")?;
    let namespace = required(metadata, "namespace")?;
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let annotations = annotations(metadata);
    let bindings = [
        (
            "aws",
            "role",
            "irsa",
            annotations.get("eks.amazonaws.com/role-arn"),
        ),
        (
            "gcp",
            "service_account",
            "gke_workload_identity",
            annotations.get("iam.gke.io/gcp-service-account"),
        ),
    ];
    bindings
        .into_iter()
        .filter_map(|(provider, target_type, relationship, target)| {
            target
                .map(|target| (provider, target_type, relationship, target))
                .filter(|(_, _, _, target)| !target.trim().is_empty())
        })
        .map(|(provider, target_type, relationship, target)| {
            let mut attributes = base_attributes(kernel, "service_account", uid, name, namespace);
            for (key, value) in [
                ("service_account_name", name),
                ("uid", uid),
                ("cloud_provider", provider),
                ("target_type", target_type),
                ("target_id", target.as_str()),
                ("relationship", relationship),
            ] {
                attributes.insert(key.to_owned(), value.to_owned());
            }
            match provider {
                "aws" => {
                    attributes.insert("aws_role_arn".to_owned(), target.clone());
                    attributes.insert("cloud_principal_arn".to_owned(), target.clone());
                }
                "gcp" => {
                    attributes.insert("gcp_service_account".to_owned(), target.clone());
                    attributes.insert("target_email".to_owned(), target.clone());
                    attributes.insert("cloud_principal_email".to_owned(), target.clone());
                }
                _ => {}
            }
            let payload = serde_json::to_value(&attributes)
                .map_err(|_| KubernetesError::MalformedResponse)?;
            let provider_id = format!("{namespace}/{name}/{provider}/{target}");
            build_record(
                kernel,
                RecordParts {
                    family: KubernetesFamily::WorkloadIdentityBinding,
                    provider_id,
                    event_id: format!(
                        "kubernetes-workload-identity-binding-{}",
                        sha256(&format!(
                            "{}/{namespace}/{name}/{provider}/{target}",
                            kernel.cluster_id
                        ))
                    ),
                    canonical_urn: canonical_urn(
                        &kernel.tenant_id,
                        "kubernetes_workload_identity_binding",
                        &[&kernel.cluster_id, namespace, name, provider, target],
                    )?,
                    attributes,
                    payload,
                    occurred_at: object_time(metadata, observed_at),
                },
            )
        })
        .collect()
}

pub(super) fn normalize_rbac_role(
    kernel: &KubernetesKernel,
    request: &KubernetesRequest,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let kind = match request.rbac_stage {
        Some(RbacStage::Role) => "Role",
        Some(RbacStage::ClusterRole) => "ClusterRole",
        _ => return Err(KubernetesError::RequestScopeMismatch),
    };
    let name = required(metadata, "name")?;
    let namespace = string(metadata, "namespace");
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let rules = array_or_empty(object.get("rules"));
    let scope = if namespace.is_empty() {
        "cluster"
    } else {
        "namespace"
    };
    let mut attributes = base_attributes(kernel, "rbac_role", uid, name, namespace);
    for (key, value) in [
        ("uid", uid),
        ("role_kind", kind),
        ("role_name", name),
        ("role_scope", scope),
    ] {
        attributes.insert(key.to_owned(), value.to_owned());
    }
    attributes.insert("rules".to_owned(), rbac_rule_summaries(&rules).join(";"));
    for (attribute, field) in [
        ("api_groups", "apiGroups"),
        ("resources", "resources"),
        ("verbs", "verbs"),
    ] {
        attributes.insert(
            attribute.to_owned(),
            nested_string_arrays(&rules, field).join(","),
        );
    }
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "role_kind": kind,
        "role_scope": scope,
        "rules": rules,
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::RbacRole,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-rbac-role-{}",
                sha256(&format!(
                    "{}/{kind}/{namespace}/{name}/{uid}",
                    kernel.cluster_id
                ))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_rbac_role",
                &[
                    &kernel.cluster_id,
                    kind,
                    first_nonempty(&[namespace, "cluster"]),
                    name,
                ],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}

pub(super) fn normalize_rbac_binding(
    kernel: &KubernetesKernel,
    request: &KubernetesRequest,
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<KubernetesRecord, KubernetesError> {
    let kind = match request.rbac_stage {
        Some(RbacStage::RoleBinding) => "RoleBinding",
        Some(RbacStage::ClusterRoleBinding) => "ClusterRoleBinding",
        _ => return Err(KubernetesError::RequestScopeMismatch),
    };
    let name = required(metadata, "name")?;
    let namespace = string(metadata, "namespace");
    let uid = first_nonempty(&[string(metadata, "uid"), name]);
    let role_ref = object
        .get("roleRef")
        .and_then(Value::as_object)
        .ok_or(KubernetesError::MalformedResponse)?;
    let role_name = required(role_ref, "name")?;
    let subjects = array_or_empty(object.get("subjects"));
    let subject_refs = rbac_subject_refs(&subjects, namespace);
    let scope = if namespace.is_empty() {
        "cluster"
    } else {
        "namespace"
    };
    let mut attributes = base_attributes(kernel, "rbac_binding", uid, name, namespace);
    for (key, value) in [
        ("uid", uid),
        ("binding_kind", kind),
        ("binding_name", name),
        ("binding_scope", scope),
        ("role_api_group", string(role_ref, "apiGroup")),
        ("role_kind", string(role_ref, "kind")),
        ("role_name", role_name),
    ] {
        insert_nonempty(&mut attributes, key, value);
    }
    attributes.insert("subject_count".to_owned(), subjects.len().to_string());
    attributes.insert(
        "subject_refs".to_owned(),
        serde_json::to_string(&subject_refs).map_err(|_| KubernetesError::MalformedResponse)?,
    );
    attributes.insert(
        "subject_kinds".to_owned(),
        object_strings(&subjects, "kind").join(","),
    );
    attributes.insert(
        "subject_names".to_owned(),
        object_strings(&subjects, "name").join(","),
    );
    let payload = json!({
        "uid": uid,
        "name": name,
        "namespace": namespace,
        "binding_kind": kind,
        "binding_scope": scope,
        "role_ref": object.get("roleRef").cloned().unwrap_or(Value::Null),
        "subjects": subjects,
    });
    build_record(
        kernel,
        RecordParts {
            family: KubernetesFamily::RbacBinding,
            provider_id: uid.to_owned(),
            event_id: format!(
                "kubernetes-rbac-binding-{}",
                sha256(&format!(
                    "{}/{kind}/{namespace}/{name}/{uid}",
                    kernel.cluster_id
                ))
            ),
            canonical_urn: canonical_urn(
                &kernel.tenant_id,
                "kubernetes_rbac_binding",
                &[
                    &kernel.cluster_id,
                    kind,
                    first_nonempty(&[namespace, "cluster"]),
                    name,
                ],
            )?,
            attributes,
            payload,
            occurred_at: object_time(metadata, observed_at),
        },
    )
}
