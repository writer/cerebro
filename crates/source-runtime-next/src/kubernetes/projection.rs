//! Provider-local semantic projection facts used for Go/Rust parity.

use std::collections::BTreeSet;

use serde_json::Value;

use super::{KubernetesError, KubernetesFamily, KubernetesRecord};

/// One normalized Kubernetes projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KubernetesProjectionEntity {
    /// Tenant-scoped canonical entity identity.
    pub urn: String,
    /// Closed entity kind.
    pub kind: String,
    /// Provider label retained for operator reads.
    pub label: String,
}

/// One normalized Kubernetes projection relationship.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KubernetesProjectionLink {
    /// Tenant-scoped source entity identity.
    pub from_urn: String,
    /// Closed semantic relation.
    pub relation: String,
    /// Tenant-scoped target entity identity.
    pub to_urn: String,
}

/// Deterministic semantic projection facts for one normalized record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesProjection {
    /// Stable entities in canonical order.
    pub entities: Vec<KubernetesProjectionEntity>,
    /// Stable relationships in canonical order.
    pub links: Vec<KubernetesProjectionLink>,
}

impl KubernetesRecord {
    /// Compute provider-local semantic facts without a graph or store handle.
    pub fn project(&self) -> Result<KubernetesProjection, KubernetesError> {
        let tenant = required_attr(self, "tenant_id")?;
        let cluster = required_attr(self, "cluster_id")?;
        let mut entities = BTreeSet::new();
        let mut links = BTreeSet::new();
        let primary_urn = projected_record_urn(self, tenant, cluster)?;
        let primary_kind = if self.family == KubernetesFamily::WorkloadIdentityBinding {
            "kubernetes.service_account".to_owned()
        } else {
            self.event_kind.clone()
        };
        entities.insert(KubernetesProjectionEntity {
            urn: primary_urn.clone(),
            kind: primary_kind,
            label: record_label(self),
        });
        let cluster_urn = urn(tenant, "kubernetes_cluster", &[cluster]);
        entities.insert(KubernetesProjectionEntity {
            urn: cluster_urn.clone(),
            kind: "kubernetes.cluster".to_owned(),
            label: self
                .attributes
                .get("cluster_name")
                .cloned()
                .unwrap_or_else(|| cluster.to_owned()),
        });
        if self.family == KubernetesFamily::Node {
            links.insert(link(&primary_urn, "belongs_to", &cluster_urn));
        }
        let namespace = self.attributes.get("namespace").map(String::as_str);
        let namespace_urn = namespace.map(|namespace| {
            let value = urn(tenant, "kubernetes_namespace", &[cluster, namespace]);
            entities.insert(KubernetesProjectionEntity {
                urn: value.clone(),
                kind: "kubernetes.namespace".to_owned(),
                label: namespace.to_owned(),
            });
            if self.family != KubernetesFamily::Namespace {
                links.insert(link(&primary_urn, "belongs_to", &value));
            }
            links.insert(link(&value, "belongs_to", &cluster_urn));
            value
        });
        match self.family {
            KubernetesFamily::Pod | KubernetesFamily::Workload => {
                if let (Some(namespace), Some(account)) = (
                    namespace,
                    self.attributes
                        .get("service_account_name")
                        .map(String::as_str),
                ) {
                    let account_urn = urn(
                        tenant,
                        "kubernetes_service_account",
                        &[cluster, namespace, account],
                    );
                    entities.insert(KubernetesProjectionEntity {
                        urn: account_urn.clone(),
                        kind: "kubernetes.service_account".to_owned(),
                        label: account.to_owned(),
                    });
                    links.insert(link(&primary_urn, "runs_as", &account_urn));
                    if let Some(namespace_urn) = namespace_urn.as_ref() {
                        links.insert(link(&account_urn, "belongs_to", namespace_urn));
                    }
                }
                if let Some(node) = self
                    .attributes
                    .get("node_name")
                    .filter(|value| !value.is_empty())
                {
                    let node_urn = urn(tenant, "kubernetes_node", &[cluster, node]);
                    entities.insert(KubernetesProjectionEntity {
                        urn: node_urn.clone(),
                        kind: "kubernetes.node".to_owned(),
                        label: node.clone(),
                    });
                    links.insert(link(&node_urn, "belongs_to", &cluster_urn));
                    links.insert(link(&primary_urn, "associated_with", &node_urn));
                }
            }
            KubernetesFamily::Container => {
                if let (Some(namespace), Some(pod_uid)) = (
                    namespace,
                    self.payload.get("pod_uid").and_then(Value::as_str),
                ) {
                    let pod_urn = urn(
                        tenant,
                        "kubernetes_workload",
                        &[cluster, namespace, pod_uid],
                    );
                    entities.insert(KubernetesProjectionEntity {
                        urn: pod_urn.clone(),
                        kind: "kubernetes.workload".to_owned(),
                        label: self
                            .payload
                            .get("pod_name")
                            .and_then(Value::as_str)
                            .unwrap_or(pod_uid)
                            .to_owned(),
                    });
                    links.insert(link(&primary_urn, "belongs_to", &pod_urn));
                    links.insert(link(&pod_urn, "contains", &primary_urn));
                    if let Some(namespace_urn) = namespace_urn.as_ref() {
                        links.insert(link(&pod_urn, "belongs_to", namespace_urn));
                    }
                }
            }
            KubernetesFamily::Ingress => {
                if let Some(namespace) = namespace {
                    for backend in csv_attr(self, "backend_services") {
                        let name = backend.split(':').next().unwrap_or("").trim();
                        if name.is_empty() {
                            continue;
                        }
                        let service_urn =
                            urn(tenant, "kubernetes_service", &[cluster, namespace, name]);
                        entities.insert(KubernetesProjectionEntity {
                            urn: service_urn.clone(),
                            kind: "kubernetes.service".to_owned(),
                            label: name.to_owned(),
                        });
                        links.insert(link(&primary_urn, "can_reach", &service_urn));
                    }
                }
            }
            KubernetesFamily::RbacBinding => {
                let role_kind = required_attr(self, "role_kind")?;
                let role_name = required_attr(self, "role_name")?;
                let scope = if role_kind == "ClusterRole" {
                    "cluster"
                } else {
                    namespace.unwrap_or("cluster")
                };
                let role_urn = urn(
                    tenant,
                    "kubernetes_rbac_role",
                    &[cluster, role_kind, scope, role_name],
                );
                entities.insert(KubernetesProjectionEntity {
                    urn: role_urn.clone(),
                    kind: "kubernetes.rbac_role".to_owned(),
                    label: role_name.to_owned(),
                });
                links.insert(link(&primary_urn, "attached_to", &role_urn));
                if namespace.is_none() {
                    links.insert(link(&primary_urn, "belongs_to", &cluster_urn));
                }
                for subject in subject_refs(self)? {
                    let subject_kind = subject
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("subject");
                    let subject_name = subject.get("name").and_then(Value::as_str).unwrap_or("");
                    if subject_name.is_empty() {
                        continue;
                    }
                    let subject_namespace = subject
                        .get("namespace")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .unwrap_or("cluster");
                    let (subject_type, subject_segments): (&str, Vec<&str>) =
                        if subject_kind.eq_ignore_ascii_case("ServiceAccount") {
                            (
                                "kubernetes_service_account",
                                vec![cluster, subject_namespace, subject_name],
                            )
                        } else if subject_kind.eq_ignore_ascii_case("Group") {
                            ("kubernetes_group", vec![cluster, subject_name])
                        } else {
                            ("kubernetes_user", vec![cluster, subject_name])
                        };
                    let subject_urn = urn(tenant, subject_type, &subject_segments);
                    entities.insert(KubernetesProjectionEntity {
                        urn: subject_urn.clone(),
                        kind: format!(
                            "kubernetes.{}",
                            subject_type.trim_start_matches("kubernetes_")
                        ),
                        label: subject_name.to_owned(),
                    });
                    links.insert(link(&subject_urn, "assigned_to", &role_urn));
                    if subject_kind.eq_ignore_ascii_case("ServiceAccount") {
                        let subject_namespace_urn = urn(
                            tenant,
                            "kubernetes_namespace",
                            &[cluster, subject_namespace],
                        );
                        entities.insert(KubernetesProjectionEntity {
                            urn: subject_namespace_urn.clone(),
                            kind: "kubernetes.namespace".to_owned(),
                            label: subject_namespace.to_owned(),
                        });
                        links.insert(link(&subject_urn, "belongs_to", &subject_namespace_urn));
                        links.insert(link(&subject_namespace_urn, "belongs_to", &cluster_urn));
                    }
                }
            }
            KubernetesFamily::WorkloadIdentityBinding => {
                let provider = required_attr(self, "cloud_provider")?;
                let target = required_attr(self, "target_id")?;
                let (target_type, target_kind) = if provider == "gcp" {
                    ("gcp_service_account", "gcp.service_account")
                } else {
                    ("aws_role", "aws.role")
                };
                let target_urn = urn(tenant, target_type, &[target]);
                entities.insert(KubernetesProjectionEntity {
                    urn: target_urn.clone(),
                    kind: target_kind.to_owned(),
                    label: target.to_owned(),
                });
                let relation = if provider == "gcp" {
                    "can_impersonate"
                } else {
                    "can_assume"
                };
                links.insert(link(&primary_urn, relation, &target_urn));
            }
            KubernetesFamily::Cluster
            | KubernetesFamily::Namespace
            | KubernetesFamily::Service
            | KubernetesFamily::ServiceAccount
            | KubernetesFamily::Node => {}
            KubernetesFamily::RbacRole => {
                if namespace.is_none() {
                    links.insert(link(&primary_urn, "belongs_to", &cluster_urn));
                }
            }
        }
        Ok(KubernetesProjection {
            entities: entities.into_iter().collect(),
            links: links.into_iter().collect(),
        })
    }
}

fn projected_record_urn(
    record: &KubernetesRecord,
    tenant: &str,
    cluster: &str,
) -> Result<String, KubernetesError> {
    let namespace = record
        .attributes
        .get("namespace")
        .map_or("default", String::as_str);
    let value = match record.family {
        KubernetesFamily::Cluster => urn(tenant, "kubernetes_cluster", &[cluster]),
        KubernetesFamily::Namespace => urn(tenant, "kubernetes_namespace", &[cluster, namespace]),
        KubernetesFamily::Node => urn(
            tenant,
            "kubernetes_node",
            &[cluster, required_attr(record, "node_name")?],
        ),
        KubernetesFamily::Pod => urn(
            tenant,
            "kubernetes_pod",
            &[cluster, namespace, required_attr(record, "resource_id")?],
        ),
        KubernetesFamily::Workload => urn(
            tenant,
            "kubernetes_workload",
            &[cluster, namespace, required_attr(record, "workload_uid")?],
        ),
        KubernetesFamily::Container => urn(
            tenant,
            "kubernetes_container",
            &[
                cluster,
                namespace,
                required_attr(record, "resource_id")?,
                required_attr(record, "container_name")?,
            ],
        ),
        KubernetesFamily::Service => urn(
            tenant,
            "kubernetes_service",
            &[cluster, namespace, required_attr(record, "service_name")?],
        ),
        KubernetesFamily::Ingress => urn(
            tenant,
            "kubernetes_ingress",
            &[cluster, namespace, required_attr(record, "ingress_name")?],
        ),
        KubernetesFamily::ServiceAccount | KubernetesFamily::WorkloadIdentityBinding => urn(
            tenant,
            "kubernetes_service_account",
            &[
                cluster,
                namespace,
                required_attr(record, "service_account_name")?,
            ],
        ),
        KubernetesFamily::RbacRole => urn(
            tenant,
            "kubernetes_rbac_role",
            &[
                cluster,
                required_attr(record, "role_kind")?,
                record
                    .attributes
                    .get("namespace")
                    .map_or("cluster", String::as_str),
                required_attr(record, "role_name")?,
            ],
        ),
        KubernetesFamily::RbacBinding => urn(
            tenant,
            "kubernetes_rbac_binding",
            &[
                cluster,
                required_attr(record, "binding_kind")?,
                record
                    .attributes
                    .get("namespace")
                    .map_or("cluster", String::as_str),
                required_attr(record, "binding_name")?,
            ],
        ),
    };
    Ok(value)
}

fn required_attr<'a>(
    record: &'a KubernetesRecord,
    field: &'static str,
) -> Result<&'a str, KubernetesError> {
    record
        .attributes
        .get(field)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(KubernetesError::MissingRequiredAttribute(field))
}

fn record_label(record: &KubernetesRecord) -> String {
    for field in [
        "cluster_name",
        "resource_name",
        "workload_name",
        "service_account_name",
        "role_name",
        "binding_name",
        "container_name",
    ] {
        if let Some(value) = record
            .attributes
            .get(field)
            .filter(|value| !value.is_empty())
        {
            return value.clone();
        }
    }
    record.provider_id.clone()
}

fn csv_attr<'a>(record: &'a KubernetesRecord, field: &str) -> impl Iterator<Item = &'a str> {
    record
        .attributes
        .get(field)
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn subject_refs(record: &KubernetesRecord) -> Result<Vec<Value>, KubernetesError> {
    let raw = record
        .attributes
        .get("subject_refs")
        .ok_or(KubernetesError::MissingRequiredAttribute("subject_refs"))?;
    serde_json::from_str(raw).map_err(|_| KubernetesError::MalformedResponse)
}

fn link(from: &str, relation: &str, to: &str) -> KubernetesProjectionLink {
    KubernetesProjectionLink {
        from_urn: from.to_owned(),
        relation: relation.to_owned(),
        to_urn: to.to_owned(),
    }
}

fn urn(tenant: &str, kind: &str, segments: &[&str]) -> String {
    format!(
        "urn:cerebro:{}:{kind}:{}",
        encode(tenant),
        segments
            .iter()
            .map(|segment| encode(segment))
            .collect::<Vec<_>>()
            .join(":")
    )
}

fn encode(value: &str) -> String {
    value.trim().to_owned()
}
