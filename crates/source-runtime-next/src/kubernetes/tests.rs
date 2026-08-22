use std::str::FromStr;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::*;

const LIST_META: &str = r#""metadata":{"continue":"next-token"}"#;

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).unwrap()
}

fn config(tenant: &str) -> KubernetesConfig {
    let mut config = KubernetesConfig::new(
        tenant,
        "https://kubernetes.example.test",
        "prod-cluster",
        "Production Cluster",
    );
    config.cloud_provider = "AWS".to_owned();
    config.cloud_account_id = "account-a".to_owned();
    config
}

fn kernel(family: KubernetesFamily) -> KubernetesKernel {
    KubernetesKernel::new(config("tenant-a"), family).unwrap()
}

fn list(item: &str) -> Vec<u8> {
    format!(r#"{{{LIST_META},"items":[{item}]}}"#).into_bytes()
}

#[test]
fn closed_family_contract_covers_every_go_runtime_family() {
    let families = [
        ("cluster", KubernetesFamily::Cluster),
        ("namespace", KubernetesFamily::Namespace),
        ("node", KubernetesFamily::Node),
        ("pod", KubernetesFamily::Pod),
        ("workload", KubernetesFamily::Workload),
        ("container", KubernetesFamily::Container),
        ("service", KubernetesFamily::Service),
        ("ingress", KubernetesFamily::Ingress),
        ("service_account", KubernetesFamily::ServiceAccount),
        ("rbac_role", KubernetesFamily::RbacRole),
        ("rbac_binding", KubernetesFamily::RbacBinding),
        (
            "workload_identity_binding",
            KubernetesFamily::WorkloadIdentityBinding,
        ),
    ];
    for (name, family) in families {
        assert_eq!(KubernetesFamily::from_str(name).unwrap(), family);
        assert_eq!(family.as_str(), name);
        assert_eq!(family.event_kind(), format!("kubernetes.{name}"));
        assert_eq!(family.schema_ref(), format!("kubernetes/{name}/v1"));
        assert!(!family.required_attributes().is_empty());
        assert!(!family.required_payload_fields().is_empty());
    }
    assert_eq!(
        KubernetesFamily::from_str("secret"),
        Err(KubernetesError::InvalidFamily)
    );
}

#[test]
fn checked_fixture_compiles_to_the_exact_closed_go_catalog_contract() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/go_oracle_contract.json")).unwrap();
    assert_eq!(fixture["source_id"], "kubernetes");
    let families = fixture["families"].as_array().unwrap();
    assert_eq!(families.len(), 12);
    for contract in families {
        let required_attributes: Vec<String> =
            serde_json::from_value(contract["required_attributes"].clone()).unwrap();
        let required_payload_fields: Vec<String> =
            serde_json::from_value(contract["required_payload_fields"].clone()).unwrap();
        let definition = KubernetesRuntimeDefinition::compile(
            fixture["source_id"].as_str().unwrap(),
            contract["id"].as_str().unwrap(),
            contract["event_kind"].as_str().unwrap(),
            contract["schema_ref"].as_str().unwrap(),
            &required_attributes,
            &required_payload_fields,
        )
        .unwrap();
        let family = definition.family();
        assert_eq!(contract["event_kind"], family.event_kind());
        assert_eq!(contract["schema_ref"], family.schema_ref());
        assert_eq!(
            contract["required_attributes"],
            serde_json::to_value(family.required_attributes()).unwrap()
        );
        assert_eq!(
            contract["required_payload_fields"],
            serde_json::to_value(family.required_payload_fields()).unwrap()
        );
        KubernetesKernel::compile(config("tenant-a"), definition).unwrap();
    }
    assert_eq!(
        KubernetesRuntimeDefinition::compile(
            "kubernetes",
            "pod",
            "kubernetes.pod",
            "kubernetes/pod/v2",
            &["cluster_id".to_owned()],
            &["uid".to_owned()],
        ),
        Err(KubernetesError::InvalidRuntimeDefinition)
    );
}

#[test]
fn projection_fixture_matches_the_go_oracle_links() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/projection_oracle.json")).unwrap();
    let tenant = fixture["tenant_id"].as_str().unwrap();
    for test_case in fixture["cases"].as_array().unwrap() {
        let family = KubernetesFamily::from_str(test_case["family"].as_str().unwrap()).unwrap();
        let mut attributes: std::collections::BTreeMap<String, String> =
            serde_json::from_value(test_case["attributes"].clone()).unwrap();
        attributes.insert("tenant_id".to_owned(), tenant.to_owned());
        let record = KubernetesRecord {
            family,
            provider_id: format!("fixture-{}", family.as_str()),
            event_id: format!("kubernetes-rust-parity-{}", family.as_str()),
            canonical_urn: format!("urn:cerebro:{tenant}:fixture:{}", family.as_str()),
            event_kind: family.event_kind().to_owned(),
            schema_ref: family.schema_ref().to_owned(),
            attributes,
            payload: test_case["payload"].clone(),
            occurred_at: "1970-01-01T00:00:00Z".to_owned(),
        };
        let projection = record.project().unwrap();
        for expected in test_case["expected_links"].as_array().unwrap() {
            let expected = expected.as_array().unwrap();
            assert!(projection.links.iter().any(|link| {
                link.from_urn == expected[0].as_str().unwrap()
                    && link.relation == expected[1].as_str().unwrap()
                    && link.to_urn == expected[2].as_str().unwrap()
            }));
        }
    }
}

#[test]
fn plans_origin_locked_credential_free_requests_and_round_trips_continuations() {
    let cases = [
        (KubernetesFamily::Cluster, "/version", false),
        (KubernetesFamily::Namespace, "/api/v1/namespaces", true),
        (KubernetesFamily::Node, "/api/v1/nodes", true),
        (KubernetesFamily::Pod, "/api/v1/pods", true),
        (KubernetesFamily::Workload, "/api/v1/pods", true),
        (KubernetesFamily::Container, "/api/v1/pods", true),
        (KubernetesFamily::Service, "/api/v1/services", true),
        (
            KubernetesFamily::Ingress,
            "/apis/networking.k8s.io/v1/ingresses",
            true,
        ),
        (
            KubernetesFamily::ServiceAccount,
            "/api/v1/serviceaccounts",
            true,
        ),
        (
            KubernetesFamily::WorkloadIdentityBinding,
            "/api/v1/serviceaccounts",
            true,
        ),
    ];
    for (family, path, paged) in cases {
        let request = kernel(family).plan(paged.then_some("continue-1")).unwrap();
        assert_eq!(request.url().path(), path);
        assert_eq!(
            request.url().origin().ascii_serialization(),
            "https://kubernetes.example.test"
        );
        assert_eq!(request.authentication_mode(), "host_managed_kubernetes");
        assert_eq!(request.method(), "GET");
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.accept(), "application/json");
        assert_eq!(request.max_response_bytes(), 8 << 20);
        assert!(!KubernetesKernel::requires_credentials());
        let rendered = format!("{request:?}").to_ascii_lowercase();
        for forbidden in ["password", "secret", "token", "kubeconfig", "certificate"] {
            assert!(!rendered.contains(forbidden));
        }
        if paged {
            assert_eq!(request.url().query(), Some("limit=100&continue=continue-1"));
        } else {
            assert_eq!(request.url().query(), None);
        }
    }
}

#[test]
fn decodes_cluster_namespace_node_workload_pod_and_container_semantics() {
    let cluster = kernel(KubernetesFamily::Cluster)
        .decode(
            &kernel(KubernetesFamily::Cluster).plan(None).unwrap(),
            200,
            br#"{"gitVersion":"v1.35.0","major":"1","minor":"35","platform":"linux/amd64"}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(
        cluster.records[0].event_id,
        "kubernetes-cluster-prod-cluster"
    );
    assert_eq!(cluster.records[0].attributes["git_version"], "v1.35.0");

    let namespace_item = r#"{
        "metadata":{"name":"payments","uid":"namespace-1","creationTimestamp":"2026-06-01T00:00:00Z"},
        "status":{"phase":"Active"}
    }"#;
    let namespace_kernel = kernel(KubernetesFamily::Namespace);
    let namespace = namespace_kernel
        .decode(
            &namespace_kernel.plan(None).unwrap(),
            200,
            &list(namespace_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(namespace.records[0].attributes["namespace"], "payments");
    assert_eq!(namespace.next_cursor.as_deref(), Some("next-token"));
    assert_eq!(namespace.proposed_checkpoint, namespace.next_cursor);

    let node_item = r#"{
        "metadata":{"name":"node-a","uid":"node-1"},
        "spec":{"providerID":"aws:///zone/i-1","unschedulable":true},
        "status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"}],
          "conditions":[{"type":"Ready","status":"True"}],
          "nodeInfo":{"kubeletVersion":"v1.35.0","containerRuntimeVersion":"containerd://1.7","architecture":"amd64"}}
    }"#;
    let node_kernel = kernel(KubernetesFamily::Node);
    let node = node_kernel
        .decode(
            &node_kernel.plan(None).unwrap(),
            200,
            &list(node_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(node.records[0].attributes["ready"], "true");
    assert_eq!(node.records[0].attributes["internal_ip"], "10.0.0.1");

    let pod_item = r#"{
        "metadata":{"name":"api","namespace":"payments","uid":"pod-1"},
        "spec":{"serviceAccountName":"api","nodeName":"node-a","hostNetwork":false,
          "containers":[{"name":"app","image":"example/app:1","imagePullPolicy":"IfNotPresent",
            "securityContext":{"runAsNonRoot":true,"privileged":false}}]},
        "status":{"phase":"Running","containerStatuses":[{"name":"app","imageID":"example/app@sha256:aaaa",
          "ready":true,"started":true,"restartCount":0,"state":{"running":{}}}]}
    }"#;
    for family in [KubernetesFamily::Pod, KubernetesFamily::Workload] {
        let kernel = kernel(family);
        let page = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                &list(pod_item),
                observed_at(),
            )
            .unwrap();
        assert_eq!(page.records[0].attributes["workload_uid"], "pod-1");
        assert_eq!(page.records[0].attributes["service_account_name"], "api");
        assert!(
            page.records[0]
                .project()
                .unwrap()
                .links
                .iter()
                .any(|link| link.relation == "runs_as")
        );
    }
    let container_kernel = kernel(KubernetesFamily::Container);
    let containers = container_kernel
        .decode(
            &container_kernel.plan(None).unwrap(),
            200,
            &list(pod_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(containers.records.len(), 1);
    assert_eq!(containers.records[0].provider_id, "pod-1/app");
    assert_eq!(
        containers.records[0].attributes["image_digest"],
        "sha256:aaaa"
    );
    assert_eq!(containers.records[0].attributes["run_as_non_root"], "true");
}

#[test]
fn decodes_service_ingress_service_account_and_workload_identity_semantics() {
    let service_item = r#"{
        "metadata":{"name":"payments","namespace":"payments","uid":"service-1"},
        "spec":{"type":"LoadBalancer","clusterIP":"10.96.0.10","externalIPs":["203.0.113.10"],
          "ports":[{"name":"https","protocol":"TCP","port":443,"targetPort":8443,"nodePort":30443}],
          "selector":{"app":"payments"}},
        "status":{"loadBalancer":{"ingress":[{"hostname":"payments.example.test"}]}}
    }"#;
    let service_kernel = kernel(KubernetesFamily::Service);
    let service = service_kernel
        .decode(
            &service_kernel.plan(None).unwrap(),
            200,
            &list(service_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(
        service.records[0].attributes["service_type"],
        "LoadBalancer"
    );
    assert!(service.records[0].attributes["ports"].contains("30443"));

    let ingress_item = r#"{
        "metadata":{"name":"payments","namespace":"payments","uid":"ingress-1"},
        "spec":{"ingressClassName":"nginx","tls":[{"hosts":["payments.example.test"],"secretName":"tls"}],
          "rules":[{"host":"payments.example.test","http":{"paths":[{"path":"/","backend":{"service":{"name":"payments","port":{"number":443}}}}]}}]},
        "status":{"loadBalancer":{"ingress":[{"ip":"198.51.100.30"}]}}
    }"#;
    let ingress_kernel = kernel(KubernetesFamily::Ingress);
    let ingress = ingress_kernel
        .decode(
            &ingress_kernel.plan(None).unwrap(),
            200,
            &list(ingress_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(
        ingress.records[0].attributes["backend_services"],
        "payments:443"
    );
    assert!(
        ingress.records[0]
            .project()
            .unwrap()
            .links
            .iter()
            .any(|link| link.relation == "can_reach")
    );

    let service_account_item = r#"{
        "metadata":{"name":"api","namespace":"payments","uid":"sa-1","annotations":{
          "eks.amazonaws.com/role-arn":"arn:aws:iam::account-a:role/api",
          "iam.gke.io/gcp-service-account":"api@example.iam.gserviceaccount.com"}},
        "automountServiceAccountToken":false
    }"#;
    let account_kernel = kernel(KubernetesFamily::ServiceAccount);
    let account = account_kernel
        .decode(
            &account_kernel.plan(None).unwrap(),
            200,
            &list(service_account_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(account.records[0].attributes["automount_token"], "false");
    let identity_kernel = kernel(KubernetesFamily::WorkloadIdentityBinding);
    let identities = identity_kernel
        .decode(
            &identity_kernel.plan(None).unwrap(),
            200,
            &list(service_account_item),
            observed_at(),
        )
        .unwrap();
    assert_eq!(identities.records.len(), 2);
    assert_eq!(identities.records[0].attributes["cloud_provider"], "aws");
    assert_eq!(identities.records[1].attributes["cloud_provider"], "gcp");
    assert!(identities.records.iter().all(|record| {
        record
            .project()
            .unwrap()
            .links
            .iter()
            .any(|link| matches!(link.relation.as_str(), "can_assume" | "can_impersonate"))
    }));
}

#[test]
fn rbac_cursor_stages_round_trip_without_skipping_roles_or_bindings() {
    let role_kernel = kernel(KubernetesFamily::RbacRole);
    let role_request = role_kernel.plan(None).unwrap();
    assert_eq!(
        role_request.url().path(),
        "/apis/rbac.authorization.k8s.io/v1/roles"
    );
    let role_page = role_kernel
        .decode(
            &role_request,
            200,
            br#"{"metadata":{"continue":""},"items":[{"metadata":{"name":"secret-reader","namespace":"payments","uid":"role-1"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list"]}]}]}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(role_page.records[0].attributes["verbs"], "get,list");
    let cluster_request = role_kernel.plan(role_page.next_cursor.as_deref()).unwrap();
    assert_eq!(
        cluster_request.url().path(),
        "/apis/rbac.authorization.k8s.io/v1/clusterroles"
    );
    let binding_kernel = kernel(KubernetesFamily::RbacBinding);
    let binding_request = binding_kernel.plan(None).unwrap();
    let binding = binding_kernel
        .decode(
            &binding_request,
            200,
            br#"{"metadata":{"continue":""},"items":[{"metadata":{"name":"reader","namespace":"payments","uid":"binding-1"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"secret-reader"},"subjects":[{"kind":"ServiceAccount","name":"api","namespace":"payments"},{"kind":"User","name":"alice@example.test"}]}]}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(binding.records[0].attributes["subject_count"], "2");
    assert!(
        binding.records[0]
            .project()
            .unwrap()
            .links
            .iter()
            .any(|link| link.relation == "assigned_to")
    );
    assert!(
        binding_kernel
            .plan(binding.next_cursor.as_deref())
            .unwrap()
            .url()
            .path()
            .ends_with("/clusterrolebindings")
    );
}

#[test]
fn failures_are_typed_and_tenant_scoped_identities_do_not_collide() {
    for (status, expected) in [
        (401, KubernetesError::AuthenticationRejected),
        (403, KubernetesError::PermissionDenied),
        (429, KubernetesError::RateLimited),
        (503, KubernetesError::ProviderUnavailable),
        (418, KubernetesError::UnexpectedProviderStatus(418)),
    ] {
        let kernel = kernel(KubernetesFamily::Namespace);
        assert_eq!(
            kernel.decode(&kernel.plan(None).unwrap(), status, b"{}", observed_at()),
            Err(expected)
        );
    }
    assert_eq!(
        KubernetesKernel::new(
            KubernetesConfig::new("tenant", "http://cluster.test", "cluster", "cluster"),
            KubernetesFamily::Node,
        )
        .unwrap_err(),
        KubernetesError::InvalidApiServer
    );
    assert_eq!(
        kernel(KubernetesFamily::Node).plan(Some("https://evil.test/next")),
        Err(KubernetesError::InvalidCursor)
    );

    let response = list(r#"{"metadata":{"name":"payments","uid":"namespace-1"}}"#);
    let a = KubernetesKernel::new(config("tenant-a"), KubernetesFamily::Namespace).unwrap();
    let b = KubernetesKernel::new(config("tenant-b"), KubernetesFamily::Namespace).unwrap();
    let a_record = &a
        .decode(&a.plan(None).unwrap(), 200, &response, observed_at())
        .unwrap()
        .records[0];
    let b_record = &b
        .decode(&b.plan(None).unwrap(), 200, &response, observed_at())
        .unwrap()
        .records[0];
    assert_ne!(a_record.canonical_urn, b_record.canonical_urn);
    assert_eq!(a_record.provider_id, b_record.provider_id);
    assert_eq!(a_record.event_id, b_record.event_id);
}

#[test]
fn rejects_origin_cursor_identity_and_tenant_tampering_without_secret_echo() {
    let namespace_kernel = kernel(KubernetesFamily::Namespace);
    let mut escaped = namespace_kernel.plan(None).unwrap();
    escaped.url = "https://evil.example.test/api/v1/namespaces"
        .parse()
        .unwrap();
    assert_eq!(
        namespace_kernel.decode(&escaped, 200, b"{}", observed_at()),
        Err(KubernetesError::RequestScopeMismatch)
    );
    assert_eq!(
        namespace_kernel.plan(Some(&"x".repeat(4_097))),
        Err(KubernetesError::InvalidCursor)
    );

    let response = list(
        r#"{"metadata":{"name":"api","namespace":"payments","uid":"sa-1","tenant_id":"attacker","annotations":{"password":"credential-secret-sentinel","eks.amazonaws.com/role-arn":"arn:aws:iam::account-a:role/api"}},"tenant_id":"attacker"}"#,
    );
    let account_kernel = kernel(KubernetesFamily::ServiceAccount);
    let mut page = account_kernel
        .decode(
            &account_kernel.plan(None).unwrap(),
            200,
            &response,
            observed_at(),
        )
        .unwrap();
    let record = page.records.remove(0);
    assert_eq!(record.attributes["tenant_id"], "tenant-a");
    assert!(record.canonical_urn.starts_with("urn:cerebro:tenant-a:"));
    let safe_output = format!(
        "{record:?} {:?}",
        record.project().expect("project safe provider record")
    );
    assert!(!safe_output.contains("credential-secret-sentinel"));
    assert!(!safe_output.contains("attacker"));

    let conflicting = br#"{"metadata":{"continue":""},"items":[
      {"metadata":{"name":"one","uid":"same"}},
      {"metadata":{"name":"two","uid":"same"}}
    ]}"#;
    assert_eq!(
        namespace_kernel.decode(
            &namespace_kernel.plan(None).unwrap(),
            200,
            conflicting,
            observed_at(),
        ),
        Err(KubernetesError::ConflictingProviderIdentity)
    );
}
