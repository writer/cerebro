use serde_json::json;

use super::{kernel, linode, observed_at};

#[test]
fn origin_response_identity_and_duplicate_bounds_fail_closed() {
    for base_url in [
        "http://api.linode.com/v4",
        "https://user@api.linode.com/v4",
        "https://api.linode.com/v3",
        "https://10.0.0.1/v4",
    ] {
        assert_eq!(
            linode::LinodeKernel::new(Some(base_url), "tenant", None).unwrap_err(),
            linode::LinodeError::InvalidBaseUrl
        );
    }
    for tenant in ["", " tenant", "tenant/id", "tenant:id", "tenant\n"] {
        let expected = if tenant.is_empty() {
            linode::LinodeError::MissingTenantId
        } else {
            linode::LinodeError::InvalidEventIdentity
        };
        assert_eq!(
            linode::LinodeKernel::new(None, tenant, None).unwrap_err(),
            expected
        );
    }
    assert_eq!(
        linode::LinodeKernel::new(None, "tenant", Some(24)).unwrap_err(),
        linode::LinodeError::InvalidPageSize
    );

    let kernel = kernel();
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel
            .decode(&request, &vec![b' '; (8 << 20) + 1], observed_at())
            .unwrap_err(),
        linode::LinodeError::ResponseTooLarge
    );
    for body in [
        br#"{}"#.as_slice(),
        br#"{"data":{},"page":1,"pages":1,"results":0}"#.as_slice(),
    ] {
        assert_eq!(
            kernel.decode(&request, body, observed_at()).unwrap_err(),
            linode::LinodeError::InvalidResponse
        );
    }
    assert_eq!(
        kernel
            .decode(
                &request,
                br#"{"data":[{}],"page":1,"pages":1,"results":1}"#,
                observed_at(),
            )
            .unwrap_err(),
        linode::LinodeError::MissingProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &request,
                br#"{
                    "data":[{
                        "created":"2026-06-01T00:00:00Z",
                        "resource_urn":"urn:cerebro:tenant:linode_issue:823",
                        "severity":"medium",
                        "status":"open"
                    }],
                    "page":1,
                    "pages":1,
                    "results":1
                }"#,
                observed_at(),
            )
            .unwrap_err(),
        linode::LinodeError::MissingRequiredPayloadField("id")
    );
    let too_many = serde_json::to_vec(&json!({
        "data": (0..101)
            .map(|id| json!({
                "id": id,
                "resource_urn": format!("urn:cerebro:tenant:linode_issue:{id}"),
                "severity": "medium",
                "status": "open"
            }))
            .collect::<Vec<_>>(),
        "page": 1,
        "pages": 1,
        "results": 101
    }))
    .unwrap();
    assert_eq!(
        kernel
            .decode(&request, &too_many, observed_at())
            .unwrap_err(),
        linode::LinodeError::TooManyRecords
    );
    let conflicting = serde_json::to_vec(&json!({
        "data": [
            {
                "id": 823,
                "resource_urn": "urn:cerebro:tenant:linode_issue:823",
                "severity": "medium",
                "status": "open"
            },
            {
                "id": 823,
                "resource_urn": "urn:cerebro:tenant:linode_issue:823",
                "severity": "high",
                "status": "open"
            }
        ],
        "page": 1,
        "pages": 1,
        "results": 2
    }))
    .unwrap();
    assert_eq!(
        kernel
            .decode(&request, &conflicting, observed_at())
            .unwrap_err(),
        linode::LinodeError::ConflictingProviderIdentity
    );
    let identical = serde_json::to_vec(&json!({
        "data": [
            {
                "id": 823,
                "resource_urn": "urn:cerebro:tenant:linode_issue:823",
                "severity": "medium",
                "status": "open"
            },
            {
                "id": 823,
                "resource_urn": "urn:cerebro:tenant:linode_issue:823",
                "severity": "medium",
                "status": "open"
            }
        ],
        "page": 1,
        "pages": 1,
        "results": 2
    }))
    .unwrap();
    assert_eq!(
        kernel
            .decode(&request, &identical, observed_at())
            .unwrap()
            .records
            .len(),
        1
    );
}
