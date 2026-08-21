//! Focused CodeBuild request, fanout, normalization, and failure tests.

use reqwest::StatusCode;
use serde_json::{Value, json};

use super::*;

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const PROJECT_ARN: &str = "arn:aws:codebuild:us-east-1:123456789012:project/orders-build";

fn kernel() -> AwsCodeBuildKernel {
    AwsCodeBuildKernel::new("https://codebuild.us-east-1.amazonaws.com", ACCOUNT, REGION)
        .expect("kernel")
}

fn decode(
    kernel: &AwsCodeBuildKernel,
    request: &AwsCodeBuildRequest,
    response: Value,
) -> AwsCodeBuildBatch {
    kernel
        .decode(
            request,
            StatusCode::OK,
            None,
            &serde_json::to_vec(&response).expect("json"),
        )
        .expect("decode")
}

#[test]
fn plans_exact_credential_free_aws_json_requests() {
    let project = kernel()
        .plan(AwsCodeBuildFamily::Project, Some("page-2"))
        .expect("project");
    assert_eq!(project.method(), "POST");
    assert_eq!(project.content_type(), AWS_JSON_CONTENT_TYPE);
    assert_eq!(project.amz_target(), "CodeBuild_20161006.ListProjects");
    assert_eq!(project.signing_service(), "codebuild");
    assert_eq!(project.signing_region(), REGION);
    assert_eq!(
        serde_json::from_slice::<Value>(project.body()).expect("body"),
        json!({"nextToken": "page-2"})
    );
    let credentials = kernel()
        .plan(AwsCodeBuildFamily::SourceCredential, None)
        .expect("credentials");
    assert_eq!(
        credentials.amz_target(),
        "CodeBuild_20161006.ListSourceCredentials"
    );
    assert_eq!(credentials.body(), b"{}");
}

#[test]
fn project_list_deduplicates_and_batches_go_names() {
    let kernel = kernel();
    let request = kernel
        .plan(AwsCodeBuildFamily::Project, None)
        .expect("list");
    let mut names = (0..101)
        .map(|index| format!("project-{index}"))
        .collect::<Vec<_>>();
    names.insert(1, " project-0 ".to_owned());
    names.insert(2, "".to_owned());
    let page = decode(
        &kernel,
        &request,
        json!({"projects": names, "nextToken": "next-page"}),
    );
    assert_eq!(page.requests.len(), 2);
    assert_eq!(page.next_cursor.as_deref(), Some("next-page"));
    assert_eq!(
        page.requests[0].kind(),
        AwsCodeBuildRequestKind::BatchGetProjects
    );
    assert_eq!(
        serde_json::from_slice::<Value>(page.requests[0].body()).expect("body")["names"]
            .as_array()
            .expect("names")
            .len(),
        100
    );
    assert_eq!(
        serde_json::from_slice::<Value>(page.requests[1].body()).expect("body"),
        json!({"names": ["project-100"]})
    );
}

#[test]
fn project_response_matches_go_fields_and_redacts_environment_values() {
    let kernel = kernel();
    let listed = decode(
        &kernel,
        &kernel
            .plan(AwsCodeBuildFamily::Project, None)
            .expect("list"),
        json!({"projects": ["orders-build"]}),
    );
    let batch = decode(
        &kernel,
        &listed.requests[0],
        json!({"projects": [{
            "arn": PROJECT_ARN,
            "created": 1776902400,
            "encryptionKey": "arn:aws:kms:us-east-1:123456789012:key/key-123",
            "environment": {
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [{
                    "name": "API_TOKEN",
                    "type": "PLAINTEXT",
                    "value": "do-not-store-this-value"
                }],
                "image": "aws/codebuild/standard:7.0",
                "privilegedMode": true,
                "type": "LINUX_CONTAINER"
            },
            "logsConfig": {
                "cloudWatchLogs": {"status": "ENABLED"},
                "s3Logs": {"status": "ENABLED", "encryptionDisabled": true}
            },
            "name": "orders-build",
            "projectVisibility": "PRIVATE",
            "serviceRole": "arn:aws:iam::123456789012:role/service-role/codebuild-orders",
            "source": {"type": "GITHUB"},
            "tags": [{"key": "Owner", "value": "ci@writer.com"}],
            "webhook": {
                "filterGroups": [[{"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"}]],
                "status": "ACTIVE"
            }
        }]}),
    );
    let record = &batch.records[0];
    assert_eq!(
        record.provider_id,
        "aws-codebuild-project-arn-aws-codebuild-us-east-1-123456789012-project-orders-build"
    );
    assert_eq!(record.fields["environment_variable_names"], "API_TOKEN");
    assert_eq!(
        record.fields["plaintext_environment_variable_names"],
        "API_TOKEN"
    );
    assert_eq!(record.fields["privileged_mode"], "true");
    assert_eq!(record.fields["s3_logs_encryption_disabled"], "true");
    assert_eq!(record.fields["source_type"], "GITHUB");
    assert_eq!(record.fields["webhook_public_trigger"], "true");
    assert_eq!(record.fields["internet_exposed"], "true");
    assert_eq!(record.fields["owner"], "ci@writer.com");
    assert_eq!(
        record.payload["environment"]["environment_variables"],
        json!([{
            "name": "API_TOKEN", "type": "PLAINTEXT"
        }])
    );
    assert!(
        !record
            .payload
            .to_string()
            .contains("do-not-store-this-value")
    );
}

#[test]
fn project_name_derives_the_go_arn_identity() {
    let kernel = kernel();
    let listed = decode(
        &kernel,
        &kernel
            .plan(AwsCodeBuildFamily::Project, None)
            .expect("list"),
        json!({"projects": ["name-only"]}),
    );
    let batch = decode(
        &kernel,
        &listed.requests[0],
        json!({"projects": [{"name": "name-only"}]}),
    );
    assert_eq!(
        batch.records[0].provider_id,
        "aws-codebuild-project-name-only"
    );
    assert_eq!(
        batch.records[0].fields["resource_id"],
        "arn:aws:codebuild:us-east-1:123456789012:project/name-only"
    );
    assert!(!batch.records[0].fields.contains_key("arn"));
    assert!(!batch.records[0].fields.contains_key("team"));
}

#[test]
fn source_credentials_sort_by_go_identity_and_emit_metadata_only() {
    let kernel = kernel();
    let request = kernel
        .plan(AwsCodeBuildFamily::SourceCredential, None)
        .expect("list");
    let batch = decode(
        &kernel,
        &request,
        json!({"sourceCredentialsInfos": [
            {"serverType": "GITLAB", "authType": "PERSONAL_ACCESS_TOKEN", "resource": "group"},
            {"arn": "arn:aws:codebuild:us-east-1:123456789012:source/github", "authType": "BASIC_AUTH", "serverType": "GITHUB"}
        ]}),
    );
    assert_eq!(
        batch.records[0].provider_id,
        "aws-codebuild-source-credential-GITLAB-PERSONAL_ACCESS_TOKEN-group"
    );
    assert_eq!(batch.records[1].fields["resource_name"], "github");
    assert_eq!(batch.records[1].fields["auth_type"], "BASIC_AUTH");
    assert!(batch.records[1].payload.get("credential").is_none());
}

#[test]
fn request_scope_and_non_paginated_cursor_fail_closed() {
    assert_eq!(
        kernel().plan(AwsCodeBuildFamily::SourceCredential, Some("cursor")),
        Err(AwsCodeBuildError::CursorNotSupported)
    );
    let request = kernel()
        .plan(AwsCodeBuildFamily::Project, None)
        .expect("request");
    let other = AwsCodeBuildKernel::new(
        "https://codebuild.us-west-2.amazonaws.com",
        ACCOUNT,
        "us-west-2",
    )
    .expect("other");
    assert_eq!(
        other.decode(&request, StatusCode::OK, None, b"{}"),
        Err(AwsCodeBuildError::RequestScopeMismatch)
    );
    assert_eq!(
        kernel().plan(AwsCodeBuildFamily::Project, Some("bad\ncursor")),
        Err(AwsCodeBuildError::InvalidCursor)
    );
}

#[test]
fn provider_errors_and_malformed_shapes_fail_closed() {
    let kernel = kernel();
    let request = kernel
        .plan(AwsCodeBuildFamily::Project, None)
        .expect("request");
    assert_eq!(
        kernel.decode(
            &request,
            StatusCode::FORBIDDEN,
            Some("AccessDeniedException:secret detail"),
            br#"{"message":"do not expose"}"#,
        ),
        Err(AwsCodeBuildError::ProviderFailure {
            status: 403,
            code: Some("AccessDeniedException".to_owned()),
        })
    );
    assert_eq!(
        kernel.decode(&request, StatusCode::OK, None, br#"{"projects":{}}"#),
        Err(AwsCodeBuildError::InvalidResponse)
    );
    let oversized = "x".repeat(MAX_CURSOR_BYTES + 1);
    let body = serde_json::to_vec(&json!({"projects": [], "nextToken": oversized})).expect("body");
    assert_eq!(
        kernel.decode(&request, StatusCode::OK, None, &body),
        Err(AwsCodeBuildError::InvalidCursor)
    );
}

#[test]
fn malformed_nested_project_members_fail_closed() {
    let kernel = kernel();
    let listed = decode(
        &kernel,
        &kernel
            .plan(AwsCodeBuildFamily::Project, None)
            .expect("list"),
        json!({"projects": ["orders-build"]}),
    );
    for project in [
        json!({"arn": PROJECT_ARN, "environment": {"privilegedMode": "true"}}),
        json!({"arn": PROJECT_ARN, "webhook": {"filterGroups": {}}}),
        json!({"arn": PROJECT_ARN, "tags": [{"key": "Team", "value": 7}]}),
        json!({"arn": PROJECT_ARN, "created": "yesterday"}),
    ] {
        let body = serde_json::to_vec(&json!({"projects": [project]})).expect("body");
        assert_eq!(
            kernel.decode(&listed.requests[0], StatusCode::OK, None, &body),
            Err(AwsCodeBuildError::InvalidResponse)
        );
    }
}

#[test]
fn rejects_unsafe_origins_and_missing_project_identity() {
    assert!(matches!(
        AwsCodeBuildKernel::new("http://codebuild.example.com", ACCOUNT, REGION),
        Err(AwsCodeBuildError::InvalidBaseUrl)
    ));
    let kernel = kernel();
    let listed = decode(
        &kernel,
        &kernel
            .plan(AwsCodeBuildFamily::Project, None)
            .expect("list"),
        json!({"projects": ["missing"]}),
    );
    assert_eq!(
        kernel.decode(
            &listed.requests[0],
            StatusCode::OK,
            None,
            br#"{"projects":[{}]}"#,
        ),
        Err(AwsCodeBuildError::MissingIdentity)
    );
}
