//! Go-compatible CodeBuild project and source-credential normalization.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::{
    request::{
        bool_member, bounded_records, integer_string, optional_array, optional_object,
        response_string_member, validate_optional_number, value_object,
    },
    wire::{AwsCodeBuildError, AwsCodeBuildFamily, AwsCodeBuildRecord},
};

pub(super) fn build_project_record(
    account_id: &str,
    region: &str,
    project: &Map<String, Value>,
) -> Result<AwsCodeBuildRecord, AwsCodeBuildError> {
    validate_optional_number(project, "created")?;
    validate_optional_number(project, "lastModified")?;
    let arn = response_string_member(project, "arn")?.unwrap_or_default();
    let name = response_string_member(project, "name")?.unwrap_or_default();
    let derived_arn = (!name.is_empty())
        .then(|| format!("arn:aws:codebuild:{region}:{account_id}:project/{name}"));
    let identity = if !arn.is_empty() {
        arn.to_owned()
    } else if let Some(derived_arn) = derived_arn {
        derived_arn
    } else {
        return Err(AwsCodeBuildError::MissingIdentity);
    };
    let event_identity = first_nonempty([arn, name]);
    let tags = decode_tags(project)?;
    let environment = optional_object(project, "environment")?;
    let environment_contract = decode_environment(environment)?;
    let logs = decode_logs(optional_object(project, "logsConfig")?)?;
    let source = decode_source(optional_object(project, "source")?)?;
    let webhook = decode_webhook(optional_object(project, "webhook")?)?;
    let visibility = response_string_member(project, "projectVisibility")?.unwrap_or_default();
    let public_alias = response_string_member(project, "publicProjectAlias")?.unwrap_or_default();
    let public = visibility == "PUBLIC_READ" || !public_alias.is_empty();
    let public_trigger = source.external && webhook.public_trigger;
    let mut fields = common_fields(
        account_id,
        region,
        AwsCodeBuildFamily::Project,
        &identity,
        name,
        "codebuild_project",
        &tags,
    );
    insert_string(&mut fields, "arn", arn);
    fields.insert(
        "build_timeout_minutes".to_owned(),
        integer_string(project, "timeoutInMinutes")?,
    );
    insert_string(
        &mut fields,
        "cloudwatch_logs_status",
        &logs.cloudwatch_status,
    );
    insert_string(
        &mut fields,
        "compute_type",
        &environment_contract.compute_type,
    );
    insert_string(
        &mut fields,
        "encryption_key",
        response_string_member(project, "encryptionKey")?.unwrap_or_default(),
    );
    insert_string(
        &mut fields,
        "environment_type",
        &environment_contract.environment_type,
    );
    insert_string(
        &mut fields,
        "environment_variable_names",
        &environment_contract.variable_names.join(","),
    );
    insert_string(
        &mut fields,
        "image_pull_credentials_type",
        &environment_contract.image_pull_credentials_type,
    );
    fields.insert(
        "internet_exposed".to_owned(),
        (public || public_trigger).to_string(),
    );
    insert_string(
        &mut fields,
        "plaintext_environment_variable_names",
        &environment_contract.plaintext_names.join(","),
    );
    insert_string(&mut fields, "project_name", name);
    insert_string(&mut fields, "project_visibility", visibility);
    fields.insert("public".to_owned(), public.to_string());
    insert_string(&mut fields, "public_project_alias", public_alias);
    fields.insert(
        "privileged_mode".to_owned(),
        environment_contract.privileged_mode.to_string(),
    );
    fields.insert(
        "queued_timeout_minutes".to_owned(),
        integer_string(project, "queuedTimeoutInMinutes")?,
    );
    insert_string(
        &mut fields,
        "service_role",
        response_string_member(project, "serviceRole")?.unwrap_or_default(),
    );
    fields.insert(
        "s3_logs_encryption_disabled".to_owned(),
        logs.s3_encryption_disabled.to_string(),
    );
    insert_string(&mut fields, "s3_logs_status", &logs.s3_status);
    insert_string(&mut fields, "source_type", &source.source_type);
    fields.insert("webhook".to_owned(), webhook.present.to_string());
    fields.insert(
        "webhook_public_trigger".to_owned(),
        public_trigger.to_string(),
    );
    insert_string(&mut fields, "webhook_status", &webhook.status);

    let payload = json!({
        "account_id": account_id,
        "arn": arn,
        "environment": environment_contract.payload,
        "logs_config": logs.payload,
        "name": name,
        "project_visibility": visibility,
        "public_project_alias": public_alias,
        "region": region,
        "service_role": response_string_member(project, "serviceRole")?.unwrap_or_default(),
        "source": source.payload,
        "tags": tags,
        "webhook": webhook.payload,
    });
    Ok(record(
        AwsCodeBuildFamily::Project,
        format!("aws-codebuild-project-{event_identity}"),
        fields,
        payload,
    ))
}

pub(super) fn build_source_credential_record(
    account_id: &str,
    region: &str,
    credential: &Map<String, Value>,
) -> Result<AwsCodeBuildRecord, AwsCodeBuildError> {
    let arn = response_string_member(credential, "arn")?.unwrap_or_default();
    let auth_type = response_string_member(credential, "authType")?.unwrap_or_default();
    let resource = response_string_member(credential, "resource")?.unwrap_or_default();
    let server_type = response_string_member(credential, "serverType")?.unwrap_or_default();
    let identity = source_credential_identity(arn, server_type, auth_type, resource);
    let generated_name = clean_strings([server_type, auth_type])
        .join("-")
        .to_ascii_lowercase();
    let name = first_nonempty([
        aws_resource_name(arn),
        generated_name.as_str(),
        aws_resource_name(resource),
        identity.as_str(),
    ]);
    let mut fields = common_fields(
        account_id,
        region,
        AwsCodeBuildFamily::SourceCredential,
        &identity,
        name,
        "codebuild_source_credential",
        &BTreeMap::new(),
    );
    insert_string(&mut fields, "arn", arn);
    insert_string(&mut fields, "auth_type", auth_type);
    insert_string(&mut fields, "resource", resource);
    insert_string(&mut fields, "server_type", server_type);
    let payload = json!({
        "account_id": account_id,
        "arn": arn,
        "auth_type": auth_type,
        "region": region,
        "resource": resource,
        "server_type": server_type,
    });
    Ok(record(
        AwsCodeBuildFamily::SourceCredential,
        format!("aws-codebuild-source-credential-{identity}"),
        fields,
        payload,
    ))
}

struct EnvironmentContract {
    compute_type: String,
    environment_type: String,
    image_pull_credentials_type: String,
    privileged_mode: bool,
    variable_names: Vec<String>,
    plaintext_names: Vec<String>,
    payload: Value,
}

fn decode_environment(
    environment: Option<&Map<String, Value>>,
) -> Result<EnvironmentContract, AwsCodeBuildError> {
    let Some(environment) = environment else {
        return Ok(EnvironmentContract {
            compute_type: String::new(),
            environment_type: String::new(),
            image_pull_credentials_type: String::new(),
            privileged_mode: false,
            variable_names: Vec::new(),
            plaintext_names: Vec::new(),
            payload: Value::Null,
        });
    };
    let compute_type = response_string_member(environment, "computeType")?
        .unwrap_or_default()
        .to_owned();
    let environment_type = response_string_member(environment, "type")?
        .unwrap_or_default()
        .to_owned();
    let image = response_string_member(environment, "image")?.unwrap_or_default();
    let image_pull_credentials_type =
        response_string_member(environment, "imagePullCredentialsType")?
            .unwrap_or_default()
            .to_owned();
    let privileged_mode = bool_member(environment, "privilegedMode")?;
    let mut variable_names = Vec::new();
    let mut plaintext_names = Vec::new();
    let mut variables = Vec::new();
    for variable in optional_array(environment, "environmentVariables")? {
        let variable = value_object(variable)?;
        let name = response_string_member(variable, "name")?.unwrap_or_default();
        let variable_type = response_string_member(variable, "type")?.unwrap_or_default();
        let _ = response_string_member(variable, "value")?;
        if name.is_empty() {
            continue;
        }
        variable_names.push(name.to_owned());
        if variable_type == "PLAINTEXT" {
            plaintext_names.push(name.to_owned());
        }
        variables.push(json!({"name": name, "type": variable_type}));
    }
    variable_names = clean_strings(variable_names.iter().map(String::as_str));
    plaintext_names = clean_strings(plaintext_names.iter().map(String::as_str));
    let payload = json!({
        "compute_type": compute_type,
        "environment_variables": variables,
        "image": image,
        "image_pull_credentials_type": image_pull_credentials_type,
        "privileged_mode": privileged_mode,
        "type": environment_type,
    });
    Ok(EnvironmentContract {
        compute_type,
        environment_type,
        image_pull_credentials_type,
        privileged_mode,
        variable_names,
        plaintext_names,
        payload,
    })
}

struct SourceContract {
    source_type: String,
    external: bool,
    payload: Value,
}

fn decode_source(source: Option<&Map<String, Value>>) -> Result<SourceContract, AwsCodeBuildError> {
    let Some(source) = source else {
        return Ok(SourceContract {
            source_type: String::new(),
            external: false,
            payload: Value::Null,
        });
    };
    let source_type = response_string_member(source, "type")?
        .unwrap_or_default()
        .to_owned();
    let insecure_ssl = bool_member(source, "insecureSsl")?;
    let external = matches!(
        source_type.as_str(),
        "GITHUB" | "BITBUCKET" | "GITLAB" | "GITHUB_ENTERPRISE" | "GITLAB_SELF_MANAGED"
    );
    Ok(SourceContract {
        source_type: source_type.clone(),
        external,
        payload: json!({"insecure_ssl": insecure_ssl, "type": source_type}),
    })
}

struct LogsContract {
    cloudwatch_status: String,
    s3_status: String,
    s3_encryption_disabled: bool,
    payload: Value,
}

fn decode_logs(logs: Option<&Map<String, Value>>) -> Result<LogsContract, AwsCodeBuildError> {
    let Some(logs) = logs else {
        return Ok(LogsContract {
            cloudwatch_status: String::new(),
            s3_status: String::new(),
            s3_encryption_disabled: false,
            payload: Value::Null,
        });
    };
    let cloudwatch = optional_object(logs, "cloudWatchLogs")?;
    let s3 = optional_object(logs, "s3Logs")?;
    let cloudwatch_status = optional_nested_string(cloudwatch, "status")?;
    let cloudwatch_group = optional_nested_string(cloudwatch, "groupName")?;
    let cloudwatch_stream = optional_nested_string(cloudwatch, "streamName")?;
    let s3_status = optional_nested_string(s3, "status")?;
    let s3_location = optional_nested_string(s3, "location")?;
    let s3_encryption_disabled = match s3 {
        Some(s3) => bool_member(s3, "encryptionDisabled")?,
        None => false,
    };
    Ok(LogsContract {
        cloudwatch_status: cloudwatch_status.clone(),
        s3_status: s3_status.clone(),
        s3_encryption_disabled,
        payload: json!({
            "cloud_watch_logs": {
                "group_name": cloudwatch_group,
                "status": cloudwatch_status,
                "stream_name": cloudwatch_stream,
            },
            "s3_logs": {
                "encryption_disabled": s3_encryption_disabled,
                "location": s3_location,
                "status": s3_status,
            }
        }),
    })
}

fn optional_nested_string(
    object: Option<&Map<String, Value>>,
    key: &str,
) -> Result<String, AwsCodeBuildError> {
    object
        .map(|object| response_string_member(object, key))
        .transpose()
        .map(|value| value.flatten().unwrap_or_default().to_owned())
}

struct WebhookContract {
    present: bool,
    public_trigger: bool,
    status: String,
    payload: Value,
}

fn decode_webhook(
    webhook: Option<&Map<String, Value>>,
) -> Result<WebhookContract, AwsCodeBuildError> {
    let Some(webhook) = webhook else {
        return Ok(WebhookContract {
            present: false,
            public_trigger: false,
            status: String::new(),
            payload: Value::Null,
        });
    };
    let manual_creation = bool_member(webhook, "manualCreation")?;
    let status = response_string_member(webhook, "status")?
        .unwrap_or_default()
        .to_owned();
    let mut filter_groups = Vec::new();
    let mut public_trigger = false;
    for group in optional_array(webhook, "filterGroups")? {
        let group = group.as_array().ok_or(AwsCodeBuildError::InvalidResponse)?;
        let mut filters = Vec::new();
        for filter in group {
            let filter = value_object(filter)?;
            let filter_type = response_string_member(filter, "type")?.unwrap_or_default();
            let pattern = response_string_member(filter, "pattern")?.unwrap_or_default();
            if filter_type == "EVENT" && pattern.contains("PULL_REQUEST") {
                public_trigger = true;
            }
            filters.push(json!({"type": filter_type, "pattern": pattern}));
        }
        filter_groups.push(Value::Array(filters));
    }
    Ok(WebhookContract {
        present: true,
        public_trigger,
        status: status.clone(),
        payload: json!({
            "filter_groups": filter_groups,
            "manual_creation": manual_creation,
            "status": status,
        }),
    })
}

fn decode_tags(
    project: &Map<String, Value>,
) -> Result<BTreeMap<String, String>, AwsCodeBuildError> {
    let tags = optional_array(project, "tags")?;
    bounded_records(tags.len())?;
    let mut result = BTreeMap::new();
    for tag in tags {
        let tag = value_object(tag)?;
        let key = response_string_member(tag, "key")?.unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let value = response_string_member(tag, "value")?.unwrap_or_default();
        result.insert(key.to_owned(), value.to_owned());
    }
    Ok(result)
}

fn source_credential_identity(arn: &str, server: &str, auth: &str, resource: &str) -> String {
    if !arn.is_empty() {
        return arn.to_owned();
    }
    let composite = clean_strings([server, auth, resource]).join(":");
    if composite.is_empty() {
        "unknown".to_owned()
    } else {
        composite
    }
}

fn aws_resource_name(value: &str) -> &str {
    value
        .trim()
        .rsplit(['/', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or_default()
}

fn first_nonempty<'a>(values: impl IntoIterator<Item = &'a str>) -> &'a str {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .map(str::trim)
        .unwrap_or_default()
}

fn clean_strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && seen.insert(value.to_owned()) {
            result.push(value.to_owned());
        }
    }
    result
}

fn common_fields(
    account_id: &str,
    region: &str,
    family: AwsCodeBuildFamily,
    resource_id: &str,
    resource_name: &str,
    resource_type: &str,
    tags: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("domain".to_owned(), account_id.to_owned()),
        (
            "env".to_owned(),
            tag_lookup(tags, &["environment", "env", "stage"]),
        ),
        (
            "environment".to_owned(),
            tag_lookup(tags, &["environment", "env", "stage"]),
        ),
        ("family".to_owned(), family.id().to_owned()),
        (
            "owner".to_owned(),
            tag_lookup(
                tags,
                &[
                    "owner",
                    "application_owner",
                    "business_owner",
                    "service_owner",
                ],
            ),
        ),
        ("region".to_owned(), region.to_owned()),
        ("resource_id".to_owned(), resource_id.to_owned()),
        ("resource_name".to_owned(), resource_name.to_owned()),
        ("resource_provider".to_owned(), "aws".to_owned()),
        ("resource_type".to_owned(), resource_type.to_owned()),
        ("tags".to_owned(), encode_tags(tags)),
        (
            "team".to_owned(),
            tag_lookup(tags, &["team", "squad", "group"]),
        ),
    ])
}

fn tag_lookup(tags: &BTreeMap<String, String>, keys: &[&str]) -> String {
    let normalized = tags
        .iter()
        .map(|(key, value)| (normalize_tag_key(key), value))
        .collect::<BTreeMap<_, _>>();
    keys.iter()
        .find_map(|key| normalized.get(&normalize_tag_key(key)))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn normalize_tag_key(value: &str) -> String {
    let mut normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' ', '.'], "_");
    normalized = normalized.trim_matches('_').to_owned();
    while normalized.contains("__") {
        normalized = normalized.replace("__", "_");
    }
    normalized
}

fn encode_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn insert_string(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    fields.insert(key.to_owned(), value.to_owned());
}

fn record(
    family: AwsCodeBuildFamily,
    provider_id: String,
    mut fields: BTreeMap<String, String>,
    payload: Value,
) -> AwsCodeBuildRecord {
    fields.retain(|_, value| {
        *value = value.trim().to_owned();
        !value.is_empty()
    });
    AwsCodeBuildRecord {
        family: family.id().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        provider_id: sanitize_event_id(&provider_id),
        fields,
        payload,
    }
}

fn sanitize_event_id(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            ' ' | '/' | ':' => '-',
            _ => character,
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}
