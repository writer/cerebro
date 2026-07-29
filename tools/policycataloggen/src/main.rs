#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: policycataloggen [--root PATH] (--write|--check)";
const OUTPUT_PATH: &str = "crates/policy-catalog/src/generated.rs";
const POLICY_DIR: &str = "policies";
const DETECTION_CATALOG_PATH: &str = "internal/findings/public_detection_catalog.json";
const MAX_POLICY_BYTES: usize = 1 << 20;
const MAX_DETECTION_CATALOG_BYTES: usize = 16 << 20;
const MAX_POLICIES: usize = 5_000;
const POLICY_DIGEST_SCHEMA: &str = "cerebro.policy-definition.v2";
const DETECTION_DIGEST_SCHEMA: &str = "cerebro.detection-definition.v1";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Write,
    Check,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyDocument {
    api_version: String,
    kind: String,
    metadata: PolicyMetadata,
    spec: PolicySpec,
}

#[derive(Debug, Deserialize)]
struct PolicyMetadata {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicySpec {
    severity: String,
    #[serde(default)]
    effect: String,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    resource_type: Option<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct DetectionCatalog {
    detections: Vec<DetectionDocument>,
}

#[derive(Clone, Debug, Deserialize)]
struct DetectionDocument {
    id: String,
    pack_id: String,
    source_id: String,
    evaluation_mode: String,
    #[serde(default)]
    event_kinds: Vec<String>,
    output_kind: String,
    #[serde(default)]
    required_attributes: Vec<String>,
    #[serde(default)]
    required_attributes_by_kind: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    fingerprint_fields: Vec<String>,
    lifecycle: LifecycleDocument,
}

#[derive(Clone, Debug, Deserialize)]
struct LifecycleDocument {
    kind: String,
    anchor: String,
    #[serde(default)]
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct RequiredAttributesByKindMaterial<'a> {
    event_kind: &'a str,
    attributes: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct DigestMaterial<'a> {
    schema: &'static str,
    id: &'a str,
    name: &'a str,
    domain: &'a str,
    severity: &'a str,
    effect: &'a str,
    resource: &'a str,
    enabled: bool,
    evaluation_mode: &'a str,
    event_kinds: &'a [&'a str],
    output_kind: &'a str,
    required_attributes: &'a [&'a str],
    required_attributes_by_kind: &'a [RequiredAttributesByKindMaterial<'a>],
    fingerprint_fields: &'a [&'a str],
    lifecycle: LifecycleMaterial<'a>,
    source_path: &'a str,
    source_digest: &'a str,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct LifecycleMaterial<'a> {
    kind: &'a str,
    anchor: &'a str,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct DetectionDigestMaterial<'a> {
    schema: &'static str,
    id: &'a str,
    source_id: &'a str,
    evaluation_mode: &'a str,
    event_kinds: &'a [&'a str],
    output_kind: &'a str,
    required_attributes: &'a [&'a str],
    required_attributes_by_kind: &'a [RequiredAttributesByKindMaterial<'a>],
    fingerprint_fields: &'a [&'a str],
    lifecycle: LifecycleMaterial<'a>,
}

#[derive(Debug)]
struct Definition {
    id: String,
    name: String,
    domain: String,
    severity: String,
    effect: String,
    resource: String,
    enabled: bool,
    detection: DetectionDocument,
    source_path: String,
    source_digest: String,
    definition_digest: String,
}

#[derive(Debug)]
struct DetectionDefinition {
    detection: DetectionDocument,
    definition_digest: String,
}

#[derive(Debug)]
struct GeneratorError(String);

impl fmt::Display for GeneratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for GeneratorError {}

fn main() {
    if let Err(error) = run() {
        eprintln!("policycataloggen: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), GeneratorError> {
    let (root, mode) = parse_args()?;
    let generated = format_generated(&generate(&root)?)?;
    let output = root.join(OUTPUT_PATH);
    match mode {
        Mode::Write => write_generated_file(&output, generated.as_bytes()),
        Mode::Check => {
            let existing = read_bounded(&output, 16 << 20)?;
            if trim_ascii(&existing) != trim_ascii(generated.as_bytes()) {
                return Err(GeneratorError(format!(
                    "{OUTPUT_PATH} is stale; run `make policy-catalog-generate`"
                )));
            }
            Ok(())
        }
    }
}

fn format_generated(generated: &str) -> Result<String, GeneratorError> {
    let mut child = Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2024"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| GeneratorError(format!("start rustfmt: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| GeneratorError("open rustfmt stdin".to_owned()))?
        .write_all(generated.as_bytes())
        .map_err(|error| GeneratorError(format!("write rustfmt input: {error}")))?;
    let output = child
        .wait_with_output()
        .map_err(|error| GeneratorError(format!("wait for rustfmt: {error}")))?;
    if !output.status.success() {
        return Err(GeneratorError(format!(
            "rustfmt generated catalog: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| GeneratorError(format!("rustfmt emitted non-UTF-8 output: {error}")))
}

fn parse_args() -> Result<(PathBuf, Mode), GeneratorError> {
    let mut root = PathBuf::from(".");
    let mut mode = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => {
                root = PathBuf::from(
                    args.next()
                        .ok_or_else(|| GeneratorError("--root requires a value".to_owned()))?,
                );
            }
            "--write" => set_mode(&mut mode, Mode::Write)?,
            "--check" => set_mode(&mut mode, Mode::Check)?,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => return Err(GeneratorError(format!("unknown argument {argument:?}"))),
        }
    }
    let mode = mode.ok_or_else(|| GeneratorError(format!("{USAGE}; mode is required")))?;
    Ok((root, mode))
}

fn set_mode(current: &mut Option<Mode>, mode: Mode) -> Result<(), GeneratorError> {
    if current.is_some_and(|current| current != mode) {
        return Err(GeneratorError(
            "--write and --check cannot be used together".to_owned(),
        ));
    }
    *current = Some(mode);
    Ok(())
}

fn generate(root: &Path) -> Result<String, GeneratorError> {
    let policy_root = root.join(POLICY_DIR);
    let detection_catalog_path = root.join(DETECTION_CATALOG_PATH);
    let detection_catalog: DetectionCatalog = serde_json::from_slice(&read_bounded(
        &detection_catalog_path,
        MAX_DETECTION_CATALOG_BYTES,
    )?)
    .map_err(|error| GeneratorError(format!("decode {DETECTION_CATALOG_PATH}: {error}")))?;
    let mut detections = BTreeMap::new();
    for detection in detection_catalog.detections {
        validate_detection(&detection)?;
        let id = detection.id.clone();
        if detections.insert(id.clone(), detection).is_some() {
            return Err(GeneratorError(format!(
                "{DETECTION_CATALOG_PATH}: duplicate detection id {id:?}"
            )));
        }
    }
    let mut paths = Vec::new();
    collect_policy_paths(&policy_root, &mut paths)?;
    paths.sort();
    if paths.len() > MAX_POLICIES {
        return Err(GeneratorError(format!(
            "policy count {} exceeds limit {MAX_POLICIES}",
            paths.len()
        )));
    }

    let mut definitions = Vec::with_capacity(paths.len());
    let mut ids = BTreeSet::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| GeneratorError(format!("{} escapes repository root", path.display())))?;
        let source_path = relative
            .to_str()
            .ok_or_else(|| GeneratorError(format!("{} is not UTF-8", relative.display())))?
            .replace('\\', "/");
        let bytes = read_bounded(&path, MAX_POLICY_BYTES)?;
        let policy: PolicyDocument = serde_saphyr::from_slice(&bytes)
            .map_err(|error| GeneratorError(format!("decode {source_path}: {error}")))?;
        validate_policy(&policy, &source_path)?;
        if !ids.insert(policy.metadata.id.clone()) {
            return Err(GeneratorError(format!(
                "duplicate policy id {:?}",
                policy.metadata.id
            )));
        }
        let domain = policy_domain(&path, &policy_root, &source_path)?;
        let source_digest = hex_digest(&bytes);
        let resource = policy_resource(&policy.spec)?.to_owned();
        let detection = detections.remove(&policy.metadata.id).ok_or_else(|| {
            GeneratorError(format!(
                "{source_path}: policy has no generated detection metadata"
            ))
        })?;
        if detection.pack_id != "policy" {
            return Err(GeneratorError(format!(
                "{source_path}: detection pack must be policy, got {:?}",
                detection.pack_id
            )));
        }
        let event_kinds = string_refs(&detection.event_kinds);
        let required_attributes = string_refs(&detection.required_attributes);
        let required_attributes_by_kind =
            required_attributes_by_kind_material(&detection.required_attributes_by_kind);
        let fingerprint_fields = string_refs(&detection.fingerprint_fields);
        let material = DigestMaterial {
            schema: POLICY_DIGEST_SCHEMA,
            id: &policy.metadata.id,
            name: &policy.metadata.name,
            domain: &domain,
            severity: &policy.spec.severity,
            effect: &policy.spec.effect,
            resource: &resource,
            enabled: policy.spec.enabled,
            evaluation_mode: &detection.evaluation_mode,
            event_kinds: &event_kinds,
            output_kind: &detection.output_kind,
            required_attributes: &required_attributes,
            required_attributes_by_kind: &required_attributes_by_kind,
            fingerprint_fields: &fingerprint_fields,
            lifecycle: lifecycle_material(&detection.lifecycle),
            source_path: &source_path,
            source_digest: &source_digest,
        };
        let definition_digest = hex_digest(
            &serde_json::to_vec(&material)
                .map_err(|error| GeneratorError(format!("encode {source_path}: {error}")))?,
        );
        definitions.push(Definition {
            id: policy.metadata.id,
            name: policy.metadata.name,
            domain,
            severity: policy.spec.severity,
            effect: policy.spec.effect,
            resource,
            enabled: policy.spec.enabled,
            detection,
            source_path,
            source_digest,
            definition_digest,
        });
    }
    definitions.sort_by(|left, right| left.id.cmp(&right.id));
    if let Some((id, _)) = detections
        .iter()
        .find(|(_, detection)| detection.pack_id == "policy")
    {
        return Err(GeneratorError(format!(
            "{DETECTION_CATALOG_PATH}: policy detection {id:?} has no policy document"
        )));
    }
    let mut detection_definitions = detections
        .into_values()
        .map(|detection| {
            let event_kinds = string_refs(&detection.event_kinds);
            let required_attributes = string_refs(&detection.required_attributes);
            let required_attributes_by_kind =
                required_attributes_by_kind_material(&detection.required_attributes_by_kind);
            let fingerprint_fields = string_refs(&detection.fingerprint_fields);
            let material = DetectionDigestMaterial {
                schema: DETECTION_DIGEST_SCHEMA,
                id: &detection.id,
                source_id: &detection.source_id,
                evaluation_mode: &detection.evaluation_mode,
                event_kinds: &event_kinds,
                output_kind: &detection.output_kind,
                required_attributes: &required_attributes,
                required_attributes_by_kind: &required_attributes_by_kind,
                fingerprint_fields: &fingerprint_fields,
                lifecycle: lifecycle_material(&detection.lifecycle),
            };
            let definition_digest =
                hex_digest(&serde_json::to_vec(&material).map_err(|error| {
                    GeneratorError(format!(
                        "encode detection definition {:?}: {error}",
                        detection.id
                    ))
                })?);
            Ok(DetectionDefinition {
                detection,
                definition_digest,
            })
        })
        .collect::<Result<Vec<_>, GeneratorError>>()?;
    detection_definitions.sort_by(|left, right| left.detection.id.cmp(&right.detection.id));
    Ok(render(&definitions, &detection_definitions))
}

fn policy_domain(
    path: &Path,
    policy_root: &Path,
    source_path: &str,
) -> Result<String, GeneratorError> {
    let relative = path.strip_prefix(policy_root).map_err(|_| {
        GeneratorError(format!(
            "{source_path} is not contained by {}",
            policy_root.display()
        ))
    })?;
    let mut components = relative.components();
    let domain = components
        .next()
        .and_then(|value| value.as_os_str().to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GeneratorError(format!("missing domain for {source_path}")))?;
    if components.next().is_none() {
        return Err(GeneratorError(format!(
            "{source_path} must be placed under {POLICY_DIR}/<domain>/"
        )));
    }
    Ok(domain.to_owned())
}

fn collect_policy_paths(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), GeneratorError> {
    reject_symlink(directory)?;
    let entries = fs::read_dir(directory)
        .map_err(|error| GeneratorError(format!("read {}: {error}", directory.display())))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            GeneratorError(format!("read {} entry: {error}", directory.display()))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| GeneratorError(format!("inspect {}: {error}", path.display())))?;
        if metadata.file_type().is_symlink() {
            return Err(GeneratorError(format!(
                "symlinks are not allowed under {POLICY_DIR}: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_policy_paths(&path, paths)?;
        } else if metadata.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "yaml")
            && !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".test.yaml"))
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn validate_policy(policy: &PolicyDocument, source_path: &str) -> Result<(), GeneratorError> {
    if policy.api_version != "cerebro.writer.com/v1alpha1" {
        return Err(GeneratorError(format!(
            "{source_path}: unsupported apiVersion {:?}",
            policy.api_version
        )));
    }
    if policy.kind != "PolicyFindingRule" {
        return Err(GeneratorError(format!(
            "{source_path}: unsupported kind {:?}",
            policy.kind
        )));
    }
    if !valid_id(&policy.metadata.id) {
        return Err(GeneratorError(format!(
            "{source_path}: invalid policy id {:?}",
            policy.metadata.id
        )));
    }
    for (field, value) in [
        ("metadata.name", policy.metadata.name.as_str()),
        ("spec.severity", policy.spec.severity.as_str()),
        ("spec.resource", policy_resource(&policy.spec)?),
    ] {
        if value.trim().is_empty() || value != value.trim() {
            return Err(GeneratorError(format!(
                "{source_path}: {field} must be non-empty and trimmed"
            )));
        }
    }
    Ok(())
}

fn validate_detection(detection: &DetectionDocument) -> Result<(), GeneratorError> {
    let prefix = format!("{DETECTION_CATALOG_PATH}: detection {:?}", detection.id);
    if !valid_id(&detection.id) {
        return Err(GeneratorError(format!(
            "{prefix} has an invalid detection id"
        )));
    }
    for (field, value) in [
        ("pack_id", detection.pack_id.as_str()),
        ("source_id", detection.source_id.as_str()),
        ("output_kind", detection.output_kind.as_str()),
    ] {
        if value.trim().is_empty() || value != value.trim() {
            return Err(GeneratorError(format!(
                "{prefix} {field} must be non-empty and trimmed"
            )));
        }
    }
    if !matches!(detection.evaluation_mode.as_str(), "event" | "graph") {
        return Err(GeneratorError(format!(
            "{prefix} has unsupported evaluation_mode {:?}",
            detection.evaluation_mode
        )));
    }
    validate_string_list(&prefix, "event_kinds", &detection.event_kinds, false)?;
    validate_string_list(
        &prefix,
        "required_attributes",
        &detection.required_attributes,
        true,
    )?;
    validate_string_list(
        &prefix,
        "fingerprint_fields",
        &detection.fingerprint_fields,
        detection.lifecycle.kind == "retired",
    )?;
    for (event_kind, attributes) in &detection.required_attributes_by_kind {
        if event_kind.trim().is_empty() || event_kind != event_kind.trim() {
            return Err(GeneratorError(format!(
                "{prefix} required_attributes_by_kind has an invalid event kind"
            )));
        }
        validate_string_list(
            &prefix,
            &format!("required_attributes_by_kind[{event_kind:?}]"),
            attributes,
            true,
        )?;
    }
    match detection.lifecycle.kind.as_str() {
        "ttl_evidence" if detection.lifecycle.ttl_seconds == 0 => {
            return Err(GeneratorError(format!(
                "{prefix} ttl_evidence requires ttl_seconds > 0"
            )));
        }
        "ttl_evidence" => {}
        "durable_state" if detection.lifecycle.anchor == "none" => {
            return Err(GeneratorError(format!(
                "{prefix} durable_state forbids anchor=none"
            )));
        }
        "durable_state" | "audit_evidence" | "retired" if detection.lifecycle.ttl_seconds != 0 => {
            return Err(GeneratorError(format!(
                "{prefix} non-TTL lifecycle requires ttl_seconds=0"
            )));
        }
        "durable_state" | "audit_evidence" | "retired" => {}
        other => {
            return Err(GeneratorError(format!(
                "{prefix} has unsupported lifecycle kind {other:?}"
            )));
        }
    }
    if !matches!(
        detection.lifecycle.anchor.as_str(),
        "graph_anchored" | "source_state" | "none"
    ) {
        return Err(GeneratorError(format!(
            "{prefix} has unsupported lifecycle anchor {:?}",
            detection.lifecycle.anchor
        )));
    }
    if detection.lifecycle.kind == "retired" && detection.lifecycle.anchor != "none" {
        return Err(GeneratorError(format!(
            "{prefix} retired requires anchor=none"
        )));
    }
    Ok(())
}

fn validate_string_list(
    prefix: &str,
    field: &str,
    values: &[String],
    allow_empty: bool,
) -> Result<(), GeneratorError> {
    if !allow_empty && values.is_empty() {
        return Err(GeneratorError(format!("{prefix} {field} is required")));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || value != value.trim() {
            return Err(GeneratorError(format!(
                "{prefix} {field} contains an empty or untrimmed value"
            )));
        }
        if !seen.insert(value) {
            return Err(GeneratorError(format!(
                "{prefix} {field} contains duplicate value {value:?}"
            )));
        }
    }
    Ok(())
}

fn string_refs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

fn required_attributes_by_kind_material(
    values: &BTreeMap<String, Vec<String>>,
) -> Vec<RequiredAttributesByKindMaterial<'_>> {
    values
        .iter()
        .map(
            |(event_kind, attributes)| RequiredAttributesByKindMaterial {
                event_kind,
                attributes: string_refs(attributes),
            },
        )
        .collect()
}

fn lifecycle_material(lifecycle: &LifecycleDocument) -> LifecycleMaterial<'_> {
    LifecycleMaterial {
        kind: &lifecycle.kind,
        anchor: &lifecycle.anchor,
        ttl_seconds: lifecycle.ttl_seconds,
    }
}

fn policy_resource(spec: &PolicySpec) -> Result<&str, GeneratorError> {
    match (spec.resource.as_deref(), spec.resource_type.as_deref()) {
        (Some(resource), Some(resource_type)) if resource.trim() != resource_type.trim() => Err(
            GeneratorError("spec.resource and spec.resourceType disagree".to_owned()),
        ),
        (Some(resource), _) => Ok(resource),
        (_, Some(resource_type)) => Ok(resource_type),
        _ => Err(GeneratorError(
            "spec.resource or spec.resourceType is required".to_owned(),
        )),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index != 0,
            _ => false,
        })
}

fn render(definitions: &[Definition], detection_definitions: &[DetectionDefinition]) -> String {
    let mut output = String::from(
        "// Code generated by policycataloggen; DO NOT EDIT.\n\nuse super::{\n    DetectionDefinition, EvaluationMode, Lifecycle, LifecycleAnchor, LifecycleKind,\n    PolicyDefinition, RequiredAttributesByKind,\n};\n\npub(super) const POLICY_DEFINITIONS: &[PolicyDefinition<'static>] = &[\n",
    );
    for definition in definitions {
        output.push_str("    PolicyDefinition {\n");
        for (field, value) in [
            ("id", definition.id.as_str()),
            ("name", definition.name.as_str()),
            ("domain", definition.domain.as_str()),
            ("severity", definition.severity.as_str()),
            ("effect", definition.effect.as_str()),
            ("resource", definition.resource.as_str()),
        ] {
            output.push_str(&format!("        {field}: {},\n", rust_string(value)));
        }
        output.push_str(&format!("        enabled: {},\n", definition.enabled));
        render_detection_semantics(&mut output, &definition.detection);
        output.push_str(&format!(
            "        source_path: {},\n",
            rust_string(&definition.source_path)
        ));
        output.push_str(&format!(
            "        source_digest: {},\n",
            rust_digest(&definition.source_digest)
        ));
        output.push_str(&format!(
            "        definition_digest: {},\n",
            rust_digest(&definition.definition_digest)
        ));
        output.push_str("    },\n");
    }
    output.push_str("];\n\n");
    output
        .push_str("pub(super) const DETECTION_DEFINITIONS: &[DetectionDefinition<'static>] = &[\n");
    for definition in detection_definitions {
        output.push_str("    DetectionDefinition {\n");
        output.push_str(&format!(
            "        id: {},\n        source_id: {},\n",
            rust_string(&definition.detection.id),
            rust_string(&definition.detection.source_id),
        ));
        render_detection_semantics(&mut output, &definition.detection);
        output.push_str(&format!(
            "        definition_digest: {},\n",
            rust_digest(&definition.definition_digest)
        ));
        output.push_str("    },\n");
    }
    output.push_str("];\n");
    output
}

fn render_detection_semantics(output: &mut String, detection: &DetectionDocument) {
    output.push_str(&format!(
        "        evaluation_mode: {},\n",
        evaluation_mode_expression(&detection.evaluation_mode)
    ));
    output.push_str(&format!(
        "        event_kinds: {},\n",
        rust_string_slice(&detection.event_kinds)
    ));
    output.push_str(&format!(
        "        output_kind: {},\n",
        rust_string(&detection.output_kind)
    ));
    output.push_str(&format!(
        "        required_attributes: {},\n",
        rust_string_slice(&detection.required_attributes)
    ));
    output.push_str(&format!(
        "        required_attributes_by_kind: {},\n",
        rust_required_attributes_by_kind(&detection.required_attributes_by_kind)
    ));
    output.push_str(&format!(
        "        fingerprint_fields: {},\n",
        rust_string_slice(&detection.fingerprint_fields)
    ));
    output.push_str(&format!(
        "        lifecycle: {},\n",
        rust_lifecycle(&detection.lifecycle)
    ));
}

fn evaluation_mode_expression(value: &str) -> &'static str {
    match value {
        "event" => "EvaluationMode::Event",
        "graph" => "EvaluationMode::Graph",
        _ => unreachable!("validated evaluation mode"),
    }
}

fn rust_string_slice(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| rust_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{values}]")
}

fn rust_required_attributes_by_kind(values: &BTreeMap<String, Vec<String>>) -> String {
    if values.is_empty() {
        return "&[]".to_owned();
    }
    let mut rendered = String::from("&[\n");
    for (event_kind, attributes) in values {
        rendered.push_str("            RequiredAttributesByKind {\n");
        rendered.push_str(&format!(
            "                event_kind: {},\n                attributes: {},\n",
            rust_string(event_kind),
            rust_string_slice(attributes)
        ));
        rendered.push_str("            },\n");
    }
    rendered.push_str("        ]");
    rendered
}

fn rust_lifecycle(lifecycle: &LifecycleDocument) -> String {
    let kind = match lifecycle.kind.as_str() {
        "durable_state" => "LifecycleKind::DurableState",
        "audit_evidence" => "LifecycleKind::AuditEvidence",
        "ttl_evidence" => "LifecycleKind::TtlEvidence",
        "retired" => "LifecycleKind::Retired",
        _ => unreachable!("validated lifecycle kind"),
    };
    let anchor = match lifecycle.anchor.as_str() {
        "graph_anchored" => "LifecycleAnchor::GraphAnchored",
        "source_state" => "LifecycleAnchor::SourceState",
        "none" => "LifecycleAnchor::None",
        _ => unreachable!("validated lifecycle anchor"),
    };
    format!(
        "Lifecycle {{ kind: {kind}, anchor: {anchor}, ttl_seconds: {} }}",
        lifecycle.ttl_seconds
    )
}

fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

fn rust_digest(value: &str) -> String {
    debug_assert_eq!(value.len(), 64);
    format!(
        "concat!(\n            {},\n            {},\n            {},\n            {},\n        )",
        rust_string(&value[0..16]),
        rust_string(&value[16..32]),
        rust_string(&value[32..48]),
        rust_string(&value[48..64]),
    )
}

fn enabled_by_default() -> bool {
    true
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, GeneratorError> {
    reject_symlink(path)?;
    let file = open_no_follow(path)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| GeneratorError(format!("read {}: {error}", path.display())))?;
    if bytes.len() > limit {
        return Err(GeneratorError(format!(
            "{} exceeds {limit} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, GeneratorError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| GeneratorError(format!("open {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, GeneratorError> {
    File::open(path).map_err(|error| GeneratorError(format!("open {}: {error}", path.display())))
}

fn reject_symlink(path: &Path) -> Result<(), GeneratorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(GeneratorError(format!(
            "symlink is not allowed: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GeneratorError(format!(
            "inspect {}: {error}",
            path.display()
        ))),
    }
}

fn write_generated_file(path: &Path, content: &[u8]) -> Result<(), GeneratorError> {
    reject_symlink(path)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options
            .open(&temp)
            .map_err(|error| GeneratorError(format!("create {}: {error}", temp.display())))?;
        file.write_all(content)
            .map_err(|error| GeneratorError(format!("write {}: {error}", temp.display())))?;
        file.sync_all()
            .map_err(|error| GeneratorError(format!("sync {}: {error}", temp.display())))?;
        fs::rename(&temp, path)
            .map_err(|error| GeneratorError(format!("replace {}: {error}", path.display())))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_ids_are_strict() {
        assert!(valid_id("aws-s3-public"));
        assert!(!valid_id(""));
        assert!(!valid_id("-leading"));
        assert!(valid_id("legacyUppercase"));
        assert!(!valid_id("contains/slash"));
    }

    #[test]
    fn digest_literals_do_not_expose_one_contiguous_credential_shaped_token() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rendered = rust_digest(digest);
        assert!(rendered.starts_with("concat!("));
        assert!(!rendered.contains(digest));
        assert_eq!(rendered.matches('"').count(), 8);
    }

    #[test]
    fn modes_are_exclusive() {
        let mut mode = None;
        set_mode(&mut mode, Mode::Write).unwrap();
        assert!(set_mode(&mut mode, Mode::Check).is_err());
    }

    #[test]
    fn a_new_generated_output_is_not_mistaken_for_a_symlink() {
        let path = env::temp_dir().join(format!(
            "cerebro-policy-catalog-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        reject_symlink(&path).expect("missing output is safe to create");
    }

    #[test]
    fn policy_domain_requires_a_directory_below_the_policy_root() {
        assert_eq!(
            policy_domain(
                Path::new("policies/cloud/policy.yaml"),
                Path::new("policies"),
                "policies/cloud/policy.yaml",
            )
            .unwrap(),
            "cloud"
        );
        let error = policy_domain(
            Path::new("policies/policy.yaml"),
            Path::new("policies"),
            "policies/policy.yaml",
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "policies/policy.yaml must be placed under policies/<domain>/"
        );
    }
}
