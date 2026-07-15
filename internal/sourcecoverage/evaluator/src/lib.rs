use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

pub const ABI_VERSION: u32 = 1;

const STATE_HEALTHY: &str = "healthy";
const STATE_PARTIAL: &str = "partial";
const STATE_UNSUPPORTED: &str = "unsupported";
const STATE_UNCONFIGURED: &str = "unconfigured";
const STATE_STALE: &str = "stale";
const STATE_FAILED: &str = "failed";
const STATE_UNKNOWN: &str = "unknown";
const CERTIFICATION_UNKNOWN: &str = "unknown";
const CERTIFICATION_CATALOG_DECLARED: &str = "catalog_declared";
const CERTIFICATION_FIXTURE_VALIDATED: &str = "fixture_validated";
const CERTIFICATION_LIVE_VALIDATED: &str = "live_validated";

#[derive(Debug, Deserialize)]
pub struct EvaluationRequest {
    #[serde(default)]
    contracts: Vec<CoverageContract>,
    #[serde(default)]
    observations: Vec<RuntimeObservation>,
    #[serde(default)]
    options: Options,
}

#[derive(Debug, Deserialize)]
struct CoverageContract {
    #[serde(default)]
    source_id: String,
    #[serde(default)]
    owner_domain: String,
    #[serde(default)]
    authority_domain: String,
    #[serde(default)]
    dimensions: Vec<CoverageDimension>,
}

#[derive(Debug, Deserialize)]
struct CoverageDimension {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    dimension_type: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    families: Vec<String>,
    #[serde(default)]
    runtime_families: Vec<String>,
    #[serde(default)]
    support: String,
    #[serde(default)]
    high_value: bool,
    #[serde(default)]
    known_unsupported_fields: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    evidence_types: Vec<String>,
    #[serde(default)]
    control_domains: Vec<String>,
    #[serde(default)]
    control_refs: Vec<CoverageControlRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
struct CoverageControlRef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    framework_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    framework_name: String,
    control_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RuntimeObservation {
    #[serde(default)]
    runtime_id: String,
    #[serde(default)]
    source_id: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    last_failure_category: String,
    #[serde(default)]
    last_synced_at: String,
    #[serde(default)]
    certification_tier: String,
}

#[derive(Debug, Default, Deserialize)]
struct Options {
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    source_id: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Serialize)]
struct EvaluationResponse {
    records: Vec<Record>,
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct Record {
    source_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tenant_id: String,
    dimension_id: String,
    dimension_type: String,
    title: String,
    state: String,
    support_level: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    runtime_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_synced_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    owner_domain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    authority_domain: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    high_value: bool,
    blind_spot: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    warning: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known_unsupported_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    evidence_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    control_domains: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    control_refs: Vec<CoverageControlRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    supported_runtime_families: Vec<String>,
    certification_tier: String,
}

pub fn evaluate(request: EvaluationRequest) -> Vec<Record> {
    let tenant_id = request.options.tenant_id.trim();
    let source_filter = request.options.source_id.trim();
    let observations = observations_by_source(request.observations);
    let mut records = Vec::new();

    for contract in request.contracts {
        let source_id = contract.source_id.trim();
        if source_id.is_empty() || (!source_filter.is_empty() && source_id != source_filter) {
            continue;
        }
        let source_observations = observations
            .get(source_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for dimension in contract.dimensions {
            if let Some(record) = coverage_record(
                source_id,
                contract.owner_domain.trim(),
                contract.authority_domain.trim(),
                dimension,
                source_observations,
                tenant_id,
            ) {
                records.push(record);
            }
        }
    }

    records.sort_by(compare_records);
    records
}

fn observations_by_source(
    observations: Vec<RuntimeObservation>,
) -> HashMap<String, Vec<RuntimeObservation>> {
    let mut by_source = HashMap::<String, Vec<RuntimeObservation>>::new();
    for observation in observations {
        let source_id = observation.source_id.trim();
        if source_id.is_empty() {
            continue;
        }
        by_source
            .entry(source_id.to_owned())
            .or_default()
            .push(observation);
    }
    by_source
}

fn coverage_record(
    source_id: &str,
    owner_domain: &str,
    authority_domain: &str,
    dimension: CoverageDimension,
    observations: &[RuntimeObservation],
    tenant_id: &str,
) -> Option<Record> {
    let dimension_id = dimension.id.trim();
    let dimension_type = dimension.dimension_type.trim();
    let title = dimension.title.trim();
    if dimension_id.is_empty() || dimension_type.is_empty() || title.is_empty() {
        return None;
    }
    let support = dimension.support.trim().to_ascii_lowercase();
    let runtime_families = coverage_runtime_families(&dimension);
    let supported_runtime_families = unique_non_empty_strings(
        dimension
            .families
            .iter()
            .chain(dimension.runtime_families.iter()),
    );
    let mut record = Record {
        source_id: source_id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        dimension_id: dimension_id.to_owned(),
        dimension_type: dimension_type.to_owned(),
        title: title.to_owned(),
        support_level: support.clone(),
        owner_domain: owner_domain.to_owned(),
        authority_domain: authority_domain.to_owned(),
        high_value: dimension.high_value,
        known_unsupported_fields: dimension.known_unsupported_fields,
        notes: dimension.notes,
        evidence_types: dimension.evidence_types,
        control_domains: dimension.control_domains,
        control_refs: dimension.control_refs,
        supported_runtime_families,
        certification_tier: CERTIFICATION_UNKNOWN.to_owned(),
        ..Record::default()
    };

    if support == "unsupported" || support == "planned" {
        record.state = STATE_UNSUPPORTED.to_owned();
        return Some(with_blind_spot(record));
    }

    let matches = matching_observations(observations, &runtime_families, tenant_id);
    let Some(best) = most_concerning_observation(&matches) else {
        record.state = STATE_UNCONFIGURED.to_owned();
        return Some(with_blind_spot(record));
    };
    record.runtime_id = best.runtime_id.clone();
    record.family = best.family.clone();
    record.last_synced_at = best.last_synced_at.clone();
    record.certification_tier = bounded_certification_tier(&best.certification_tier).to_owned();
    record.state = observation_state(best).to_owned();
    if record.state == STATE_HEALTHY && support == "partial" {
        record.state = STATE_PARTIAL.to_owned();
    }
    Some(with_blind_spot(record))
}

fn bounded_certification_tier(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        CERTIFICATION_CATALOG_DECLARED => CERTIFICATION_CATALOG_DECLARED,
        CERTIFICATION_FIXTURE_VALIDATED => CERTIFICATION_FIXTURE_VALIDATED,
        CERTIFICATION_LIVE_VALIDATED => CERTIFICATION_LIVE_VALIDATED,
        _ => CERTIFICATION_UNKNOWN,
    }
}

fn coverage_runtime_families(dimension: &CoverageDimension) -> Vec<String> {
    let runtime_families = unique_non_empty_strings(dimension.runtime_families.iter());
    if runtime_families.is_empty() {
        return unique_non_empty_strings(dimension.families.iter());
    }
    runtime_families
}

fn unique_non_empty_strings<'a>(values: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && seen.insert(value.to_owned()) {
            result.push(value.to_owned());
        }
    }
    result
}

fn matching_observations<'a>(
    observations: &'a [RuntimeObservation],
    families: &[String],
    tenant_id: &str,
) -> Vec<&'a RuntimeObservation> {
    let family_set: HashSet<&str> = families.iter().map(String::as_str).collect();
    observations
        .iter()
        .filter(|observation| {
            (tenant_id.is_empty() || observation.tenant_id.trim() == tenant_id)
                && (family_set.is_empty() || family_set.contains(observation.family.trim()))
        })
        .collect()
}

fn most_concerning_observation<'a>(
    observations: &[&'a RuntimeObservation],
) -> Option<&'a RuntimeObservation> {
    let mut best = *observations.first()?;
    for observation in &observations[1..] {
        if state_rank(observation_state(observation)) < state_rank(observation_state(best)) {
            best = observation;
        }
    }
    Some(best)
}

fn observation_state(observation: &RuntimeObservation) -> &'static str {
    if !observation.last_failure_category.trim().is_empty() {
        return STATE_FAILED;
    }
    if observation.status.trim().eq_ignore_ascii_case("failing")
        || observation.status.trim().eq_ignore_ascii_case("failed")
    {
        STATE_FAILED
    } else if observation.status.trim().eq_ignore_ascii_case("stale") {
        STATE_STALE
    } else if observation.status.trim().eq_ignore_ascii_case("healthy")
        || observation.status.trim().eq_ignore_ascii_case("current")
    {
        STATE_HEALTHY
    } else if observation.status.trim().eq_ignore_ascii_case("partial") {
        STATE_PARTIAL
    } else {
        STATE_UNKNOWN
    }
}

fn with_blind_spot(mut record: Record) -> Record {
    record.blind_spot = record.high_value && record.state != STATE_HEALTHY;
    if record.blind_spot {
        record.warning = coverage_warning(&record);
    }
    record
}

fn coverage_warning(record: &Record) -> String {
    let subject = if record.title.trim().is_empty() {
        record.dimension_id.trim()
    } else {
        record.title.trim()
    };
    let source_id = record.source_id.trim();
    match record.state.as_str() {
        STATE_UNSUPPORTED => format!("{subject} coverage is unsupported by {source_id}"),
        STATE_UNCONFIGURED if !record.tenant_id.is_empty() => format!(
            "{subject} coverage is unconfigured for tenant {}",
            record.tenant_id
        ),
        STATE_UNCONFIGURED => format!("{subject} coverage is unconfigured"),
        STATE_STALE => format!("{subject} coverage is stale for {source_id}"),
        STATE_FAILED => format!("{subject} coverage is failing for {source_id}"),
        STATE_PARTIAL => format!("{subject} coverage is partial for {source_id}"),
        state => format!("{subject} coverage state is {state} for {source_id}"),
    }
}

fn compare_records(left: &Record, right: &Record) -> Ordering {
    left.source_id
        .cmp(&right.source_id)
        .then_with(|| right.blind_spot.cmp(&left.blind_spot))
        .then_with(|| state_rank(&left.state).cmp(&state_rank(&right.state)))
        .then_with(|| left.dimension_id.cmp(&right.dimension_id))
}

fn state_rank(state: &str) -> u8 {
    match state {
        STATE_FAILED => 0,
        STATE_STALE => 1,
        STATE_UNCONFIGURED => 2,
        STATE_UNSUPPORTED => 3,
        STATE_PARTIAL => 4,
        STATE_UNKNOWN => 5,
        STATE_HEALTHY => 6,
        _ => 7,
    }
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_sourcecoverage_abi_version() -> u32 {
    ABI_VERSION
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_sourcecoverage_alloc(length: u32) -> u32 {
    let mut bytes = vec![0_u8; length as usize];
    let pointer = bytes.as_mut_ptr() as usize;
    std::mem::forget(bytes);
    u32::try_from(pointer).unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn cerebro_sourcecoverage_evaluate(
    request_pointer: u32,
    request_length: u32,
    result_pointer: u32,
) -> u32 {
    const RESULT_SIZE: usize = 16;
    let request_start = request_pointer as usize;
    let result_start = result_pointer as usize;
    let Some(request_end) = request_start.checked_add(request_length as usize) else {
        return 3;
    };
    let Some(result_end) = result_start.checked_add(RESULT_SIZE) else {
        return 3;
    };
    let memory_size = core::arch::wasm32::memory_size(0) * 65_536;
    if request_end > memory_size || result_end > memory_size {
        return 3;
    }

    // SAFETY: The host allocates the request range in this module and the bounds are checked above.
    let request_bytes = unsafe {
        std::slice::from_raw_parts(request_pointer as *const u8, request_length as usize)
    };
    let request: EvaluationRequest = match serde_json::from_slice(request_bytes) {
        Ok(request) => request,
        Err(_) => return 1,
    };
    let response = EvaluationResponse {
        records: evaluate(request),
    };
    let mut output = match serde_json::to_vec(&response) {
        Ok(output) => output,
        Err(_) => return 2,
    };
    let Ok(output_pointer) = u32::try_from(output.as_mut_ptr() as usize) else {
        return 2;
    };
    let Ok(output_length) = u32::try_from(output.len()) else {
        return 2;
    };
    std::mem::forget(output);

    let mut result = [0_u8; RESULT_SIZE];
    result[4..8].copy_from_slice(&output_pointer.to_le_bytes());
    result[8..12].copy_from_slice(&output_length.to_le_bytes());
    // SAFETY: The result range is checked against linear memory above.
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_pointer as *mut u8, result.len())
    };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> EvaluationRequest {
        serde_json::from_str(json).expect("fixture request")
    }

    #[test]
    fn evaluates_and_sorts_batch_by_source_blind_spot_and_state() {
        let records = evaluate(request(
            r#"{
              "contracts": [
                {"source_id":" zeta ","dimensions":[
                  {"id":" users ","type":" entity_family ","title":" Users ","families":[" user "],"support":" supported ","high_value":true},
                  {"id":"apps","type":"entity_family","title":"Applications","families":["application"],"support":"supported","high_value":true}
                ]},
                {"source_id":"alpha","dimensions":[
                  {"id":"audit","type":"audit_event","title":"Audit","families":["audit"],"support":"partial","high_value":true}
                ]}
              ],
              "observations": [
                {"runtime_id":"z-user","source_id":"zeta","tenant_id":"tenant-a","family":"user","status":"healthy","certification_tier":" Fixture_Validated "},
                {"runtime_id":"a-audit","source_id":"alpha","tenant_id":"tenant-a","family":"audit","status":"healthy"}
              ],
              "options":{"tenant_id":" tenant-a "}
            }"#,
        ));
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].source_id, "alpha");
        assert_eq!(records[0].state, STATE_PARTIAL);
        assert!(records[0].blind_spot);
        assert_eq!(records[1].dimension_id, "apps");
        assert_eq!(records[1].state, STATE_UNCONFIGURED);
        assert_eq!(records[1].certification_tier, CERTIFICATION_UNKNOWN);
        assert_eq!(records[2].dimension_id, "users");
        assert_eq!(records[2].state, STATE_HEALTHY);
        assert_eq!(
            records[2].certification_tier,
            CERTIFICATION_FIXTURE_VALIDATED
        );
    }

    #[test]
    fn failure_wins_and_first_observation_wins_ties() {
        let records = evaluate(request(
            r#"{
              "contracts":[{"source_id":"okta","dimensions":[{"id":"users","type":"entity_family","title":"Users","families":["user"],"support":"supported","high_value":true}]}],
              "observations":[
                {"runtime_id":"first-failed","source_id":"okta","tenant_id":"tenant-a","family":"user","status":"healthy","last_failure_category":"schema"},
                {"runtime_id":"second-failed","source_id":"okta","tenant_id":"tenant-a","family":"user","status":"failed"},
                {"runtime_id":"healthy","source_id":"okta","tenant_id":"tenant-a","family":"user","status":"healthy"}
              ],
              "options":{"tenant_id":"tenant-a"}
            }"#,
        ));
        assert_eq!(records[0].state, STATE_FAILED);
        assert_eq!(records[0].runtime_id, "first-failed");
        assert_eq!(records[0].warning, "Users coverage is failing for okta");
    }

    #[test]
    fn runtime_family_override_and_supported_family_union_preserve_order() {
        let records = evaluate(request(
            r#"{
              "contracts":[{"source_id":"addigy","dimensions":[{"id":"devices","type":"entity_family","title":"Devices","families":[" device ","device"],"runtime_families":[" devices ","devices"],"support":"supported"}]}],
              "observations":[
                {"runtime_id":"singular","source_id":"addigy","family":"device","status":"failed"},
                {"runtime_id":"plural","source_id":"addigy","family":"devices","status":"healthy","certification_tier":"future_tier"}
              ]
            }"#,
        ));
        assert_eq!(records[0].runtime_id, "plural");
        assert_eq!(records[0].supported_runtime_families, ["device", "devices"]);
        assert_eq!(records[0].certification_tier, CERTIFICATION_UNKNOWN);
    }

    #[test]
    fn filters_sources_tenants_and_invalid_dimensions() {
        let records = evaluate(request(
            r#"{
              "contracts":[
                {"source_id":"okta","dimensions":[
                  {"id":"","type":"entity_family","title":"Invalid","support":"supported"},
                  {"id":"users","type":"entity_family","title":"Users","families":["user"],"support":"supported"}
                ]},
                {"source_id":"github","dimensions":[{"id":"repos","type":"entity_family","title":"Repositories","support":"planned","high_value":true}]}
              ],
              "observations":[
                {"runtime_id":"wrong-tenant","source_id":"okta","tenant_id":"tenant-b","family":"user","status":"healthy"},
                {"runtime_id":"right-tenant","source_id":"okta","tenant_id":"tenant-a","family":"user","status":"stale"}
              ],
              "options":{"tenant_id":"tenant-a","source_id":"okta"}
            }"#,
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].runtime_id, "right-tenant");
        assert_eq!(records[0].state, STATE_STALE);
    }
}
