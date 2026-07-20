use std::{
    collections::BTreeMap,
    hint::black_box,
    time::{Duration, Instant},
};

use cerebro_sourceruntime_eventadmission::{
    AdmissionRequest, EventContract, EventEnvelope, Timestamp, evaluate_json,
};

const DEFAULT_SAMPLE_MILLISECONDS: u64 = 500;
const DEFAULT_SAMPLES: usize = 5;

struct Workload {
    name: String,
    input: Vec<u8>,
}

fn main() {
    if cfg!(debug_assertions) {
        return;
    }
    let sample_duration = Duration::from_millis(environment_u64(
        "ADMISSION_BENCH_SAMPLE_MS",
        DEFAULT_SAMPLE_MILLISECONDS,
    ));
    let samples = environment_u64("ADMISSION_BENCH_SAMPLES", DEFAULT_SAMPLES as u64) as usize;
    for workload in workloads() {
        benchmark(&workload, sample_duration, samples);
    }
}

fn benchmark(workload: &Workload, sample_duration: Duration, samples: usize) {
    black_box(evaluate_json(black_box(&workload.input)).expect("warm evaluation succeeds"));
    let iterations = calibrated_iterations(&workload.input, sample_duration);
    for _ in 0..samples {
        let elapsed = run_iterations(&workload.input, iterations);
        let nanos_per_operation = elapsed.as_nanos() / u128::from(iterations);
        println!(
            "BenchmarkAdmissionRustNativeJSON/{}\t{}\t{} ns/op",
            workload.name, iterations, nanos_per_operation
        );
    }
}

fn calibrated_iterations(input: &[u8], target: Duration) -> u64 {
    let calibration_target = target.min(Duration::from_millis(100));
    let mut iterations = 1_u64;
    loop {
        let elapsed = run_iterations(input, iterations);
        if elapsed >= calibration_target {
            let scaled = (iterations as f64 * target.as_secs_f64() / elapsed.as_secs_f64())
                .ceil()
                .max(1.0);
            return scaled as u64;
        }
        iterations = iterations.saturating_mul(2);
        assert!(iterations != u64::MAX, "benchmark calibration overflowed");
    }
}

fn run_iterations(input: &[u8], iterations: u64) -> Duration {
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(evaluate_json(black_box(input)).expect("benchmark evaluation succeeds"));
    }
    started.elapsed()
}

fn workloads() -> Vec<Workload> {
    vec![
        accepted_workload(1, 0),
        accepted_workload(100, 0),
        accepted_workload(1_000, 0),
        accepted_workload(5_000, 0),
        quarantine_workload(1_000),
        duplicate_workload(1_000),
        conflict_workload(1_000),
        accepted_workload(100, 1 << 10),
        accepted_workload(100, 10 << 10),
    ]
}

fn accepted_workload(count: usize, blob_bytes: usize) -> Workload {
    let mut name = format!("accepted/events_{count}");
    if blob_bytes != 0 {
        name = format!("{name}/payload_{}k", blob_bytes >> 10);
    }
    let events = (0..count)
        .map(|index| event(index, blob_bytes, false))
        .collect();
    workload(name, events)
}

fn quarantine_workload(count: usize) -> Workload {
    let events = (0..count)
        .map(|index| event(index, 0, index % 10 == 9))
        .collect();
    workload(format!("quarantine_10_percent/events_{count}"), events)
}

fn duplicate_workload(count: usize) -> Workload {
    let mut events = Vec::<EventEnvelope>::with_capacity(count);
    for index in 0..count {
        if index % 10 == 9 {
            events.push(events.last().expect("prior event exists").clone());
        } else {
            events.push(event(index, 0, false));
        }
    }
    workload(format!("duplicate_10_percent/events_{count}"), events)
}

fn conflict_workload(count: usize) -> Workload {
    let mut events = (0..count)
        .map(|index| event(index, 0, false))
        .collect::<Vec<_>>();
    let first_id = events[0].id.clone();
    events.last_mut().expect("events are not empty").id = first_id;
    workload(format!("conflicting_duplicate/events_{count}"), events)
}

fn workload(name: String, events: Vec<EventEnvelope>) -> Workload {
    let request = AdmissionRequest {
        schema_version: "source-event-admission.v2".to_owned(),
        contracts: vec![EventContract {
            kind: "directory.identity".to_owned(),
            schema_ref: "directory/identity/v1".to_owned(),
            required_attributes: vec!["resource_id".to_owned()],
            required_payload_fields: vec!["identity.id".to_owned()],
        }],
        events,
    };
    Workload {
        name,
        input: serde_json::to_vec(&request).expect("benchmark request serializes"),
    }
}

fn event(index: usize, blob_bytes: usize, quarantine: bool) -> EventEnvelope {
    let identity = if quarantine {
        "{}".to_owned()
    } else {
        format!(r#"{{"id":"user-{index}"}}"#)
    };
    let payload_json = if blob_bytes == 0 {
        format!(r#"{{"identity":{identity}}}"#)
    } else {
        format!(
            r#"{{"blob":"{}","identity":{identity}}}"#,
            "x".repeat(blob_bytes)
        )
    };
    EventEnvelope {
        id: format!("event-{index}"),
        tenant_id: "tenant-1".to_owned(),
        source_id: "directory".to_owned(),
        kind: "directory.identity".to_owned(),
        occurred_at: Some(Timestamp {
            seconds: 1_784_116_800,
            nanos: 0,
        }),
        schema_ref: "directory/identity/v1".to_owned(),
        payload_json,
        attributes: BTreeMap::from([
            ("resource_id".to_owned(), format!("user-{index}")),
            ("resource_type".to_owned(), "identity".to_owned()),
        ]),
    }
}

fn environment_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
