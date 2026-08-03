#![forbid(unsafe_code)]

mod execution_v2;
mod promotion;

use std::{env, error::Error, fs, path::Path, time::Duration};

use cerebro_slack_agent_eval_wire::{
    AGENT_DELIVERY_RECEIPT_V1, BLACKBOX_RECEIPT_V1, BLIND_PACKET_V1, BlackboxReceipt, BlindPacket,
    BlindTranscriptTurn, CandidateAttestation, CandidateDeliveryReceipt,
    CandidateRuntimeAttestation, CandidateTurnOutcome, DeterministicDefect, DigestEnvelope,
    ExchangeReceipt, HarnessTelemetry, OPERATOR_TURN_V1, OperatorDecision, OperatorTurnRequest,
    SupervisorEpisodeSpec, TranscriptTurn, sha256_json, sha256_text,
};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const USAGE: &str = "usage:\n  slack-agent-blackbox run CONFIG.json RECEIPT.json\n  slack-agent-blackbox run-v2 CONFIG.json RECEIPT.json\n  slack-agent-blackbox blind RECEIPT.json ASSIGNMENT_REF CANDIDATE_ALIAS BRIEF.json PACKET.json\n  slack-agent-blackbox verify-receipt RECEIPT.json\n  slack-agent-blackbox commit-holdouts-v2 SUITE.json PRIVATE_ASSIGNMENTS.json COMMITMENT.json\n  slack-agent-blackbox verify-promotion-v2 BUNDLE.json";
const RUN_CONFIG_V1: &str = "slack-agent-blackbox-run-config/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    schema_version: String,
    candidate_base_url: String,
    operator_url: String,
    #[serde(default)]
    restart_url: Option<String>,
    candidate_ref: String,
    candidate_artifact_digest: String,
    episode: SupervisorEpisodeSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfigV2 {
    execution: execution_v2::SupervisorExecutionConfigV2,
    public_keys: Vec<promotion::Ed25519PublicKeyBinding>,
}

struct ExecutionReceiptVerifier(promotion::Ed25519KeyringVerifier);

impl execution_v2::ReceiptSignatureVerifierV2 for ExecutionReceiptVerifier {
    fn verify(
        &self,
        payload_digest: &str,
        signer: &cerebro_slack_agent_eval_wire::SignerAttestationV2,
        signature_base64: &str,
    ) -> Result<(), String> {
        promotion::ReceiptSignatureVerifier::verify(
            &self.0,
            signer,
            payload_digest,
            signature_base64,
        )
    }
}

#[derive(Debug, Deserialize)]
struct AuthorityStatusWire {
    schema_version: String,
    agent_ready: bool,
    build_commit_sha: String,
    build_tree_clean: bool,
    runtime_instance_ref: String,
    model_provider: Option<String>,
    model_id: Option<String>,
    model_config_sha256: Option<String>,
    session_schema_version: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = dispatch(env::args().skip(1).collect()).await {
        eprintln!("slack-agent-blackbox: {error}");
        std::process::exit(1);
    }
}

async fn dispatch(arguments: Vec<String>) -> Result<(), Box<dyn Error>> {
    match arguments.as_slice() {
        [command, config, output] if command == "run" => run(config, output).await,
        [command, config, output] if command == "run-v2" => run_v2(config, output).await,
        [command, receipt, assignment, alias, brief, output] if command == "blind" => {
            blind(receipt, assignment, alias, brief, output)
        }
        [command, receipt] if command == "verify-receipt" => verify_receipt(receipt),
        [command, suite, assignments, output] if command == "commit-holdouts-v2" => {
            promotion::validate_suite_files_and_write_commitment(suite, assignments, output)?;
            Ok(())
        }
        [command, bundle] if command == "verify-promotion-v2" => {
            promotion::verify_promotion_file(bundle)?;
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

async fn run_v2(config_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    let config: RunConfigV2 = read_json(config_path)?;
    let verifier =
        ExecutionReceiptVerifier(promotion::Ed25519KeyringVerifier::new(config.public_keys)?);
    let output = execution_v2::execute_supervisor_v2(&config.execution, &verifier).await?;
    write_json(output_path, &output)?;
    if !output.passed_deterministic_execution() {
        return Err("V2 episode failed a deterministic execution gate".into());
    }
    Ok(())
}

async fn run(config_path: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    let config: RunConfig = read_json(config_path)?;
    validate_config(&config)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()?;
    let initial_runtime = read_status(&client, &config.candidate_base_url).await?;
    validate_runtime(&initial_runtime)?;
    let candidate = CandidateAttestation {
        candidate_ref: config.candidate_ref.clone(),
        artifact_digest: config.candidate_artifact_digest.clone(),
        runtime: initial_runtime.clone(),
    };
    let private_context_digest = sha256_json(&config.episode.private_context)?;
    let mut request = config.episode.initial_turn.clone();
    let mut transcript = vec![TranscriptTurn {
        role: "operator".into(),
        message: request.message.clone(),
    }];
    let mut exchanges = Vec::new();
    let mut defects = Vec::new();
    let mut restart_observed = false;
    let mut concluded = false;

    for sequence in 1..=config.episode.limits.max_exchanges {
        let runtime = match read_status(&client, &config.candidate_base_url).await {
            Ok(runtime) => runtime,
            Err(error) => {
                defects.push(terminal(
                    "candidate_status_unavailable",
                    bounded_error(error.as_ref()),
                ));
                break;
            }
        };
        if let Err(detail) = same_candidate(&initial_runtime, &runtime) {
            defects.push(terminal("candidate_identity_changed", detail));
            break;
        }
        let exchange = match run_exchange(
            &client,
            &config.candidate_base_url,
            request.clone(),
            sequence,
            &runtime.runtime_instance_ref,
            config.episode.limits.turn_timeout_ms,
        )
        .await
        {
            Ok(exchange) => exchange,
            Err(error) => {
                defects.push(terminal(
                    "candidate_turn_failed",
                    bounded_error(error.as_ref()),
                ));
                break;
            }
        };
        if let Some(lane) = exchange.outcome.telemetry().0
            && let Some(limit_ms) = config.episode.limits.lane_latency_limits_ms.get(lane)
            && exchange.latency_ms > *limit_ms
        {
            defects.push(terminal(
                "lane_latency_exceeded",
                format!(
                    "The {lane} turn took {} ms; the sealed episode limit is {limit_ms} ms.",
                    exchange.latency_ms
                ),
            ));
        }
        if let Some(markdown) = exchange.outcome.markdown() {
            transcript.push(TranscriptTurn {
                role: "assistant".into(),
                message: markdown.into(),
            });
        }
        let operator_request = OperatorTurnRequest {
            schema_version: OPERATOR_TURN_V1.into(),
            episode_ref: config.episode.episode_ref.clone(),
            private_context: config.episode.private_context.clone(),
            transcript: transcript.clone(),
            latest_exchange: exchange.clone(),
        };
        exchanges.push(exchange);

        if defects.iter().any(|defect| defect.terminal) {
            break;
        }

        let decision = match call_operator(
            &client,
            &config.operator_url,
            &operator_request,
            config.episode.limits.operator_timeout_ms,
        )
        .await
        {
            Ok(decision) => decision,
            Err(error) => {
                defects.push(terminal(
                    "operator_turn_failed",
                    bounded_error(error.as_ref()),
                ));
                break;
            }
        };
        match decision {
            OperatorDecision::Conclude { .. } => {
                concluded = true;
                break;
            }
            OperatorDecision::Abort { reason } => {
                defects.push(terminal("operator_aborted", reason));
                break;
            }
            OperatorDecision::Continue { message, .. } => {
                if sequence == config.episode.limits.max_exchanges {
                    defects.push(terminal(
                        "operator_unsatisfied_at_limit",
                        "The independent operator requested another exchange after the episode limit.",
                    ));
                    break;
                }
                transcript.push(TranscriptTurn {
                    role: "operator".into(),
                    message: message.clone(),
                });
                request = next_request(&config.episode, &request, sequence + 1, message)?;
            }
        }

        if config.episode.limits.restart_after_exchange == Some(sequence) {
            match config.restart_url.as_deref() {
                Some(url) => {
                    let restarted =
                        match restart_candidate(&client, url, &config.candidate_base_url, &runtime)
                            .await
                        {
                            Ok(restarted) => restarted,
                            Err(error) => {
                                defects.push(terminal(
                                    "candidate_restart_failed",
                                    bounded_error(error.as_ref()),
                                ));
                                break;
                            }
                        };
                    if let Err(detail) = same_candidate(&initial_runtime, &restarted) {
                        defects.push(terminal("candidate_identity_changed", detail));
                        break;
                    }
                    if restarted.runtime_instance_ref == runtime.runtime_instance_ref {
                        defects.push(terminal(
                            "restart_not_observed",
                            "The lifecycle controller returned without a new runtime instance.",
                        ));
                        break;
                    }
                    restart_observed = true;
                }
                None => {
                    defects.push(terminal(
                        "restart_controller_missing",
                        "The episode requires a restart but no lifecycle controller was configured.",
                    ));
                    break;
                }
            }
        }
    }

    if !concluded && defects.is_empty() {
        defects.push(terminal(
            "episode_not_concluded",
            "The episode ended without independent operator acceptance.",
        ));
    }
    if config.episode.limits.restart_after_exchange.is_some() && !restart_observed {
        defects.push(terminal(
            "persistence_not_exercised",
            "The required runtime restart did not occur.",
        ));
    }

    let telemetry = HarnessTelemetry {
        exchange_count: exchanges.len(),
        total_latency_ms: exchanges.iter().map(|exchange| exchange.latency_ms).sum(),
        tool_call_count: exchanges
            .iter()
            .map(|exchange| exchange.outcome.telemetry().2)
            .sum(),
        restart_observed,
    };
    let receipt = DigestEnvelope::new(BlackboxReceipt {
        schema_version: BLACKBOX_RECEIPT_V1.into(),
        episode_ref: config.episode.episode_ref,
        candidate,
        private_context_digest,
        transcript,
        exchanges,
        telemetry,
        deterministic_defects: defects,
        completed_at: now()?,
    })?;
    write_json(output_path, &receipt)?;
    if receipt
        .payload
        .deterministic_defects
        .iter()
        .any(|defect| defect.terminal)
    {
        return Err("episode failed a deterministic gate".into());
    }
    Ok(())
}

async fn run_exchange(
    client: &Client,
    candidate_base_url: &str,
    request: cerebro_slack_agent_eval_wire::CandidateTurnRequest,
    sequence: usize,
    runtime_instance_ref: &str,
    timeout_ms: u64,
) -> Result<ExchangeReceipt, Box<dyn Error>> {
    let request_digest = sha256_json(&request)?;
    let started_at = now()?;
    let started = tokio::time::Instant::now();
    let response = client
        .post(endpoint(candidate_base_url, "/v1/turns/run"))
        .timeout(Duration::from_millis(timeout_ms))
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(format!("candidate turn returned {status}: {}", bounded_body(&body)).into());
    }
    let outcome: CandidateTurnOutcome = serde_json::from_slice(&body)?;
    let response_digest = sha256_json(&outcome)?;
    let delivery = if outcome.needs_delivery() {
        let markdown = outcome
            .markdown()
            .ok_or("pending delivery omitted markdown")?;
        let receipt = CandidateDeliveryReceipt {
            schema_version: AGENT_DELIVERY_RECEIPT_V1.into(),
            tenant_id: request.tenant_id.clone(),
            thread_ref: request.thread_ref.clone(),
            request_id: request.request_id.clone(),
            transport: "slack-blackbox".into(),
            delivery_ref: format!("blackbox-delivery:{sequence}"),
            payload_digest: sha256_text(markdown),
            delivered_at: now()?,
        };
        let response = client
            .post(endpoint(candidate_base_url, "/v1/turns/deliveries"))
            .json(&receipt)
            .send()
            .await?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(format!("delivery receipt returned {}", response.status()).into());
        }
        Some(receipt)
    } else {
        None
    };
    Ok(ExchangeReceipt {
        sequence,
        request_digest,
        response_digest,
        runtime_instance_ref: runtime_instance_ref.into(),
        started_at,
        completed_at: now()?,
        latency_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        request,
        outcome,
        delivery,
    })
}

async fn call_operator(
    client: &Client,
    operator_url: &str,
    request: &OperatorTurnRequest,
    timeout_ms: u64,
) -> Result<OperatorDecision, Box<dyn Error>> {
    let operation = async {
        let response = client.post(operator_url).json(request).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(format!("operator returned {status}: {}", bounded_body(&body)).into());
        }
        Ok(serde_json::from_slice(&body)?)
    };
    match tokio::time::timeout(Duration::from_millis(timeout_ms), operation).await {
        Ok(result) => result,
        Err(_) => Err(format!("operator turn exceeded its sealed {timeout_ms} ms timeout").into()),
    }
}

async fn read_status(
    client: &Client,
    candidate_base_url: &str,
) -> Result<CandidateRuntimeAttestation, Box<dyn Error>> {
    let response = client
        .get(endpoint(candidate_base_url, "/v1/status"))
        .send()
        .await?
        .error_for_status()?;
    let status: AuthorityStatusWire = response.json().await?;
    Ok(CandidateRuntimeAttestation {
        schema_version: status.schema_version,
        agent_ready: status.agent_ready,
        build_commit_sha: status.build_commit_sha,
        build_tree_clean: status.build_tree_clean,
        runtime_instance_ref: status.runtime_instance_ref,
        model_provider: status.model_provider,
        model_id: status.model_id,
        model_config_sha256: status.model_config_sha256,
        session_schema_version: status.session_schema_version,
    })
}

async fn restart_candidate(
    client: &Client,
    restart_url: &str,
    candidate_base_url: &str,
    previous: &CandidateRuntimeAttestation,
) -> Result<CandidateRuntimeAttestation, Box<dyn Error>> {
    client.post(restart_url).send().await?.error_for_status()?;
    for _ in 0..90 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(status) = read_status(client, candidate_base_url).await
            && status.runtime_instance_ref != previous.runtime_instance_ref
        {
            return Ok(status);
        }
    }
    Err("candidate did not return with a new runtime instance within 90 seconds".into())
}

fn validate_config(config: &RunConfig) -> Result<(), Box<dyn Error>> {
    if config.schema_version != RUN_CONFIG_V1 {
        return Err("unsupported run config schema".into());
    }
    if config.episode.schema_version != cerebro_slack_agent_eval_wire::SUPERVISOR_EPISODE_V1
        || config.episode.initial_turn.schema_version
            != cerebro_slack_agent_eval_wire::AGENT_TURN_REQUEST_V1
        || config.episode.limits.max_exchanges == 0
        || config.episode.limits.max_exchanges > 24
        || config.episode.limits.turn_timeout_ms < 1_000
        || config.episode.limits.turn_timeout_ms > 600_000
        || config.episode.limits.operator_timeout_ms < 1_000
        || config.episode.limits.operator_timeout_ms > 180_000
        || config.episode.limits.lane_latency_limits_ms.is_empty()
        || config
            .episode
            .limits
            .lane_latency_limits_ms
            .values()
            .any(|limit| *limit < 1_000 || *limit > config.episode.limits.turn_timeout_ms)
    {
        return Err("invalid bounded episode configuration".into());
    }
    let initial = &config.episode.initial_turn;
    for value in [
        initial.tenant_id.as_str(),
        initial.request_id.as_str(),
        initial.thread_ref.as_str(),
        initial.actor_ref.as_str(),
    ] {
        if discloses_evaluation(value) {
            return Err("candidate-visible identifiers disclose evaluation context".into());
        }
    }
    if initial
        .context_scope_ref
        .as_deref()
        .is_some_and(discloses_evaluation)
    {
        return Err("candidate-visible identifiers disclose evaluation context".into());
    }
    Ok(())
}

fn discloses_evaluation(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "blackbox",
        "holdout",
        "episode",
        "grader",
        "candidate",
        "eval-",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn validate_runtime(runtime: &CandidateRuntimeAttestation) -> Result<(), Box<dyn Error>> {
    if !runtime.agent_ready
        || !runtime.build_tree_clean
        || runtime.build_commit_sha.len() != 40
        || runtime.model_id.as_deref().is_none_or(str::is_empty)
        || runtime
            .model_config_sha256
            .as_deref()
            .is_none_or(|digest| !valid_sha256(digest))
        || runtime.runtime_instance_ref.is_empty()
    {
        return Err("candidate runtime attestation is incomplete or dirty".into());
    }
    Ok(())
}

fn same_candidate(
    expected: &CandidateRuntimeAttestation,
    actual: &CandidateRuntimeAttestation,
) -> Result<(), String> {
    if expected.build_commit_sha != actual.build_commit_sha
        || expected.build_tree_clean != actual.build_tree_clean
        || expected.model_provider != actual.model_provider
        || expected.model_id != actual.model_id
        || expected.model_config_sha256 != actual.model_config_sha256
        || expected.session_schema_version != actual.session_schema_version
    {
        return Err(
            "commit, model configuration, or session schema changed during the episode".into(),
        );
    }
    Ok(())
}

fn next_request(
    episode: &SupervisorEpisodeSpec,
    previous: &cerebro_slack_agent_eval_wire::CandidateTurnRequest,
    sequence: usize,
    message: String,
) -> Result<cerebro_slack_agent_eval_wire::CandidateTurnRequest, Box<dyn Error>> {
    let mut request = previous.clone();
    request.request_id = opaque_request_ref(&episode.episode_ref, sequence);
    request.assessment_at = now()?;
    request.message = message;
    request.history.clear();
    request.history_metadata.clear();
    request.working_state = None;
    request.effect_authorizations.clear();
    Ok(request)
}

fn opaque_request_ref(episode_ref: &str, sequence: usize) -> String {
    let digest = sha256_text(&format!("blackbox-request/v1\n{episode_ref}\n{sequence}"));
    format!("slack-request-{}", &digest[7..])
}

fn blind(
    receipt_path: &str,
    assignment_ref: &str,
    candidate_alias: &str,
    brief_path: &str,
    output_path: &str,
) -> Result<(), Box<dyn Error>> {
    let receipt: DigestEnvelope<BlackboxReceipt> = read_json(receipt_path)?;
    if !receipt.verify_digest()? {
        return Err("black-box receipt digest does not verify".into());
    }
    let evaluation_brief: Value = read_json(brief_path)?;
    let packet = DigestEnvelope::new(BlindPacket {
        schema_version: BLIND_PACKET_V1.into(),
        assignment_ref: assignment_ref.into(),
        candidate_alias: candidate_alias.into(),
        evaluation_brief,
        transcript: receipt
            .payload
            .transcript
            .iter()
            .map(|turn| BlindTranscriptTurn {
                role: turn.role.clone(),
                message: turn.message.clone(),
            })
            .collect(),
        telemetry: receipt.payload.telemetry.clone(),
        deterministic_defects: receipt.payload.deterministic_defects.clone(),
    })?;
    write_json(output_path, &packet)
}

fn verify_receipt(receipt_path: &str) -> Result<(), Box<dyn Error>> {
    let receipt: DigestEnvelope<BlackboxReceipt> = read_json(receipt_path)?;
    if receipt.payload.schema_version != BLACKBOX_RECEIPT_V1 || !receipt.verify_digest()? {
        return Err("black-box receipt is invalid".into());
    }
    for exchange in &receipt.payload.exchanges {
        if exchange.request_digest != sha256_json(&exchange.request)?
            || exchange.response_digest != sha256_json(&exchange.outcome)?
        {
            return Err(format!("exchange {} digest is invalid", exchange.sequence).into());
        }
        if let Some(delivery) = &exchange.delivery
            && exchange.outcome.markdown().map(sha256_text).as_deref()
                != Some(delivery.payload_digest.as_str())
        {
            return Err(
                format!("exchange {} delivery digest is invalid", exchange.sequence).into(),
            );
        }
    }
    Ok(())
}

fn terminal(code: &str, detail: impl Into<String>) -> DeterministicDefect {
    DeterministicDefect {
        code: code.into(),
        detail: detail.into(),
        terminal: true,
    }
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn now() -> Result<String, time::error::Format> {
    OffsetDateTime::now_utc().format(&Rfc3339)
}

fn bounded_body(body: &[u8]) -> String {
    String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned()
}

fn bounded_error(error: &dyn Error) -> String {
    error.to_string().chars().take(512).collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json(path: impl AsRef<Path>, value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_alias_does_not_disclose_episode_ref() {
        let alias = opaque_request_ref("private-episode-name", 2);
        assert!(!alias.contains("private-episode-name"));
        assert!(!alias.contains("blackbox"));
        assert!(!alias.contains("eval"));
        assert!(alias.starts_with("slack-request-"));
        assert_eq!(alias, opaque_request_ref("private-episode-name", 2));
    }

    #[test]
    fn exact_candidate_allows_only_instance_change() {
        let first = CandidateRuntimeAttestation {
            schema_version: "status/v2".into(),
            agent_ready: true,
            build_commit_sha: "a".repeat(40),
            build_tree_clean: true,
            runtime_instance_ref: "instance:one".into(),
            model_provider: Some("provider".into()),
            model_id: Some("model".into()),
            model_config_sha256: Some(format!("sha256:{}", "b".repeat(64))),
            session_schema_version: "session/v2".into(),
        };
        let mut restarted = first.clone();
        restarted.runtime_instance_ref = "instance:two".into();
        assert!(same_candidate(&first, &restarted).is_ok());
        restarted.model_id = Some("different".into());
        assert!(same_candidate(&first, &restarted).is_err());
    }

    #[test]
    fn candidate_visible_identifiers_cannot_disclose_the_experiment() {
        for value in [
            "blackbox-request:one",
            "holdout-thread",
            "private-episode-7",
            "grader-actor",
            "candidate-a",
            "eval-thread",
        ] {
            assert!(discloses_evaluation(value), "{value}");
        }
        for value in [
            "writer",
            "slack-request-0123456789abcdef",
            "slack-thread:T01:C01:1710000000.000001",
            "slack-user:U01",
        ] {
            assert!(!discloses_evaluation(value), "{value}");
        }
    }
}
