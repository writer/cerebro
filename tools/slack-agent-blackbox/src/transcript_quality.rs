//! Provider-blind deterministic checks for multi-turn transcript defects.
//!
//! These checks intentionally cover only observable anti-patterns. Independent
//! graders remain responsible for semantic task completion and judgment.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};

use cerebro_slack_agent_eval_wire::{CONTENT_BLIND_PACKET_V2, ContentBlindPacketV2, sha256_json};
use serde::{Deserialize, Serialize};

const TRANSCRIPT_DEFECT_LINT_REPORT_V1: &str = "slack-agent-transcript-defect-lint-report/v1";
const MIN_OPERATOR_TURNS: usize = 3;
const MIN_ASSISTANT_TURNS: usize = 3;

const CORRECTION_MARKERS: &[&str] = &[
    "actually,",
    "correction:",
    "i said ",
    "i meant ",
    "not the ",
    "that's incorrect",
    "that's not right",
    "that's wrong",
    "that is incorrect",
    "that is not right",
    "that is wrong",
    "the old route",
    "used the old",
    "you are wrong",
    "you're wrong",
];

const CORRECTION_ACKNOWLEDGMENTS: &[&str] = &[
    "agreed",
    "correct",
    "i had that wrong",
    "i was wrong",
    "that changes",
    "that correction",
    "which means",
    "you are right",
    "you're right",
];

const STRONG_FALLBACK_MARKERS: &[&str] = &[
    "as an ai",
    "i can only help with",
    "i cannot assist with that",
    "i can't assist with that",
    "i did not evaluate the requested condition",
    "i did not execute the requested action",
    "i do not have enough information to help",
    "i'm unable to help with that",
    "i am unable to help with that",
    "no current authoritative observation was obtained",
];

const GENERIC_FALLBACK_MARKERS: &[&str] = &[
    "i cannot help",
    "i can't help",
    "i do not have access to",
    "i don't have access to",
    "i do not have enough information",
    "i don't have enough information",
    "let me know what you'd like to",
    "please provide more information",
];

const META_LABELS: &[&str] = &[
    "confidence:",
    "coverage gap:",
    "current state:",
    "decision:",
    "evidence:",
    "next step:",
    "recommendation:",
    "status:",
    "what changed:",
];

const NOVELTY_MARKERS: &[&str] = &[
    "a new implication",
    "another implication",
    "new insight",
    "one insight",
    "one thing you did not ask",
    "one thing you didn't ask",
    "you may be missing",
    "you might be missing",
];

const STOP_WORDS: &[&str] = &[
    "about", "after", "again", "also", "because", "before", "being", "could", "exactly", "from",
    "give", "going", "have", "into", "just", "keep", "later", "means", "need", "only", "please",
    "should", "that", "their", "then", "there", "these", "they", "thing", "this", "those",
    "through", "what", "when", "where", "which", "while", "with", "would", "your", "you're",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptQualitySeverity {
    Advisory,
    Hard,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptQualityFinding {
    pub code: String,
    pub severity: TranscriptQualitySeverity,
    /// Zero-based index in the content-blind transcript.
    pub turn_index: Option<usize>,
    /// Earlier transcript turn used by the deterministic comparison, if any.
    pub related_turn_index: Option<usize>,
    /// Digest of the candidate-visible turn, never runtime or model identity.
    pub turn_digest: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptDefectMetrics {
    pub operator_turn_count: usize,
    pub assistant_turn_count: usize,
    pub hard_defect_count: usize,
    pub advisory_finding_count: usize,
    /// Diagnostic weight only. This is not a semantic quality score.
    pub penalty_points: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptQualityReport {
    pub schema_version: String,
    /// Binds the report to the exact sealed packet, including its opaque aliases.
    pub packet_digest: String,
    /// Stable across assignment/candidate alias randomization.
    pub identity_blind_content_digest: String,
    pub gate_scope: String,
    pub semantic_grade_required: bool,
    pub metrics: TranscriptDefectMetrics,
    pub findings: Vec<TranscriptQualityFinding>,
    pub passed_deterministic_lint: bool,
}

#[derive(Serialize)]
struct IdentityBlindContent<'a> {
    task: &'a cerebro_slack_agent_eval_wire::BlindTaskBriefV2,
    transcript: &'a [cerebro_slack_agent_eval_wire::BlindTranscriptTurn],
}

#[derive(Clone, Debug)]
struct IndexedAssistantTurn<'a> {
    index: usize,
    message: &'a str,
    normalized: String,
    tokens: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Penalties {
    points: u16,
}

pub fn score_file(
    packet_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<TranscriptQualityReport, Box<dyn Error>> {
    let packet: ContentBlindPacketV2 = serde_json::from_slice(&fs::read(packet_path)?)?;
    let report = score(&packet)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(output_path, bytes)?;
    if !report.passed_deterministic_lint {
        return Err("content-blind transcript failed the deterministic defect lint".into());
    }
    Ok(report)
}

pub fn score(packet: &ContentBlindPacketV2) -> Result<TranscriptQualityReport, serde_json::Error> {
    validate_packet(packet)?;
    let packet_digest = sha256_json(packet)?;
    let identity_blind_content_digest = sha256_json(&IdentityBlindContent {
        task: &packet.task,
        transcript: &packet.transcript,
    })?;
    let assistants = packet
        .transcript
        .iter()
        .enumerate()
        .filter(|(_, turn)| turn.role.eq_ignore_ascii_case("assistant"))
        .map(|(index, turn)| IndexedAssistantTurn {
            index,
            message: &turn.message,
            normalized: normalize(&turn.message),
            tokens: tokens(&turn.message),
        })
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut penalties = Penalties::default();

    detect_minimum_trajectory(packet, &assistants, &mut findings, &mut penalties);

    detect_canned_fallbacks(&assistants, &mut findings, &mut penalties);
    detect_meta_labels(&assistants, &mut findings, &mut penalties);
    detect_later_turn_repetition(&assistants, &mut findings, &mut penalties);
    detect_correction_retention(packet, &assistants, &mut findings, &mut penalties);
    detect_false_novelty(&assistants, &mut findings, &mut penalties);

    findings.sort_by(|left, right| {
        left.turn_index
            .cmp(&right.turn_index)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.related_turn_index.cmp(&right.related_turn_index))
    });
    findings.dedup_by(|left, right| {
        left.code == right.code
            && left.turn_index == right.turn_index
            && left.related_turn_index == right.related_turn_index
    });

    let hard_defect_count = findings
        .iter()
        .filter(|finding| finding.severity == TranscriptQualitySeverity::Hard)
        .count();
    let advisory_finding_count = findings.len().saturating_sub(hard_defect_count);
    let operator_turn_count = packet
        .transcript
        .iter()
        .filter(|turn| is_operator_role(&turn.role))
        .count();

    Ok(TranscriptQualityReport {
        schema_version: TRANSCRIPT_DEFECT_LINT_REPORT_V1.into(),
        packet_digest,
        identity_blind_content_digest,
        gate_scope: "observable_transcript_defects_only".into(),
        semantic_grade_required: true,
        metrics: TranscriptDefectMetrics {
            operator_turn_count,
            assistant_turn_count: assistants.len(),
            hard_defect_count,
            advisory_finding_count,
            penalty_points: penalties.points,
        },
        findings,
        passed_deterministic_lint: hard_defect_count == 0,
    })
}

fn validate_packet(packet: &ContentBlindPacketV2) -> Result<(), serde_json::Error> {
    let valid_roles_and_messages = packet.transcript.iter().all(|turn| {
        (is_operator_role(&turn.role) || turn.role.eq_ignore_ascii_case("assistant"))
            && !turn.message.trim().is_empty()
    });
    if packet.schema_version != CONTENT_BLIND_PACKET_V2
        || packet.assignment_alias.trim().is_empty()
        || packet.candidate_alias.trim().is_empty()
        || packet.task.operator_request.trim().is_empty()
        || packet.task.success_definition.trim().is_empty()
        || !valid_roles_and_messages
    {
        return Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "content-blind transcript packet is incomplete or unsupported",
        )));
    }
    Ok(())
}

pub fn execution_defects(
    transcript: &[cerebro_slack_agent_eval_wire::TranscriptTurn],
) -> Result<Vec<cerebro_slack_agent_eval_wire::DeterministicDefect>, serde_json::Error> {
    let packet = ContentBlindPacketV2 {
        schema_version: CONTENT_BLIND_PACKET_V2.into(),
        assignment_alias: "execution-bound-assignment".into(),
        candidate_alias: "execution-bound-candidate".into(),
        task: cerebro_slack_agent_eval_wire::BlindTaskBriefV2 {
            operator_request: "Sealed multi-turn episode".into(),
            success_definition: "No deterministic transcript defect".into(),
        },
        transcript: transcript
            .iter()
            .map(|turn| cerebro_slack_agent_eval_wire::BlindTranscriptTurn {
                role: turn.role.clone(),
                message: turn.message.clone(),
            })
            .collect(),
    };
    Ok(score(&packet)?
        .findings
        .into_iter()
        .filter(|finding| finding.severity == TranscriptQualitySeverity::Hard)
        .map(
            |finding| cerebro_slack_agent_eval_wire::DeterministicDefect {
                code: format!("transcript_{}", finding.code),
                detail: finding.detail,
                terminal: true,
            },
        )
        .collect())
}

fn detect_minimum_trajectory(
    packet: &ContentBlindPacketV2,
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    let operator_turn_count = packet
        .transcript
        .iter()
        .filter(|turn| is_operator_role(&turn.role))
        .count();
    if operator_turn_count < MIN_OPERATOR_TURNS || assistants.len() < MIN_ASSISTANT_TURNS {
        findings.push(TranscriptQualityFinding {
            code: "insufficient_multi_turn_trajectory".into(),
            severity: TranscriptQualitySeverity::Hard,
            turn_index: None,
            related_turn_index: None,
            turn_digest: cerebro_slack_agent_eval_wire::sha256_text("insufficient-trajectory"),
            detail: format!(
                "The transcript contains {operator_turn_count} operator and {} assistant turns; the deterministic gate requires at least {MIN_OPERATOR_TURNS} of each.",
                assistants.len()
            ),
        });
        penalties.points = penalties.points.saturating_add(100);
    }
}

fn detect_canned_fallbacks(
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    for turn in assistants {
        let strong_count = marker_count(&turn.normalized, STRONG_FALLBACK_MARKERS);
        let generic_count = marker_count(&turn.normalized, GENERIC_FALLBACK_MARKERS);
        if strong_count > 0 || generic_count >= 2 || looks_like_non_answer_fallback(turn) {
            findings.push(finding(
                "canned_fallback_or_refusal",
                TranscriptQualitySeverity::Hard,
                turn,
                None,
                "The reply matched a generic capability refusal or no-observation fallback instead of advancing the thread.",
            ));
            penalties.points = penalties.points.saturating_add(50);
        }
    }
}

fn detect_meta_labels(
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    for turn in assistants {
        let labels = line_prefix_marker_count(turn.message, META_LABELS)
            .max(short_colon_heading_count(turn.message));
        let has_coverage_gap = turn.normalized.starts_with("coverage gap:")
            || turn.normalized.contains("\ncoverage gap:");
        if has_coverage_gap || labels >= 2 {
            findings.push(finding(
                "canned_meta_labels",
                TranscriptQualitySeverity::Advisory,
                turn,
                None,
                "The reply used canned status labels instead of a direct conversational answer.",
            ));
            penalties.points = penalties.points.saturating_add(15);
        }
    }
}

fn detect_later_turn_repetition(
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    for (position, turn) in assistants.iter().enumerate().skip(1) {
        let best = assistants[..position]
            .iter()
            .map(|previous| {
                (
                    previous,
                    similarity_basis_points(&turn.tokens, &previous.tokens),
                )
            })
            .max_by_key(|(_, similarity)| *similarity);
        let Some((previous, similarity)) = best else {
            continue;
        };
        if turn.tokens.len() >= 10 && previous.tokens.len() >= 10 && similarity >= 7_200 {
            findings.push(finding(
                "later_turn_repetition",
                TranscriptQualitySeverity::Hard,
                turn,
                Some(previous.index),
                "A later reply substantially repeated an earlier assistant turn without enough new content.",
            ));
            penalties.points = penalties.points.saturating_add(35);
        }
    }
}

fn detect_correction_retention(
    packet: &ContentBlindPacketV2,
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    let assistant_by_index = assistants
        .iter()
        .map(|turn| (turn.index, turn))
        .collect::<BTreeMap<_, _>>();
    for (index, operator_turn) in packet.transcript.iter().enumerate() {
        if !operator_turn.role.eq_ignore_ascii_case("operator")
            && !operator_turn.role.eq_ignore_ascii_case("user")
        {
            continue;
        }
        let normalized = normalize(&operator_turn.message);
        if !CORRECTION_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
        {
            continue;
        }
        let Some(next_assistant) = packet
            .transcript
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, turn)| turn.role.eq_ignore_ascii_case("assistant"))
            .and_then(|(turn_index, _)| assistant_by_index.get(&turn_index).copied())
        else {
            continue;
        };
        let anchors = correction_anchors(&operator_turn.message);
        let response_tokens = next_assistant
            .tokens
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let shared_anchors = anchors
            .iter()
            .filter(|anchor| response_tokens.contains(anchor.as_str()))
            .count();
        let acknowledged = CORRECTION_ACKNOWLEDGMENTS
            .iter()
            .any(|marker| next_assistant.normalized.contains(marker));
        let required_anchors = anchors.len().min(2);
        let repeated_pre_correction_answer = assistants
            .iter()
            .rev()
            .find(|turn| turn.index < index)
            .is_some_and(|previous| {
                similarity_basis_points(&previous.tokens, &next_assistant.tokens) >= 6_800
            });
        if repeated_pre_correction_answer
            || (!acknowledged && required_anchors > 0 && shared_anchors < required_anchors)
        {
            findings.push(finding(
                "correction_not_retained",
                TranscriptQualitySeverity::Hard,
                next_assistant,
                Some(index),
                "The first reply after an explicit correction neither carried its distinctive terms forward nor revised the prior answer.",
            ));
            penalties.points = penalties.points.saturating_add(45);
        }
    }
}

fn detect_false_novelty(
    assistants: &[IndexedAssistantTurn<'_>],
    findings: &mut Vec<TranscriptQualityFinding>,
    penalties: &mut Penalties,
) {
    for (position, turn) in assistants.iter().enumerate().skip(1) {
        let Some(fragment) = novelty_fragment(&turn.normalized) else {
            continue;
        };
        let fragment_tokens = tokens(fragment);
        if fragment_tokens.len() < 5 {
            continue;
        }
        let best = assistants[..position]
            .iter()
            .map(|previous| {
                (
                    previous,
                    directional_overlap_basis_points(&fragment_tokens, &previous.tokens),
                )
            })
            .max_by_key(|(_, overlap)| *overlap);
        let Some((previous, overlap)) = best else {
            continue;
        };
        if overlap >= 7_000 {
            findings.push(finding(
                "novelty_claim_repeats_prior_content",
                TranscriptQualitySeverity::Hard,
                turn,
                Some(previous.index),
                "Content presented as a new insight substantially repeated an earlier assistant turn.",
            ));
            penalties.points = penalties.points.saturating_add(40);
        }
    }
}

fn finding(
    code: &str,
    severity: TranscriptQualitySeverity,
    turn: &IndexedAssistantTurn<'_>,
    related_turn_index: Option<usize>,
    detail: &str,
) -> TranscriptQualityFinding {
    TranscriptQualityFinding {
        code: code.into(),
        severity,
        turn_index: Some(turn.index),
        related_turn_index,
        turn_digest: cerebro_slack_agent_eval_wire::sha256_text(turn.message),
        detail: detail.into(),
    }
}

fn is_operator_role(role: &str) -> bool {
    role.eq_ignore_ascii_case("operator") || role.eq_ignore_ascii_case("user")
}

fn looks_like_non_answer_fallback(turn: &IndexedAssistantTurn<'_>) -> bool {
    if turn.tokens.len() > 70 {
        return false;
    }
    let vocabulary = turn
        .tokens
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let contains_any = |words: &[&str]| words.iter().any(|word| vocabulary.contains(word));
    let missing_evidence = contains_any(&[
        "lacked",
        "missing",
        "no",
        "nothing",
        "unable",
        "unavailable",
        "without",
    ]) && contains_any(&[
        "access",
        "authoritative",
        "data",
        "evidence",
        "information",
        "observation",
        "source",
    ]);
    let did_not_answer = contains_any(&[
        "assess",
        "assessed",
        "answer",
        "answered",
        "evaluate",
        "evaluated",
        "execute",
        "executed",
        "unevaluated",
    ]);
    let concrete_next_action = contains_any(&[
        "check", "compare", "fetch", "inspect", "open", "query", "read", "record", "run", "send",
        "test", "verify",
    ]);
    missing_evidence && did_not_answer && !concrete_next_action
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '\'')
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn correction_anchors(value: &str) -> BTreeSet<String> {
    tokens(value)
        .into_iter()
        .filter(|token| token.len() >= 3)
        .filter(|token| !STOP_WORDS.contains(&token.as_str()))
        .filter(|token| {
            ![
                "actually",
                "correction",
                "incorrect",
                "right",
                "said",
                "wrong",
            ]
            .contains(&token.as_str())
        })
        .collect()
}

fn marker_count(value: &str, markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|marker| value.contains(**marker))
        .count()
}

fn line_prefix_marker_count(value: &str, markers: &[&str]) -> usize {
    value
        .lines()
        .map(|line| {
            line.trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, '#' | '*' | '-' | '_')
            })
            .to_ascii_lowercase()
        })
        .filter(|line| markers.iter().any(|marker| line.starts_with(marker)))
        .count()
}

fn short_colon_heading_count(value: &str) -> usize {
    value
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, '#' | '*' | '-' | '_')
            });
            let (prefix, _) = trimmed.split_once(':')?;
            let word_count = prefix.split_whitespace().count();
            (word_count > 0
                && word_count <= 3
                && prefix
                    .chars()
                    .all(|character| character.is_ascii_alphabetic() || character.is_whitespace()))
            .then_some(())
        })
        .count()
}

fn novelty_fragment(value: &str) -> Option<&str> {
    NOVELTY_MARKERS
        .iter()
        .filter_map(|marker| value.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)
        .map(|(index, marker)| {
            value[index + marker.len()..].trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, ':' | '-' | ',' | '.')
            })
        })
}

fn similarity_basis_points(left: &[String], right: &[String]) -> u16 {
    let containment = directional_overlap_basis_points(left, right)
        .max(directional_overlap_basis_points(right, left));
    let left_set = left.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let right_set = right.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let union = left_set.union(&right_set).count();
    let jaccard = if union == 0 {
        0
    } else {
        ((left_set.intersection(&right_set).count() * 10_000) / union) as u16
    };
    ((u32::from(containment) + u32::from(jaccard)) / 2) as u16
}

fn directional_overlap_basis_points(needle: &[String], haystack: &[String]) -> u16 {
    if needle.is_empty() {
        return 0;
    }
    let mut available =
        haystack
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, token| {
                *counts.entry(token.as_str()).or_default() += 1;
                counts
            });
    let matched = needle.iter().fold(0_usize, |matched, token| {
        let Some(count) = available.get_mut(token.as_str()) else {
            return matched;
        };
        if *count == 0 {
            matched
        } else {
            *count -= 1;
            matched + 1
        }
    });
    ((matched * 10_000) / needle.len()) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_slack_agent_eval_wire::{BlindTaskBriefV2, BlindTranscriptTurn};

    fn packet(turns: &[(&str, &str)]) -> ContentBlindPacketV2 {
        ContentBlindPacketV2 {
            schema_version: CONTENT_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment-opaque-17".into(),
            candidate_alias: "candidate-opaque-b".into(),
            task: BlindTaskBriefV2 {
                operator_request: "Diagnose the rollout and decide the next check.".into(),
                success_definition: "Retain corrections and provide one useful implication.".into(),
            },
            transcript: turns
                .iter()
                .map(|(role, message)| BlindTranscriptTurn {
                    role: (*role).into(),
                    message: (*message).into(),
                })
                .collect(),
        }
    }

    fn codes(report: &TranscriptQualityReport) -> BTreeSet<&str> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect()
    }

    #[test]
    fn excellent_correction_trajectory_passes() {
        let report = score(&packet(&[
            ("operator", "The dashboard is green. What changed and what should we test?"),
            (
                "assistant",
                "The green dashboard shows the service is up, but it does not prove the new sync route served a request. I would send one request that can only succeed through that route and record the route identifier in the receipt.",
            ),
            (
                "operator",
                "Actually, the successful run used the old route, not the new route. Update your conclusion.",
            ),
            (
                "assistant",
                "You're right; that changes the conclusion. The old route is verified, while the new route is still untested. Run a request with fallback disabled and require the receipt to name the new route before promoting it.",
            ),
            (
                "operator",
                "So what does that change exactly? Give me the decision and one implication.",
            ),
            (
                "assistant",
                "Hold the rollout. The next check is a fallback-disabled request whose receipt names the new route. If route identity is not part of the release evidence, a healthy old path can keep masking a broken replacement.",
            ),
        ]))
        .unwrap();
        assert!(report.passed_deterministic_lint, "{:?}", report.findings);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn canned_no_observation_fallback_is_a_hard_failure() {
        let report = score(&packet(&[
            ("operator", "Are you better now?"),
            (
                "assistant",
                "Coverage gap: No current authoritative observation was obtained. I did not evaluate the requested condition, execute an action, or record a new follow-up.",
            ),
        ]))
        .unwrap();
        assert!(!report.passed_deterministic_lint);
        assert!(codes(&report).contains("canned_fallback_or_refusal"));
        assert!(codes(&report).contains("canned_meta_labels"));
    }

    #[test]
    fn later_turn_repetition_is_a_hard_failure() {
        let repeated = "The old route is verified but the new route remains untested. Run one fallback-disabled request and require its receipt to name the new route before promotion.";
        let report = score(&packet(&[
            ("operator", "What changed?"),
            ("assistant", repeated),
            ("operator", "Keep going. What is the decision?"),
            ("assistant", repeated),
        ]))
        .unwrap();
        assert!(!report.passed_deterministic_lint);
        assert!(codes(&report).contains("later_turn_repetition"));
    }

    #[test]
    fn ignored_correction_is_a_hard_failure() {
        let prior = "The new route is verified by the successful request, so promotion can continue after the ordinary availability check.";
        let report = score(&packet(&[
            ("operator", "What does the successful request prove?"),
            ("assistant", prior),
            (
                "operator",
                "Actually, that request used the old route, not the new route.",
            ),
            ("assistant", prior),
        ]))
        .unwrap();
        assert!(!report.passed_deterministic_lint);
        assert!(codes(&report).contains("correction_not_retained"));
    }

    #[test]
    fn claimed_novelty_must_not_repeat_prior_content() {
        let report = score(&packet(&[
            ("operator", "What should we do next?"),
            (
                "assistant",
                "A fallback-disabled request must name the new route in its receipt before promotion can continue.",
            ),
            ("operator", "Add one insight I may be missing."),
            (
                "assistant",
                "One insight: a fallback-disabled request must name the new route in its receipt before promotion can continue.",
            ),
        ]))
        .unwrap();
        assert!(!report.passed_deterministic_lint);
        assert!(codes(&report).contains("novelty_claim_repeats_prior_content"));
    }

    #[test]
    fn assignment_and_candidate_aliases_cannot_change_the_score() {
        let first = packet(&[
            ("operator", "What changed?"),
            (
                "assistant",
                "The service is healthy, but the replacement route still needs one route-bound request before promotion.",
            ),
        ]);
        let mut second = first.clone();
        second.assignment_alias = "assignment-opus".into();
        second.candidate_alias = "provider-model-name".into();
        let first_report = score(&first).unwrap();
        let second_report = score(&second).unwrap();
        assert_eq!(first_report.metrics, second_report.metrics);
        assert_eq!(first_report.findings, second_report.findings);
        assert_eq!(
            first_report.identity_blind_content_digest,
            second_report.identity_blind_content_digest
        );
        assert_ne!(first_report.packet_digest, second_report.packet_digest);
    }

    #[test]
    fn packet_contract_rejects_model_identity_fields() {
        let mut value = serde_json::to_value(packet(&[(
            "assistant",
            "The next check is a route-bound request.",
        )]))
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("model_id".into(), serde_json::json!("secret-model"));
        assert!(serde_json::from_value::<ContentBlindPacketV2>(value).is_err());
    }

    #[test]
    fn bounded_evidence_caveat_is_not_a_refusal() {
        let report = score(&packet(&[
            ("operator", "Can we promote this?"),
            (
                "assistant",
                "I do not have access to the deployment receipt yet, so I would not promote it. The concrete next check is to fetch that receipt and verify it names the new route.",
            ),
            ("operator", "Keep going."),
            (
                "assistant",
                "I would compare the named route with the release target and stop if they differ. That preserves the current evidence without treating availability as route verification.",
            ),
            ("operator", "What is the final decision?"),
            (
                "assistant",
                "Do not promote until the deployment receipt and one fresh request both identify the replacement route. If either is absent, the exact blocker is route identity, not service health.",
            ),
        ]))
        .unwrap();
        assert!(report.passed_deterministic_lint, "{:?}", report.findings);
        assert!(!codes(&report).contains("canned_fallback_or_refusal"));
    }

    #[test]
    fn empty_and_single_turn_transcripts_fail_closed() {
        for transcript in [
            packet(&[]),
            packet(&[("operator", "Are you better now?")]),
            packet(&[
                ("operator", "Are you better now?"),
                ("assistant", "Yes, everything is fixed."),
            ]),
        ] {
            let report = score(&transcript).unwrap();
            assert!(!report.passed_deterministic_lint);
            assert!(codes(&report).contains("insufficient_multi_turn_trajectory"));
        }
    }

    #[test]
    fn paraphrased_non_answer_fallback_is_detected_without_fixture_text() {
        let report = score(&packet(&[
            ("operator", "What changed?"),
            (
                "assistant",
                "Nothing authoritative was available, so the requested state remained unevaluated.",
            ),
            ("operator", "Try once more."),
            (
                "assistant",
                "No evidence was available and the condition was not assessed.",
            ),
            ("operator", "Give me a decision."),
            (
                "assistant",
                "Without source information, the request cannot be answered.",
            ),
        ]))
        .unwrap();
        assert!(!report.passed_deterministic_lint);
        assert!(codes(&report).contains("canned_fallback_or_refusal"));
    }

    #[test]
    fn fluent_unsupported_text_never_becomes_a_quality_attestation() {
        let report = score(&packet(&[
            ("operator", "Is the route safe?"),
            (
                "assistant",
                "The route is unquestionably safe and every production request now uses it.",
            ),
            ("operator", "How do you know?"),
            (
                "assistant",
                "The architecture guarantees complete coverage across every deployment and connector.",
            ),
            ("operator", "What should I do?"),
            (
                "assistant",
                "Promote immediately because all relevant evidence is already conclusive.",
            ),
        ]))
        .unwrap();
        assert!(report.passed_deterministic_lint);
        assert!(report.semantic_grade_required);
        assert_eq!(report.gate_scope, "observable_transcript_defects_only");
    }

    #[test]
    fn execution_receipt_defects_bind_the_lint_to_promotion_input() {
        let repeated = "The old route is verified but the new route remains untested. Run one fallback-disabled request and require its receipt to name the new route before promotion.";
        let transcript = [
            ("operator", "What changed?"),
            ("assistant", repeated),
            ("operator", "Keep going."),
            ("assistant", repeated),
            ("operator", "Final decision?"),
            ("assistant", repeated),
        ]
        .into_iter()
        .map(
            |(role, message)| cerebro_slack_agent_eval_wire::TranscriptTurn {
                role: role.into(),
                message: message.into(),
            },
        )
        .collect::<Vec<_>>();
        let defects = execution_defects(&transcript).unwrap();
        assert!(defects.iter().any(|defect| {
            defect.terminal && defect.code == "transcript_later_turn_repetition"
        }));
    }
}
