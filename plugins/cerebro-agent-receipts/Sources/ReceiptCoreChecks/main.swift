import CryptoKit
import Foundation
import ReceiptCore

struct CheckRunner {
  private var failures: [String] = []

  mutating func run() throws {
    do { try checkCommandMinimization() } catch {
      failures.append("command minimization: \(error)")
    }
    do { try checkSignedChain() } catch { failures.append("signed chain: \(error)") }
    do { try checkTamperDetection() } catch { failures.append("tamper detection: \(error)") }
    do { try checkCanaryCorrelation() } catch { failures.append("canary correlation: \(error)") }
    do { try checkProviderBinding() } catch { failures.append("provider binding: \(error)") }
    do { try checkProviderFirstGap() } catch { failures.append("provider-first gap: \(error)") }
    do { try checkOneToOneAllocation() } catch {
      failures.append("one-to-one allocation: \(error)")
    }
    do { try checkImportedBindingIsRejected() } catch {
      failures.append("imported binding rejection: \(error)")
    }
    do { try checkAgentAdapters() } catch { failures.append("agent adapters: \(error)") }
    do { try checkFailedAction() } catch { failures.append("failed action: \(error)") }
    do { try checkProductIsolation() } catch { failures.append("product isolation: \(error)") }

    if failures.isEmpty {
      print("PASS: 11 receipt security checks")
      return
    }
    failures.forEach { FileHandle.standardError.write(Data("FAIL: \($0)\n".utf8)) }
    exit(1)
  }

  private mutating func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { failures.append(message) }
  }

  private mutating func checkCommandMinimization() throws {
    let envelope = HookEnvelope(
      sessionID: "session-1",
      cwd: "/tmp",
      hookEventName: "PreToolUse",
      model: "gpt-test",
      turnID: "turn-1",
      permissionMode: "default",
      toolName: "Bash",
      toolUseID: "call-1",
      toolInput: .object([
        "command": .string("aws ecs register-task-definition --token super-secret")
      ])
    )
    guard let date = ReceiptDate.parser.date(from: "2026-07-15T08:41:04.855Z") else {
      failures.append("test timestamp did not parse")
      return
    }
    let draft = try HookCapture.draft(
      from: envelope,
      capturedAt: date,
      environment: ["CEREBRO_HUMAN_PRINCIPAL": "operator@example.com"]
    )
    expect(draft.actionSummary == "aws ecs register-task-definition", "action summary changed")
    expect(
      !draft.actionSummary.contains("super-secret"), "action summary leaked a command argument")
    expect(draft.inputDigest != nil, "input digest is missing")
  }

  private mutating func checkSignedChain() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    let first = try store.append(draft: draft(id: "first", phase: .attempted), signer: signer)
    let second = try store.append(draft: draft(id: "second", phase: .completed), signer: signer)
    let results = ReceiptVerifier.verify(
      try store.readReceipts(), trustedPublicKeyBase64: signer.publicKeyBase64)
    let firstDigest = try CanonicalJSON.digest(first)
    expect(first.payload.sequence == 1, "first sequence is not one")
    expect(second.payload.sequence == 2, "second sequence is not two")
    expect(results.allSatisfy(\.valid), "valid receipt chain did not verify")
    expect(
      second.payload.previousReceiptDigest == firstDigest,
      "previous digest does not bind the prior receipt")
  }

  private mutating func checkTamperDetection() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    let receipt = try store.append(draft: draft(id: "original", phase: .attempted), signer: signer)
    let original = receipt.payload
    let payload = ExecutionReceiptPayload(
      id: original.id,
      sequence: original.sequence,
      previousReceiptDigest: original.previousReceiptDigest,
      capturedAt: original.capturedAt,
      phase: original.phase,
      localUserClaim: original.localUserClaim,
      localUserClaimSource: original.localUserClaimSource,
      agent: original.agent,
      deviceID: original.deviceID,
      permissionMode: original.permissionMode,
      toolName: original.toolName,
      actionSummary: "different action",
      inputDigest: original.inputDigest,
      resultDigest: original.resultDigest,
      cwd: original.cwd,
      git: original.git
    )
    expect(
      !DeviceKeySigner.verify(ExecutionReceipt(payload: payload, signature: receipt.signature)),
      "tampered receipt signature verified")
  }

  private mutating func checkCanaryCorrelation() throws {
    let lookup = #"""
      {"Events":[{"EventId":"e037b713-9bf8-49d9-b947-b17dc4941ead","EventName":"RegisterTaskDefinition","EventTime":"2026-07-15T08:41:25Z","CloudTrailEvent":"{\"eventID\":\"e037b713-9bf8-49d9-b947-b17dc4941ead\",\"eventName\":\"RegisterTaskDefinition\",\"eventTime\":\"2026-07-15T08:41:25Z\",\"userIdentity\":{\"arn\":\"arn:aws:sts::000000000000:assumed-role/Admin/jonathan\"},\"userAgent\":\"aws-cli/2.x\"}"}]}
      """#
    let events = try CloudTrailImporter.parse(Data(lookup.utf8))
    let action = try signedCanaryAction(actionSummary: "run-cerebro-candidate-canary.sh")
    guard
      let match = ReceiptCorrelator.assess(actions: [action], providerEvents: events).actionMatches[
        action.id]
    else {
      failures.append("canary event did not correlate")
      return
    }
    expect(
      match.level == .candidateCorrelation, "unbound canary event was not classified as a candidate"
    )
    expect(abs((match.deltaSeconds ?? 0) - 20.145) < 0.01, "canary time delta is incorrect")
    expect(match.evidence.contains("user-imported JSON"), "manual import provenance was hidden")
  }

  private mutating func checkProviderBinding() throws {
    let action = try signedCanaryAction(actionSummary: "aws ecs register-task-definition")
    let event = ProviderEvent(
      id: "event-1",
      eventName: "RegisterTaskDefinition",
      eventTime: "2026-07-15T08:41:25.000Z",
      principal: "arn:aws:sts::000000000000:assumed-role/cerebro-agent-executor/action",
      recipientAccountID: "000000000000",
      userAgent: "aws-cli/2.x",
      sourceIPAddress: nil,
      resources: [],
      sourceIdentity: action.id,
      provenance: .authenticatedAWSAPI
    )
    let policy = ProviderBindingPolicy(
      expectedAccountID: "000000000000", expectedAgentRole: "cerebro-agent-executor")
    guard
      let match = ReceiptCorrelator.assess(
        actions: [action], providerEvents: [event], policy: policy
      ).actionMatches[action.id]
    else {
      failures.append("bound provider event did not correlate")
      return
    }
    expect(match.level == .providerBound, "session-bound event was not classified provider-bound")
    expect(
      match.evidence.contains("dedicated agent role"),
      "provider binding did not require the dedicated role")
  }

  private mutating func checkProviderFirstGap() throws {
    let event = ProviderEvent(
      id: "unmatched-event",
      eventName: "PutParameter",
      eventTime: "2026-07-15T08:41:25.000Z",
      principal: "arn:aws:sts::000000000000:assumed-role/Admin/operator",
      recipientAccountID: "000000000000",
      userAgent: "aws-cli/2.x",
      sourceIPAddress: nil,
      resources: [],
      provenance: .authenticatedAWSAPI
    )
    let assessment = ReceiptCorrelator.assess(actions: [], providerEvents: [event])
    expect(
      assessment.unmatchedProviderEvents.map(\.id) == ["unmatched-event"],
      "provider event without a receipt disappeared from the denominator")
  }

  private mutating func checkOneToOneAllocation() throws {
    let first = completedAction(id: "action-1", call: "call-1")
    let second = completedAction(id: "action-2", call: "call-2")
    let event = ProviderEvent(
      id: "one-event",
      eventName: "PutParameter",
      eventTime: "2026-07-15T08:41:25.000Z",
      principal: "arn:aws:sts::000000000000:assumed-role/Admin/operator",
      userAgent: "aws-cli/2.x",
      sourceIPAddress: nil,
      resources: [],
      provenance: .authenticatedAWSAPI
    )
    let assessment = ReceiptCorrelator.assess(actions: [first, second], providerEvents: [event])
    expect(
      assessment.candidateCount == 1, "one provider event was allocated to more than one action")
    expect(assessment.capturedOnlyCount == 1, "the second action did not remain unmatched")
  }

  private mutating func checkImportedBindingIsRejected() throws {
    let action = completedAction(id: "action-spoof", call: "call-spoof")
    let event = ProviderEvent(
      id: "spoof",
      eventName: "PutParameter",
      eventTime: "2026-07-15T08:41:25.000Z",
      principal: "arn:aws:sts::000000000000:assumed-role/cerebro-agent-executor/spoof",
      recipientAccountID: "000000000000",
      userAgent: "aws-cli/2.x",
      sourceIPAddress: nil,
      resources: [],
      sourceIdentity: action.id,
      provenance: .userImported
    )
    let policy = ProviderBindingPolicy(
      expectedAccountID: "000000000000", expectedAgentRole: "cerebro-agent-executor")
    let match = ReceiptCorrelator.assess(actions: [action], providerEvents: [event], policy: policy)
      .actionMatches[action.id]
    expect(match?.level != .providerBound, "user-imported JSON created a provider binding")
  }

  private mutating func checkAgentAdapters() throws {
    let cases: [(AgentProduct, String, String, String, AgentIntegration)] = [
      (
        .codex,
        #"{"session_id":"codex-session","cwd":"/tmp","hook_event_name":"PreToolUse","model":"gpt-test","tool_name":"Bash","tool_use_id":"codex-call","tool_input":{"command":"printf codex"}}"#,
        "codex-session", "Bash", .nativeHook
      ),
      (
        .droid,
        #"{"session_id":"droid-session","cwd":"/tmp","hook_event_name":"PreToolUse","permission_mode":"auto-low","tool_name":"Execute","tool_use_id":"droid-call","tool_input":{"command":"printf droid"}}"#,
        "droid-session", "Execute", .nativeHook
      ),
      (
        .claudeCode,
        #"{"session_id":"claude-session","cwd":"/tmp","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"claude-call","tool_input":{"command":"false"},"tool_response":{"error":"exit 1"}}"#,
        "claude-session", "Bash", .nativeHook
      ),
      (
        .openCode,
        #"{"session_id":"opencode-session","directory":"/tmp","event":"tool.execute.before","tool":"bash","call_id":"opencode-call","args":{"command":"printf opencode"}}"#,
        "opencode-session", "bash", .pluginEvent
      ),
      (
        .cursor,
        #"{"conversation_id":"cursor-session","generation_id":"cursor-turn","cwd":"/tmp","hook_event_name":"beforeShellExecution","command":"printf cursor"}"#,
        "cursor-session", "Shell", .nativeHook
      ),
    ]

    for (product, json, sessionID, toolName, integration) in cases {
      let envelope = try AgentEventNormalizer.normalize(Data(json.utf8), product: product)
      let draft = try HookCapture.draft(from: envelope, product: product)
      expect(envelope.sessionID == sessionID, "\(product.displayName) session was not normalized")
      expect(envelope.toolName == toolName, "\(product.displayName) tool was not normalized")
      expect(draft.agent.product == product.displayName, "\(product.displayName) product was lost")
      expect(
        draft.collector?.integration == integration, "\(product.displayName) integration was lost")
      expect(draft.inputDigest != nil, "\(product.displayName) input digest is missing")
    }
  }

  private mutating func checkFailedAction() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    _ = try store.append(draft: draft(id: "failed-pre", phase: .attempted), signer: signer)
    _ = try store.append(draft: draft(id: "failed-post", phase: .failed), signer: signer)
    let receipts = try store.readReceipts()
    let verification = ReceiptVerifier.verify(
      receipts, trustedPublicKeyBase64: signer.publicKeyBase64)
    let actions = ExecutionActionReducer.reduce(
      receipts: receipts,
      verifications: Dictionary(uniqueKeysWithValues: verification.map { ($0.receiptID, $0) })
    )
    expect(actions.count == 1, "failed tool phases did not reduce to one action")
    expect(actions.first?.state == .failed, "failed tool result was not terminal")
  }

  private mutating func checkProductIsolation() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    for product in ["Codex", "Droid"] {
      for phase in [ReceiptPhase.attempted, .completed] {
        let base = draft(id: "\(product)-\(phase.rawValue)", phase: phase)
        _ = try store.append(
          draft: ReceiptDraft(
            id: base.id,
            capturedAt: base.capturedAt,
            phase: base.phase,
            localUserClaim: base.localUserClaim,
            localUserClaimSource: base.localUserClaimSource,
            agent: AgentIdentity(
              product: product,
              model: base.agent.model,
              sessionID: base.agent.sessionID,
              turnID: base.agent.turnID,
              toolCallID: base.agent.toolCallID
            ),
            permissionMode: base.permissionMode,
            toolName: base.toolName,
            actionSummary: base.actionSummary,
            inputDigest: base.inputDigest,
            resultDigest: base.resultDigest,
            cwd: base.cwd,
            git: base.git
          ),
          signer: signer
        )
      }
    }
    let receipts = try store.readReceipts()
    let verification = ReceiptVerifier.verify(
      receipts, trustedPublicKeyBase64: signer.publicKeyBase64)
    let actions = ExecutionActionReducer.reduce(
      receipts: receipts,
      verifications: Dictionary(uniqueKeysWithValues: verification.map { ($0.receiptID, $0) })
    )
    expect(actions.count == 2, "two products with the same session and call collapsed together")
  }

  private func signedCanaryAction(actionSummary: String) throws -> ExecutionAction {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    let attempted = ReceiptDraft(
      id: "receipt-canary-pre",
      capturedAt: "2026-07-15T08:41:04.855Z",
      phase: .attempted,
      localUserClaim: "jonathan",
      localUserClaimSource: "macos_account",
      agent: AgentIdentity(
        product: "Codex",
        model: "gpt-test",
        sessionID: "019f6406-2bc6-7b72-93ec-ee87221d075d",
        turnID: "019f648d-ded2-7121-8326-c57fa25561ef",
        toolCallID: "call_JuSsa99BJVt1AvH0Fq4wr2Fe"
      ),
      permissionMode: "default",
      toolName: "Bash",
      actionSummary: actionSummary,
      inputDigest: "sha256:input",
      resultDigest: nil,
      cwd: "/redacted",
      git: GitContext(repositoryRoot: "/redacted", commit: "0000000", branch: "test")
    )
    _ = try store.append(draft: attempted, signer: signer)
    _ = try store.append(
      draft: ReceiptDraft(
        id: "receipt-canary-post",
        capturedAt: "2026-07-15T08:41:30.000Z",
        phase: .completed,
        localUserClaim: "jonathan",
        localUserClaimSource: "macos_account",
        agent: AgentIdentity(
          product: "Codex",
          model: "gpt-test",
          sessionID: "019f6406-2bc6-7b72-93ec-ee87221d075d",
          turnID: "019f648d-ded2-7121-8326-c57fa25561ef",
          toolCallID: "call_JuSsa99BJVt1AvH0Fq4wr2Fe"
        ),
        permissionMode: "default",
        toolName: "Bash",
        actionSummary: actionSummary,
        inputDigest: "sha256:input",
        resultDigest: "sha256:result",
        cwd: "/redacted",
        git: GitContext(repositoryRoot: "/redacted", commit: "0000000", branch: "test")
      ),
      signer: signer
    )
    let receipts = try store.readReceipts()
    let verification = ReceiptVerifier.verify(
      receipts, trustedPublicKeyBase64: signer.publicKeyBase64)
    let verificationMap = Dictionary(uniqueKeysWithValues: verification.map { ($0.receiptID, $0) })
    guard
      let action = ExecutionActionReducer.reduce(receipts: receipts, verifications: verificationMap)
        .first
    else {
      throw CheckError.missingAction
    }
    return action
  }

  private func draft(id: String, phase: ReceiptPhase) -> ReceiptDraft {
    ReceiptDraft(
      id: id,
      capturedAt: ReceiptDate.string(from: Date()),
      phase: phase,
      localUserClaim: "operator@example.com",
      localUserClaimSource: "macos_account",
      agent: AgentIdentity(
        product: "Codex", model: "gpt-test", sessionID: "session", turnID: "turn",
        toolCallID: "call"),
      permissionMode: "default",
      toolName: "Bash",
      actionSummary: "aws sts",
      inputDigest: "sha256:input",
      resultDigest: phase == .completed ? "sha256:result" : nil,
      cwd: "/tmp",
      git: GitContext(repositoryRoot: nil, commit: nil, branch: nil)
    )
  }

  private func completedAction(id: String, call: String) -> ExecutionAction {
    ExecutionAction(
      id: id,
      sessionID: "session",
      turnID: "turn",
      toolCallID: call,
      toolName: "Bash",
      actionSummary: "aws ssm put-parameter",
      inputDigest: "input-\(call)",
      resultDigest: "result-\(call)",
      localUserClaim: "operator",
      localUserClaimSource: "macos_account",
      model: "gpt-test",
      permissionMode: "default",
      state: .completed,
      authorizationEvidence: .notObserved,
      startedAt: ReceiptDate.parser.date(from: "2026-07-15T08:41:04.855Z"),
      completedAt: ReceiptDate.parser.date(from: "2026-07-15T08:41:30.000Z"),
      receiptIDs: ["pre-\(call)", "post-\(call)"],
      integrityValid: true,
      repositoryRoot: "/redacted",
      commit: "0000000"
    )
  }

  private func temporaryStore() throws -> (ReceiptStore, DeviceKeySigner, () -> Void) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let signer = try DeviceKeySigner(rawKey: P256.Signing.PrivateKey().rawRepresentation)
    return (
      ReceiptStore(directory: directory), signer,
      { try? FileManager.default.removeItem(at: directory) }
    )
  }
}

private enum CheckError: Error {
  case missingAction
}

do {
  var runner = CheckRunner()
  try runner.run()
} catch {
  FileHandle.standardError.write(Data("FAIL: \(error.localizedDescription)\n".utf8))
  exit(1)
}
