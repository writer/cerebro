import CryptoKit
import Darwin
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
    do { try checkMultiAgentLifecycle() } catch {
      failures.append("multi-agent lifecycle: \(error)")
    }
    do { try checkFailedAction() } catch { failures.append("failed action: \(error)") }
    do { try checkProductIsolation() } catch { failures.append("product isolation: \(error)") }
    do { try checkAdapterInstaller() } catch { failures.append("adapter installer: \(error)") }
    do { try checkAutomaticReconciliation() } catch {
      failures.append("automatic reconciliation: \(error)")
    }
    do { try checkAdminCapability() } catch { failures.append("admin capability: \(error)") }
    do { try checkFallbackSpool() } catch { failures.append("fallback spool: \(error)") }
    checkFallbackTrustBoundary()
    do { try checkDevelopmentKeyFile() } catch {
      failures.append("development key file: \(error)")
    }
    do { try checkShieldFalseGreen() } catch {
      failures.append("shield false green: \(error)")
    }
    do { try checkDeliveryStaysNotEnrolledWithoutCredential() } catch {
      failures.append("delivery not enrolled: \(error)")
    }
    do { try checkDeliveryAcknowledgementAndRetry() } catch {
      failures.append("delivery acknowledgement: \(error)")
    }
    do { try checkDeliveryEnrollmentAndCredentialBinding() } catch {
      failures.append("delivery enrollment: \(error)")
    }

    if failures.isEmpty {
      print("PASS: 22 receipt security checks")
      return
    }
    for failure in failures {
      FileHandle.standardError.write(Data("FAIL: \(failure)\n".utf8))
    }
    exit(1)
  }

  private mutating func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { failures.append(message) }
  }

  private mutating func checkFallbackTrustBoundary() {
    expect(
      ShieldFallbackPolicy.permitsUserWritableFallback(clientTrust: .validAdHocSignature),
      "development hook could not use the bounded fallback")
    expect(
      !ShieldFallbackPolicy.permitsUserWritableFallback(clientTrust: .verifiedPublisher),
      "managed hook accepted a user-writable fallback")
    expect(
      !ShieldFallbackPolicy.permitsUserWritableFallback(clientTrust: .invalidSignature),
      "invalid hook accepted a user-writable fallback")
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
    guard let date = ReceiptDate.parse("2026-07-15T08:41:04.855Z") else {
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

  private mutating func checkDevelopmentKeyFile() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("development-signing-key")
    let first = try DeviceKeySigner(developmentKeyFileURL: url)
    let second = try DeviceKeySigner(developmentKeyFileURL: url)
    let permissions =
      try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions]
      as? NSNumber
    expect(permissions?.uint16Value == 0o600, "development key permissions are not 0600")
    expect(first.deviceID == second.deviceID, "development key identity changed after reload")
    expect(
      DeviceKeySigner.deviceID(publicKeyBase64: first.publicKeyBase64) == first.deviceID,
      "public key did not reproduce the collector device identity")
    expect(
      DeviceKeySigner.deviceID(publicKeyBase64: "not-a-key") == nil,
      "invalid public key produced a device identity")
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    do {
      _ = try DeviceKeySigner(developmentKeyFileURL: url)
      failures.append("development key accepted group-readable permissions")
    } catch SigningError.keyFilePermissions {
      // Expected.
    }
  }

  private mutating func checkShieldFalseGreen() throws {
    let status = AgentAdapterStatus(
      product: .codex,
      state: .configured,
      executableAvailable: true,
      configurationPath: "/redacted"
    )
    let unreachable = ShieldSnapshotBuilder.build(
      statuses: [status],
      binaryIdentities: [],
      recentValidEventByProduct: [:],
      invalidReceiptCount: 0,
      collectorReachable: false,
      trustBoundary: .development
    )
    expect(unreachable.level == .attention, "unreachable collector retained an active shield")
    expect(
      unreachable.incidents.contains { $0.kind == .backgroundService },
      "unreachable collector did not create a background-service incident")
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    let sessionReceipt = try store.append(
      draft: draft(id: "session-only", phase: .session), signer: signer)
    let original = sessionReceipt.payload
    let corruptedSession = ExecutionReceipt(
      payload: ExecutionReceiptPayload(
        id: original.id,
        sequence: original.sequence,
        previousReceiptDigest: original.previousReceiptDigest,
        capturedAt: original.capturedAt,
        phase: original.phase,
        localUserClaim: original.localUserClaim,
        localUserClaimSource: original.localUserClaimSource,
        agent: original.agent,
        collector: original.collector,
        deviceID: original.deviceID,
        permissionMode: original.permissionMode,
        toolName: original.toolName,
        actionSummary: "corrupted session",
        inputDigest: original.inputDigest,
        resultDigest: original.resultDigest,
        cwd: original.cwd,
        git: original.git
      ),
      signature: sessionReceipt.signature
    )
    let sessionResults = ReceiptVerifier.verify(
      [corruptedSession], trustedPublicKeyBase64: signer.publicKeyBase64)
    expect(
      sessionResults.filter { !$0.valid }.count == 1,
      "corrupted SessionStart receipt was not counted as invalid")
    let invalidSession = ShieldSnapshotBuilder.build(
      statuses: [status],
      binaryIdentities: [],
      recentValidEventByProduct: [:],
      invalidReceiptCount: sessionResults.filter { !$0.valid }.count,
      trustBoundary: .development
    )
    expect(invalidSession.level == .attention, "invalid non-action receipt retained active shield")
    expect(
      invalidSession.incidents.contains { $0.kind == .receiptIntegrity },
      "invalid non-action receipt did not create an integrity incident")

    let configuration = ManagedShieldConfiguration(
      organizationPublicKeyBase64: "public-key",
      expectedTeamIdentifier: "WRITERTEAM",
      expectedSigningIdentifier: "com.writer.cerebro.agent-receipts",
      capabilityURL: URL(fileURLWithPath: "/managed/capability.json"),
      autoRepair: true
    )
    let approved = AgentBinaryIdentity(
      product: .codex,
      path: "/Applications/Cerebro Shield.app",
      trust: .verifiedPublisher,
      signingIdentifier: "com.writer.cerebro.agent-receipts",
      teamIdentifier: "WRITERTEAM",
      cdHash: nil,
      contentDigest: nil,
      modifiedAt: nil
    )
    expect(configuration.accepts(applicationIdentity: approved), "approved publisher was rejected")
    let wrongPublisher = AgentBinaryIdentity(
      product: .codex,
      path: approved.path,
      trust: .verifiedPublisher,
      signingIdentifier: approved.signingIdentifier,
      teamIdentifier: "OTHERTEAM",
      cdHash: nil,
      contentDigest: nil,
      modifiedAt: nil
    )
    expect(
      !configuration.accepts(applicationIdentity: wrongPublisher),
      "another valid publisher was accepted as organization managed")
    let wrongSigningIdentifier = AgentBinaryIdentity(
      product: .codex,
      path: approved.path,
      trust: .verifiedPublisher,
      signingIdentifier: "com.writer.another-app",
      teamIdentifier: approved.teamIdentifier,
      cdHash: nil,
      contentDigest: nil,
      modifiedAt: nil
    )
    expect(
      !configuration.accepts(applicationIdentity: wrongSigningIdentifier),
      "another signing identifier was accepted as organization managed")
    let adHocBuild = AgentBinaryIdentity(
      product: .codex,
      path: approved.path,
      trust: .validAdHocSignature,
      signingIdentifier: approved.signingIdentifier,
      teamIdentifier: approved.teamIdentifier,
      cdHash: nil,
      contentDigest: nil,
      modifiedAt: nil
    )
    expect(
      !configuration.accepts(applicationIdentity: adHocBuild),
      "an ad-hoc build was accepted as organization managed")
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
    let lookupWithoutNested = #"""
      {"Events":[{"EventId":"lookup-only","EventName":"PutParameter","EventTime":"2026-07-15T08:41:25Z","Username":"operator"}]}
      """#
    let lookupEvents = try CloudTrailImporter.parse(Data(lookupWithoutNested.utf8))
    expect(lookupEvents.first?.id == "lookup-only", "lookup event without nested JSON did not parse")
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
    let duplicateAssessment = ReceiptCorrelator.assess(actions: [], providerEvents: [event, event])
    expect(
      duplicateAssessment.unmatchedProviderEvents.count == 2,
      "duplicate provider event IDs were not preserved")
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

    let (fallbackStore, fallbackSigner, fallbackCleanup) = try temporaryStore()
    defer { fallbackCleanup() }
    _ = try fallbackStore.append(
      draft: draft(id: "fallback-pre", phase: .attempted, toolCallID: nil, inputDigest: nil),
      signer: fallbackSigner)
    _ = try fallbackStore.append(
      draft: draft(id: "fallback-post", phase: .completed, toolCallID: nil, inputDigest: nil),
      signer: fallbackSigner)
    let fallbackReceipts = try fallbackStore.readReceipts()
    let fallbackVerification = ReceiptVerifier.verify(
      fallbackReceipts, trustedPublicKeyBase64: fallbackSigner.publicKeyBase64)
    let fallbackActions = ExecutionActionReducer.reduce(
      receipts: fallbackReceipts,
      verifications: Dictionary(
        uniqueKeysWithValues: fallbackVerification.map { ($0.receiptID, $0) }))
    expect(fallbackActions.count == 1, "receipts without call ID or input digest did not group")
    expect(fallbackActions.first?.state == .completed, "fallback grouped action did not complete")

    let (approvalStore, approvalSigner, approvalCleanup) = try temporaryStore()
    defer { approvalCleanup() }
    _ = try approvalStore.append(
      draft: draft(id: "approval", phase: .approvalRequested, toolCallID: "call-1"),
      signer: approvalSigner)
    _ = try approvalStore.append(
      draft: draft(id: "attempted", phase: .attempted, toolCallID: "call-2"),
      signer: approvalSigner)
    let approvalReceipts = try approvalStore.readReceipts()
    let approvalVerification = ReceiptVerifier.verify(
      approvalReceipts, trustedPublicKeyBase64: approvalSigner.publicKeyBase64)
    let approvalActions = ExecutionActionReducer.reduce(
      receipts: approvalReceipts,
      verifications: Dictionary(
        uniqueKeysWithValues: approvalVerification.map { ($0.receiptID, $0) }))
    expect(
      approvalActions.first?.authorizationEvidence == .notObserved,
      "approval from another tool call authorized the attempted action")
  }

  private mutating func checkMultiAgentLifecycle() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    let cases: [(AgentProduct, String, String)] = [
      (
        .codex,
        #"{"session_id":"canary-codex","turn_id":"turn-1","cwd":"/tmp","hook_event_name":"PreToolUse","model":"canary","tool_name":"Bash","tool_use_id":"call-1","tool_input":{"command":"printf codex"}}"#,
        #"{"session_id":"canary-codex","turn_id":"turn-1","cwd":"/tmp","hook_event_name":"PostToolUse","model":"canary","tool_name":"Bash","tool_use_id":"call-1","tool_input":{"command":"printf codex"},"tool_response":{"exit_code":0}}"#
      ),
      (
        .droid,
        #"{"session_id":"canary-droid","cwd":"/tmp","hook_event_name":"PreToolUse","permission_mode":"auto-low","tool_name":"Execute","tool_use_id":"call-2","tool_input":{"command":"printf droid"}}"#,
        #"{"session_id":"canary-droid","cwd":"/tmp","hook_event_name":"PostToolUse","permission_mode":"auto-low","tool_name":"Execute","tool_use_id":"call-2","tool_input":{"command":"printf droid"},"tool_response":{"success":true}}"#
      ),
      (
        .claudeCode,
        #"{"session_id":"canary-claude","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call-3","tool_input":{"command":"printf claude"}}"#,
        #"{"session_id":"canary-claude","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"call-3","tool_input":{"command":"printf claude"},"tool_response":{"exit_code":0}}"#
      ),
      (
        .openCode,
        #"{"session_id":"canary-opencode","directory":"/tmp","event":"tool.execute.before","tool":"bash","call_id":"call-4","args":{"command":"printf opencode"}}"#,
        #"{"session_id":"canary-opencode","directory":"/tmp","event":"tool.execute.after","tool":"bash","call_id":"call-4","args":{"command":"printf opencode"},"result":{"output":"ok"}}"#
      ),
      (
        .cursor,
        #"{"conversation_id":"canary-cursor","generation_id":"turn-5","cwd":"/tmp","hook_event_name":"beforeShellExecution","command":"printf cursor"}"#,
        #"{"conversation_id":"canary-cursor","generation_id":"turn-5","cwd":"/tmp","hook_event_name":"afterShellExecution","command":"printf cursor","result":{"exit_code":0}}"#
      ),
    ]

    for (product, attempted, completed) in cases {
      for event in [attempted, completed] {
        let envelope = try AgentEventNormalizer.normalize(Data(event.utf8), product: product)
        let draft = try HookCapture.draft(from: envelope, product: product)
        _ = try store.append(draft: draft, signer: signer)
      }
    }

    let receipts = try store.readReceipts()
    let verification = ReceiptVerifier.verify(
      receipts, trustedPublicKeyBase64: signer.publicKeyBase64)
    let actions = ExecutionActionReducer.reduce(
      receipts: receipts,
      verifications: Dictionary(uniqueKeysWithValues: verification.map { ($0.receiptID, $0) })
    )
    expect(receipts.count == 10, "multi-agent canary did not create ten lifecycle receipts")
    expect(actions.count == 5, "ten lifecycle receipts did not reduce to five actions")
    expect(actions.allSatisfy { $0.state == .completed }, "a canary action did not complete")
    expect(actions.allSatisfy(\.integrityValid), "a canary action failed integrity verification")
    expect(
      Set(actions.map(\.product)) == Set(AgentProduct.allCases.map(\.displayName)),
      "the canary lost an agent product"
    )
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

  private mutating func checkAdapterInstaller() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let helper = URL(fileURLWithPath: "/usr/bin/true")
    let installed = root.appendingPathComponent("support/CerebroAgentReceiptHook")
    let installer = AgentAdapterInstaller(
      homeDirectory: root,
      bundledHelperURL: helper,
      installedHelperURL: installed
    )

    let firstPath = root.appendingPathComponent("path-first")
    let secondPath = root.appendingPathComponent("path-second")
    for directory in [firstPath, secondPath] {
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      let executable = directory.appendingPathComponent("droid")
      try Data("#!/bin/sh\nexit 0\n".utf8).write(to: executable, options: .atomic)
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o755], ofItemAtPath: executable.path)
    }
    let pathInstaller = AgentAdapterInstaller(
      homeDirectory: root,
      bundledHelperURL: helper,
      installedHelperURL: installed,
      environment: ["PATH": "\(secondPath.path):\(firstPath.path):\(secondPath.path)"])
    expect(
      pathInstaller.executableURL(for: .droid) == secondPath.appendingPathComponent("droid"),
      "executable resolution did not preserve configured PATH order")

    let factorySettings = root.appendingPathComponent(".factory/settings.json")
    try FileManager.default.createDirectory(
      at: factorySettings.deletingLastPathComponent(), withIntermediateDirectories: true)
    let existing: [String: Any] = [
      "theme": "dark",
      "hooks": [
        "PreToolUse": [
          [
            "matcher": "Read",
            "hooks": [["type": "command", "command": "/tmp/existing-hook"]],
          ]
        ]
      ],
    ]
    try JSONSerialization.data(withJSONObject: existing).write(to: factorySettings)

    try installer.install(.droid)
    expect(installer.status(for: .droid).state == .configured, "Droid adapter was not configured")
    let merged =
      try JSONSerialization.jsonObject(with: Data(contentsOf: factorySettings))
      as? [String: Any]
    expect(merged?["theme"] as? String == "dark", "Droid settings were overwritten")
    let mergedHooks = merged?["hooks"] as? [String: Any]
    let sessionGroups = mergedHooks?["SessionStart"] as? [[String: Any]]
    expect(
      sessionGroups?.last?["matcher"] == nil,
      "Droid SessionStart adapter used a tool-only matcher")
    expect(FileManager.default.isExecutableFile(atPath: installed.path), "helper was not staged")
    try Data("stale helper".utf8).write(to: installed, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installed.path)
    expect(
      installer.status(for: .droid).state == .needsRepair,
      "a stale helper was reported as configured")
    try installer.install(.droid)
    expect(
      installer.status(for: .droid).state == .configured,
      "repair did not restore the bundled helper")
    try installer.remove(.droid)
    expect(
      installer.status(for: .droid).state == .notInstalled,
      "Droid adapter was not removed")
    let preserved = try String(contentsOf: factorySettings, encoding: .utf8)
    expect(preserved.contains("/tmp/existing-hook"), "unrelated Droid hook was removed")

    for product in [AgentProduct.claudeCode, .cursor, .openCode] {
      try installer.install(product)
      let installedState = installer.status(for: product).state
      expect(
        installedState == .configured,
        "\(product.displayName) adapter was not configured (\(installedState.rawValue))")
      try installer.remove(product)
      expect(
        installer.status(for: product).state == .notInstalled,
        "\(product.displayName) adapter was not removed")
    }

    let cursorSettings = root.appendingPathComponent(".cursor/hooks.json")
    let invalidCursor = Data(#"{"hooks":"unexpected"}"#.utf8)
    try invalidCursor.write(to: cursorSettings, options: .atomic)
    expect(
      installer.status(for: .cursor).state == .invalidConfiguration,
      "an invalid Cursor hook schema was accepted")
    do {
      try installer.install(.cursor)
      failures.append("invalid Cursor hook schema was overwritten")
    } catch AgentAdapterInstallError.invalidConfiguration {
      let preservedInvalidCursor = try Data(contentsOf: cursorSettings)
      expect(
        preservedInvalidCursor == invalidCursor,
        "invalid Cursor configuration changed after a refused install")
    }

    let invalidDroid = Data(#"{"hooks":{"PreToolUse":"unexpected"}}"#.utf8)
    try invalidDroid.write(to: factorySettings, options: .atomic)
    expect(
      installer.status(for: .droid).state == .invalidConfiguration,
      "an invalid Droid hook schema was accepted")
    do {
      try installer.install(.droid)
      failures.append("invalid Droid hook schema was overwritten")
    } catch AgentAdapterInstallError.invalidConfiguration {
      let preservedInvalidDroid = try Data(contentsOf: factorySettings)
      expect(
        preservedInvalidDroid == invalidDroid,
        "invalid Droid configuration changed after a refused install")
    }

    let openCodePlugin = root.appendingPathComponent(
      ".config/opencode/plugins/cerebro-agent-receipts.js")
    try FileManager.default.createDirectory(
      at: openCodePlugin.deletingLastPathComponent(), withIntermediateDirectories: true)
    let unmanagedPlugin = Data("export const Existing = async () => ({})\n".utf8)
    try unmanagedPlugin.write(to: openCodePlugin, options: .atomic)
    expect(
      installer.status(for: .openCode).state == .unmanagedConflict,
      "an unmanaged OpenCode plugin was not reported as a conflict")
    do {
      try installer.install(.openCode)
      failures.append("unmanaged OpenCode plugin was overwritten")
    } catch AgentAdapterInstallError.unmanagedPlugin {
      let preservedOpenCodePlugin = try Data(contentsOf: openCodePlugin)
      expect(
        preservedOpenCodePlugin == unmanagedPlugin,
        "unmanaged OpenCode plugin changed after a refused install")
    }
  }

  private mutating func checkAutomaticReconciliation() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let executable = root.appendingPathComponent(".local/bin/droid")
    try FileManager.default.createDirectory(
      at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: executable, options: .atomic)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o755], ofItemAtPath: executable.path)
    let installed = root.appendingPathComponent("support/CerebroAgentReceiptHook")
    let installer = AgentAdapterInstaller(
      homeDirectory: root,
      bundledHelperURL: URL(fileURLWithPath: "/usr/bin/true"),
      installedHelperURL: installed
    )
    let first = installer.reconcileDetectedAgents().first { $0.product == .droid }
    expect(first?.outcome == .installed, "detected Droid was not configured automatically")
    expect(installer.status(for: .droid).state == .configured, "automatic install is not current")
    try Data("stale".utf8).write(to: installed, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installed.path)
    let repaired = installer.reconcileDetectedAgents().first { $0.product == .droid }
    expect(repaired?.outcome == .repaired, "changed helper was not repaired automatically")
    expect(installer.status(for: .droid).state == .configured, "automatic repair is not current")
  }

  private mutating func checkAdminCapability() throws {
    let organizationKey = P256.Signing.PrivateKey()
    let now = Date()
    let payload = ShieldAdminCapabilityPayload(
      organizationID: "org-test",
      subject: "security@example.com",
      deviceID: "device-test",
      roles: [.read, .repair],
      operation: .repairAdapters,
      target: "device:device-test",
      requestID: "request-test",
      issuedAt: ReceiptDate.string(from: now.addingTimeInterval(-30)),
      expiresAt: ReceiptDate.string(from: now.addingTimeInterval(15 * 60))
    )
    let signature = try organizationKey.signature(for: CanonicalJSON.encode(payload))
    let capability = SignedShieldAdminCapability(
      payload: payload,
      signature: signature.derRepresentation.base64EncodedString()
    )
    let publicKey = organizationKey.publicKey.x963Representation.base64EncodedString()
    let access = ShieldAdminCapabilityVerifier.verify(
      capability,
      organizationPublicKeyBase64: publicKey,
      expectedDeviceID: "device-test",
      expectedRequest: .device(operation: .repairAdapters, deviceID: "device-test"),
      requiredRole: .repair,
      now: now
    )
    expect(access.isAuthorized, "a valid device-bound administrator capability was rejected")
    let wrongDevice = ShieldAdminCapabilityVerifier.verify(
      capability,
      organizationPublicKeyBase64: publicKey,
      expectedDeviceID: "another-device",
      expectedRequest: .device(operation: .repairAdapters, deviceID: "another-device"),
      now: now
    )
    expect(!wrongDevice.isAuthorized, "an administrator capability crossed device boundaries")
    let wrongOperation = ShieldAdminCapabilityVerifier.verify(
      capability,
      organizationPublicKeyBase64: publicKey,
      expectedDeviceID: "device-test",
      expectedRequest: .device(operation: .exportReceipts, deviceID: "device-test"),
      requiredRole: .repair,
      now: now
    )
    expect(!wrongOperation.isAuthorized, "a capability authorized another operation")
    let wrongTarget = ShieldAdminCapabilityVerifier.verify(
      capability,
      organizationPublicKeyBase64: publicKey,
      expectedDeviceID: "device-test",
      expectedRequest: .device(operation: .repairAdapters, deviceID: "another-device"),
      requiredRole: .repair,
      now: now
    )
    expect(!wrongTarget.isAuthorized, "a capability authorized another target")
    let changedPayload = ShieldAdminCapabilityPayload(
      organizationID: payload.organizationID,
      subject: payload.subject,
      deviceID: payload.deviceID,
      roles: [.read, .repair, .policyOverride],
      operation: payload.operation,
      target: payload.target,
      requestID: payload.requestID,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt
    )
    let changedCapability = SignedShieldAdminCapability(
      payload: changedPayload,
      signature: capability.signature
    )
    let changedAccess = ShieldAdminCapabilityVerifier.verify(
      changedCapability,
      organizationPublicKeyBase64: publicKey,
      expectedDeviceID: "device-test",
      expectedRequest: .device(operation: .repairAdapters, deviceID: "device-test"),
      requiredRole: .policyOverride,
      now: now
    )
    expect(!changedAccess.isAuthorized, "tampered administrator roles retained a valid signature")

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let capabilityURL = directory.appendingPathComponent("capability.json")
    try JSONEncoder().encode(capability).write(to: capabilityURL, options: .atomic)
    let configuration = ManagedShieldConfiguration(
      organizationPublicKeyBase64: publicKey,
      expectedTeamIdentifier: "WRITERTEAM",
      expectedSigningIdentifier: "com.writer.cerebro.agent-receipts",
      capabilityURL: capabilityURL,
      autoRepair: true
    )
    let replayStore = ShieldCapabilityReplayStore(
      ledgerURL: directory.appendingPathComponent("used-capabilities.json"))
    let firstUse = ShieldAdminCapabilityLoader.authorize(
      configuration: configuration,
      deviceID: "device-test",
      request: .device(operation: .repairAdapters, deviceID: "device-test"),
      requiredRole: .repair,
      replayStore: replayStore,
      now: now
    )
    expect(firstUse.isAuthorized, "a fresh administrator capability was rejected")
    let replay = ShieldAdminCapabilityLoader.authorize(
      configuration: configuration,
      deviceID: "device-test",
      request: .device(operation: .repairAdapters, deviceID: "device-test"),
      requiredRole: .repair,
      replayStore: replayStore,
      now: now
    )
    expect(!replay.isAuthorized, "an administrator capability was accepted twice")
    try Data("not-json".utf8).write(to: replayStore.ledgerURL, options: .atomic)
    do {
      _ = try replayStore.consume(
        requestID: "another-request",
        expiresAt: ReceiptDate.string(from: now.addingTimeInterval(15 * 60)),
        now: now
      )
      failures.append("a corrupt capability-use ledger failed open")
    } catch ShieldCapabilityReplayError.invalidLedger {
      // Expected.
    }
  }

  private mutating func checkFallbackSpool() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let spool = ShieldFallbackSpool(
      directory: directory,
      maximumRecords: 2,
      maximumBytes: 100_000
    )
    try spool.enqueue(draft(id: "first-fallback", phase: .attempted))
    try spool.enqueue(draft(id: "second-fallback", phase: .completed))
    expect(spool.queuedCount() == 2, "fallback records were not queued")
    do {
      try spool.enqueue(draft(id: "overflow-fallback", phase: .completed))
      failures.append("fallback queue exceeded its record bound")
    } catch ShieldFallbackSpoolError.capacityExceeded {
      // Expected.
    }
    var drainedIDs: [String] = []
    let count = try spool.drain { drainedIDs.append($0.id) }
    expect(count == 2, "fallback queue did not drain both records")
    expect(
      drainedIDs == ["first-fallback", "second-fallback"],
      "fallback queue did not preserve event order")
    let secondDrain = try spool.drain { _ in }
    expect(secondDrain == 0, "fallback queue delivered a record twice")
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

  private func draft(
    id: String,
    phase: ReceiptPhase,
    toolCallID: String? = "call",
    inputDigest: String? = "sha256:input",
    toolName: String? = "Bash",
    actionSummary: String = "aws sts"
  ) -> ReceiptDraft {
    ReceiptDraft(
      id: id,
      capturedAt: ReceiptDate.string(from: Date()),
      phase: phase,
      localUserClaim: "operator@example.com",
      localUserClaimSource: "macos_account",
      agent: AgentIdentity(
        product: "Codex", model: "gpt-test", sessionID: "session", turnID: "turn",
        toolCallID: toolCallID),
      permissionMode: "default",
      toolName: toolName,
      actionSummary: actionSummary,
      inputDigest: inputDigest,
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
      startedAt: ReceiptDate.parse("2026-07-15T08:41:04.855Z"),
      completedAt: ReceiptDate.parse("2026-07-15T08:41:30.000Z"),
      receiptIDs: ["pre-\(call)", "post-\(call)"],
      integrityValid: true,
      repositoryRoot: "/redacted",
      commit: "0000000"
    )
  }

  private mutating func checkDeliveryStaysNotEnrolledWithoutCredential() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    _ = try store.append(draft: draft(id: "delivery-pending", phase: .completed), signer: signer)
    let credentialStore = TestCredentialStore(credential: nil)
    let cursorStore = TestCursorStore()
    let stateStore = TestDeliveryStateStore()
    let http = TestHTTPClient(responses: [])
    let engine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-1"),
      store: store,
      signer: signer,
      credentials: credentialStore,
      cursorStore: cursorStore,
      stateStore: stateStore,
      http: http)

    engine.deliverOnce()

    expect(stateStore.state?.state == .notEnrolled, "missing credential did not report not_enrolled")
    expect(stateStore.state?.pendingReceipts == 1, "not_enrolled state lost the pending count")
    expect(http.requests.isEmpty, "not_enrolled delivery made a network request")
    expect(cursorStore.cursor == nil, "not_enrolled delivery advanced the cursor")
  }

  private mutating func checkDeliveryAcknowledgementAndRetry() throws {
    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    _ = try store.append(draft: draft(id: "delivery-receipt", phase: .completed), signer: signer)
    let credentialStore = TestCredentialStore(credential: CerebroDeviceCredential(
      baseURL: "https://cerebro.test",
      hardwareUUID: "hardware-1",
      serverDeviceID: "server-device-1",
      refreshToken: "refresh-old",
      refreshExpiresAt: "2026-07-17T00:00:00Z"))
    let cursorStore = TestCursorStore()
    let stateStore = TestDeliveryStateStore()
    let tokenBody = Data(#"{"access_token":"access-1","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-new","refresh_expires_at":"2026-07-18T00:00:00Z","scopes":["platform.telemetry.ingest"]}"#.utf8)
    let acceptedBody = Data(#"{"status":"accepted","device_id":"server-device-1","bytes":1,"received_at":"2026-07-16T00:00:00Z"}"#.utf8)
    let http = TestHTTPClient(responses: [
      CerebroHTTPResponse(statusCode: 200, body: tokenBody),
      CerebroHTTPResponse(statusCode: 500, body: Data()),
      CerebroHTTPResponse(statusCode: 202, body: acceptedBody),
    ])
    let fixedNow = ReceiptDate.parse("2026-07-16T00:00:00.000Z")!
    let engine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-1"),
      store: store,
      signer: signer,
      credentials: credentialStore,
      cursorStore: cursorStore,
      stateStore: stateStore,
      http: http,
      now: { fixedNow })

    engine.deliverOnce()
    expect(cursorStore.cursor == nil, "500 response advanced the delivery cursor")
    expect(stateStore.state?.state == .retryableFailure, "500 response was not retryable")
    expect(credentialStore.credential?.refreshToken == "refresh-new", "rotated refresh token was not stored")
    engine.deliverOnce()

    expect(cursorStore.cursor?.lastSequence == 1, "accepted response did not advance one receipt")
    expect(stateStore.state?.state == .accepted, "accepted response did not report accepted")
    expect(http.requests.count == 3, "unexpected delivery request count")
    let firstIngest = http.requests[1]
    let retriedIngest = http.requests[2]
    expect(firstIngest.httpBody == retriedIngest.httpBody, "retry changed the canonical body")
    expect(
      firstIngest.value(forHTTPHeaderField: "Idempotency-Key")
        == retriedIngest.value(forHTTPHeaderField: "Idempotency-Key"),
      "retry changed the idempotency key")
    expect(
      firstIngest.value(forHTTPHeaderField: "DPoP")
        != retriedIngest.value(forHTTPHeaderField: "DPoP"),
      "retry reused a DPoP proof")
    try verifyDPoP(firstIngest.value(forHTTPHeaderField: "DPoP"), signer: signer, accessToken: "access-1")
  }

  private mutating func checkDeliveryEnrollmentAndCredentialBinding() throws {
    expect(
      ManagedShieldConfiguration.validDeliveryBaseURL(URL(string: "https://cerebro.test")!),
      "root HTTPS delivery URL was rejected")
    expect(
      !ManagedShieldConfiguration.validDeliveryBaseURL(URL(string: "https://cerebro.test/prefix")!),
      "managed delivery URL accepted a path prefix")
    expect(
      !ManagedShieldConfiguration.validDeliveryBaseURL(URL(string: "http://cerebro.test")!),
      "managed delivery URL accepted plaintext HTTP")

    let malformedDirectory = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: malformedDirectory) }
    try FileManager.default.createDirectory(
      at: malformedDirectory, withIntermediateDirectories: true)
    let malformedConfigurationURL = malformedDirectory.appendingPathComponent("shield.plist")
    let malformedConfiguration: [String: Any] = [
      "OrganizationPublicKey": "test-key",
      "ExpectedTeamIdentifier": "WRITERTEAM",
      "ExpectedSigningIdentifier": "com.writer.cerebro.agent-receipts",
      "AdminCapabilityPath": "/var/db/cerebro/capability.json",
      "ReceiptUploadEnabled": "true",
    ]
    let malformedData = try PropertyListSerialization.data(
      fromPropertyList: malformedConfiguration, format: .xml, options: 0)
    try malformedData.write(to: malformedConfigurationURL, options: .atomic)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600], ofItemAtPath: malformedConfigurationURL.path)
    do {
      _ = try ManagedShieldConfiguration.load(
        from: malformedConfigurationURL,
        requiredOwnerAccountID: UInt32(geteuid()))
      failures.append("a malformed managed upload flag disabled delivery silently")
    } catch ManagedShieldConfigurationError.invalidManagedConfiguration {
      // Expected.
    }

    let (store, signer, cleanup) = try temporaryStore()
    defer { cleanup() }
    _ = try store.append(draft: draft(id: "enrolled-receipt", phase: .completed), signer: signer)
    let credentialStore = TestCredentialStore(credential: nil)
    let cursorStore = TestCursorStore()
    let stateStore = TestDeliveryStateStore()
    let enrollmentBody = Data(#"{"access_token":"access-enrolled","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-enrolled","refresh_expires_at":"2026-07-18T00:00:00Z","scopes":["platform.telemetry.ingest"],"device_id":"server-device-enrolled"}"#.utf8)
    let acceptedBody = Data(#"{"status":"accepted","device_id":"server-device-enrolled"}"#.utf8)
    let http = TestHTTPClient(responses: [
      CerebroHTTPResponse(statusCode: 200, body: enrollmentBody),
      CerebroHTTPResponse(statusCode: 202, body: acceptedBody),
    ])
    let engine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-enrolled"),
      store: store,
      signer: signer,
      credentials: credentialStore,
      cursorStore: cursorStore,
      stateStore: stateStore,
      http: http)

    try engine.enroll(bootstrapToken: "one-time-bootstrap")
    expect(credentialStore.credential?.baseURL == "https://cerebro.test", "credential omitted base URL binding")
    expect(credentialStore.credential?.hardwareUUID == "hardware-enrolled", "credential omitted hardware binding")
    expect(http.requests.first?.value(forHTTPHeaderField: "Authorization") == nil, "enrollment sent Authorization")
    expect(http.requests.first?.value(forHTTPHeaderField: "DPoP") == nil, "enrollment sent an unnecessary DPoP proof")
    expect(
      !(http.requests.first?.httpBody ?? Data()).isEmpty,
      "enrollment omitted its request body")
    expect(stateStore.state?.state == .queued, "enrollment hid a queued receipt as idle")
    expect(stateStore.state?.pendingReceipts == 1, "enrollment lost the queued receipt count")
    engine.deliverOnce()
    expect(http.requests.count == 2, "fresh enrollment unnecessarily rotated its refresh token")
    expect(cursorStore.cursor?.lastSequence == 1, "enrolled delivery did not reach the cursor")

    let wrongCredential = TestCredentialStore(credential: CerebroDeviceCredential(
      baseURL: "https://other.test",
      hardwareUUID: "hardware-enrolled",
      serverDeviceID: "other-device",
      refreshToken: "must-not-send",
      refreshExpiresAt: "2026-07-18T00:00:00Z"))
    let blockedHTTP = TestHTTPClient(responses: [])
    let blockedState = TestDeliveryStateStore()
    let blockedEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-enrolled"),
      store: store,
      signer: signer,
      credentials: wrongCredential,
      cursorStore: TestCursorStore(),
      stateStore: blockedState,
      http: blockedHTTP)
    blockedEngine.deliverOnce()
    expect(blockedHTTP.requests.isEmpty, "credential was sent to a different managed base URL")
    expect(blockedState.state?.errorCode == "credential_binding_mismatch", "credential mismatch was not explicit")

    let stateFailureHTTP = TestHTTPClient(responses: [])
    let stateFailureEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-enrolled"),
      store: store,
      signer: signer,
      credentials: TestCredentialStore(credential: CerebroDeviceCredential(
        baseURL: "https://cerebro.test",
        hardwareUUID: "hardware-enrolled",
        serverDeviceID: "server-device-enrolled",
        refreshToken: "must-not-send",
        refreshExpiresAt: "2026-07-18T00:00:00Z")),
      cursorStore: TestCursorStore(),
      stateStore: FailingDeliveryStateStore(),
      http: stateFailureHTTP)
    stateFailureEngine.deliverOnce()
    expect(
      stateFailureHTTP.requests.isEmpty,
      "delivery made a network request without a durable attempt state")
    expect(
      !stateFailureEngine.deliveryStateStorageHealthy,
      "delivery state persistence failure was not exposed to the status app")

    let (corruptStore, corruptSigner, corruptCleanup) = try temporaryStore()
    defer { corruptCleanup() }
    _ = try corruptStore.append(
      draft: draft(id: "corrupt-delivery-receipt", phase: .completed), signer: corruptSigner)
    let corruptHandle = try FileHandle(forWritingTo: corruptStore.receiptsURL)
    try corruptHandle.seekToEnd()
    try corruptHandle.write(contentsOf: Data("{not-json}\n".utf8))
    try corruptHandle.close()
    let corruptState = TestDeliveryStateStore()
    let corruptHTTP = TestHTTPClient(responses: [])
    let corruptEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-enrolled"),
      store: corruptStore,
      signer: corruptSigner,
      credentials: TestCredentialStore(credential: nil),
      cursorStore: TestCursorStore(),
      stateStore: corruptState,
      http: corruptHTTP)
    corruptEngine.deliverOnce()
    expect(corruptState.state?.state == .blocked, "an unreadable ledger was not blocked")
    expect(
      corruptState.state?.pendingReceipts == nil,
      "an unreadable ledger reported a known pending receipt count")
    expect(corruptHTTP.requests.isEmpty, "an unreadable ledger made a network request")

    let corruptEnrollmentState = TestDeliveryStateStore()
    let corruptEnrollmentEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-corrupt"),
      store: corruptStore,
      signer: corruptSigner,
      credentials: TestCredentialStore(credential: nil),
      cursorStore: TestCursorStore(),
      stateStore: corruptEnrollmentState,
      http: TestHTTPClient(responses: [
        CerebroHTTPResponse(statusCode: 200, body: enrollmentBody)
      ]))
    try corruptEnrollmentEngine.enroll(bootstrapToken: "one-time-bootstrap")
    expect(
      corruptEnrollmentState.state?.state == .blocked,
      "enrollment reported an unreadable ledger as idle")
    expect(
      corruptEnrollmentState.state?.pendingReceipts == nil,
      "enrollment reported an unreadable ledger as zero pending")

    let corruptCursorStore = TestCursorStore()
    corruptCursorStore.cursor = CerebroDeliveryCursor(
      serverDeviceID: "server-device-enrolled",
      signingDeviceID: signer.deviceID,
      lastSequence: 2,
      lastReceiptID: "missing-receipt",
      lastReceiptDigest: "missing-digest")
    let corruptCursorState = TestDeliveryStateStore()
    let corruptCursorEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-cursor"),
      store: store,
      signer: signer,
      credentials: TestCredentialStore(credential: nil),
      cursorStore: corruptCursorStore,
      stateStore: corruptCursorState,
      http: TestHTTPClient(responses: [
        CerebroHTTPResponse(statusCode: 200, body: enrollmentBody)
      ]))
    try corruptCursorEngine.enroll(bootstrapToken: "one-time-bootstrap")
    expect(
      corruptCursorState.state?.state == .blocked,
      "enrollment reported a corrupt delivery cursor as healthy")
    expect(
      corruptCursorState.state?.pendingReceipts == nil,
      "enrollment reported a known count for a corrupt delivery cursor")

    let validOldCursor = CerebroDeliveryCursor(
      serverDeviceID: "old-server-device",
      signingDeviceID: signer.deviceID,
      lastSequence: 1,
      lastReceiptID: cursorStore.cursor!.lastReceiptID,
      lastReceiptDigest: cursorStore.cursor!.lastReceiptDigest)
    let oldCursorEnrollmentStore = TestCursorStore()
    oldCursorEnrollmentStore.cursor = validOldCursor
    let oldCursorEnrollmentState = TestDeliveryStateStore()
    let newDeviceEnrollmentBody = Data(#"{"access_token":"access-new-device","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-new-device","refresh_expires_at":"2026-07-18T00:00:00Z","scopes":["platform.telemetry.ingest"],"device_id":"new-server-device"}"#.utf8)
    let oldCursorEnrollmentEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-old-cursor"),
      store: store,
      signer: signer,
      credentials: TestCredentialStore(credential: nil),
      cursorStore: oldCursorEnrollmentStore,
      stateStore: oldCursorEnrollmentState,
      http: TestHTTPClient(responses: [
        CerebroHTTPResponse(statusCode: 200, body: newDeviceEnrollmentBody)
      ]))
    try oldCursorEnrollmentEngine.enroll(bootstrapToken: "one-time-bootstrap")
    expect(
      oldCursorEnrollmentState.state?.state == .blocked,
      "enrollment accepted a cursor bound to another server device")
    expect(
      oldCursorEnrollmentState.state?.pendingReceipts == nil,
      "enrollment counted pending receipts through another device's cursor")

    let oldCursorDeliveryStore = TestCursorStore()
    oldCursorDeliveryStore.cursor = validOldCursor
    let oldCursorDeliveryState = TestDeliveryStateStore()
    let oldCursorDeliveryHTTP = TestHTTPClient(responses: [])
    let oldCursorDeliveryEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-old-cursor"),
      store: store,
      signer: signer,
      credentials: TestCredentialStore(credential: CerebroDeviceCredential(
        baseURL: "https://cerebro.test",
        hardwareUUID: "hardware-old-cursor",
        serverDeviceID: "new-server-device",
        refreshToken: "must-not-send",
        refreshExpiresAt: "2026-07-18T00:00:00Z")),
      cursorStore: oldCursorDeliveryStore,
      stateStore: oldCursorDeliveryState,
      http: oldCursorDeliveryHTTP)
    oldCursorDeliveryEngine.deliverOnce()
    expect(
      oldCursorDeliveryState.state?.state == .blocked,
      "delivery accepted a cursor bound to another server device")
    expect(
      oldCursorDeliveryState.state?.pendingReceipts == nil,
      "delivery counted pending receipts through another device's cursor")
    expect(
      oldCursorDeliveryHTTP.requests.isEmpty,
      "delivery used the network with another device's cursor")

    let (postAcceptStore, postAcceptSigner, postAcceptCleanup) = try temporaryStore()
    defer { postAcceptCleanup() }
    _ = try postAcceptStore.append(
      draft: draft(id: "post-accept-receipt", phase: .completed), signer: postAcceptSigner)
    let postAcceptCursor = CommitThenFailCursorStore()
    let postAcceptState = TestDeliveryStateStore()
    let postAcceptTokenBody = Data(#"{"access_token":"access-post-accept","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-post-accept","refresh_expires_at":"2026-07-18T00:00:00Z","scopes":["platform.telemetry.ingest"]}"#.utf8)
    let postAcceptHTTP = TestHTTPClient(responses: [
      CerebroHTTPResponse(statusCode: 200, body: postAcceptTokenBody),
      CerebroHTTPResponse(
        statusCode: 202,
        body: Data(#"{"status":"accepted","device_id":"server-device-1"}"#.utf8)),
    ])
    let postAcceptEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-1"),
      store: postAcceptStore,
      signer: postAcceptSigner,
      credentials: TestCredentialStore(credential: CerebroDeviceCredential(
        baseURL: "https://cerebro.test",
        hardwareUUID: "hardware-1",
        serverDeviceID: "server-device-1",
        refreshToken: "refresh-old",
        refreshExpiresAt: "2026-07-18T00:00:00Z")),
      cursorStore: postAcceptCursor,
      stateStore: postAcceptState,
      http: postAcceptHTTP)
    postAcceptEngine.deliverOnce()
    expect(
      postAcceptCursor.cursor?.lastSequence == 1,
      "post-accept cursor failure did not model a committed acknowledgement")
    expect(
      postAcceptState.state?.state == .blocked,
      "post-accept local failure did not remain visible")
    expect(
      postAcceptState.state?.pendingReceipts == 0,
      "post-accept fallback retained the pre-acknowledgement pending count")

    let (emptyRaceStore, emptyRaceSigner, emptyRaceCleanup) = try temporaryStore()
    defer { emptyRaceCleanup() }
    let emptyRaceDraft = draft(id: "concurrent-not-enrolled", phase: .completed)
    let emptyRaceCursor = AppendOnceOnLoadCursorStore {
      _ = try emptyRaceStore.append(
        draft: emptyRaceDraft,
        signer: emptyRaceSigner)
    }
    let emptyRaceState = TestDeliveryStateStore()
    let emptyRaceEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-empty-race"),
      store: emptyRaceStore,
      signer: emptyRaceSigner,
      credentials: TestCredentialStore(credential: nil),
      cursorStore: emptyRaceCursor,
      stateStore: emptyRaceState,
      http: TestHTTPClient(responses: []))
    emptyRaceEngine.deliverOnce()
    expect(
      emptyRaceState.state?.state == .notEnrolled,
      "concurrent append changed the missing-credential state")
    expect(
      emptyRaceState.state?.pendingReceipts == 1,
      "concurrent append was omitted from the persisted not-enrolled count")

    let (acceptedRaceStore, acceptedRaceSigner, acceptedRaceCleanup) = try temporaryStore()
    defer { acceptedRaceCleanup() }
    _ = try acceptedRaceStore.append(
      draft: draft(id: "accepted-race-first", phase: .completed),
      signer: acceptedRaceSigner)
    let acceptedRaceDraft = draft(id: "accepted-race-second", phase: .completed)
    let acceptedRaceCursor = AppendOnceOnSaveCursorStore {
      _ = try acceptedRaceStore.append(
        draft: acceptedRaceDraft,
        signer: acceptedRaceSigner)
    }
    let acceptedRaceState = TestDeliveryStateStore()
    let acceptedRaceHTTP = TestHTTPClient(responses: [
      CerebroHTTPResponse(statusCode: 200, body: postAcceptTokenBody),
      CerebroHTTPResponse(
        statusCode: 202,
        body: Data(#"{"status":"accepted","device_id":"server-device-1"}"#.utf8)),
    ])
    let acceptedRaceEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-1"),
      store: acceptedRaceStore,
      signer: acceptedRaceSigner,
      credentials: TestCredentialStore(credential: CerebroDeviceCredential(
        baseURL: "https://cerebro.test",
        hardwareUUID: "hardware-1",
        serverDeviceID: "server-device-1",
        refreshToken: "refresh-old",
        refreshExpiresAt: "2026-07-18T00:00:00Z")),
      cursorStore: acceptedRaceCursor,
      stateStore: acceptedRaceState,
      http: acceptedRaceHTTP)
    acceptedRaceEngine.deliverOnce()
    expect(
      acceptedRaceState.state?.state == .accepted,
      "concurrent append prevented accepted status persistence")
    expect(
      acceptedRaceState.state?.pendingReceipts == 1,
      "concurrent append was omitted from the post-accept pending count")

    let (failureLockStore, failureLockSigner, failureLockCleanup) = try temporaryStore()
    defer { failureLockCleanup() }
    _ = try failureLockStore.append(
      draft: draft(id: "failure-lock-receipt", phase: .completed),
      signer: failureLockSigner)
    let failureLockState = LockObservingDeliveryStateStore(
      lockURL: failureLockStore.directory.appendingPathComponent("receipts.lock"),
      observedState: .retryableFailure)
    let failureLockEngine = CerebroDeliveryEngine(
      configuration: CerebroDeliveryConfiguration(
        baseURL: URL(string: "https://cerebro.test")!, hardwareUUID: "hardware-1"),
      store: failureLockStore,
      signer: failureLockSigner,
      credentials: TestCredentialStore(credential: CerebroDeviceCredential(
        baseURL: "https://cerebro.test",
        hardwareUUID: "hardware-1",
        serverDeviceID: "server-device-1",
        refreshToken: "refresh-old",
        refreshExpiresAt: "2026-07-18T00:00:00Z")),
      cursorStore: TestCursorStore(),
      stateStore: failureLockState,
      http: TestHTTPClient(responses: [
        CerebroHTTPResponse(statusCode: 200, body: postAcceptTokenBody),
        CerebroHTTPResponse(statusCode: 500, body: Data()),
      ]))
    failureLockEngine.deliverOnce()
    expect(
      failureLockState.state?.state == .retryableFailure,
      "network failure did not persist a retryable state")
    expect(
      failureLockState.observedSharedReceiptLock,
      "failure state was persisted outside the verified-ledger transaction")
  }

  private mutating func verifyDPoP(
    _ proof: String?, signer: DeviceKeySigner, accessToken: String
  ) throws {
    guard let proof else { failures.append("ingest request omitted DPoP"); return }
    let parts = proof.split(separator: ".").map(String.init)
    guard parts.count == 3,
      let payloadData = base64URLDecode(parts[1]),
      let signatureData = base64URLDecode(parts[2]),
      let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
      let publicData = Data(base64Encoded: signer.publicKeyBase64),
      let publicKey = try? P256.Signing.PublicKey(x963Representation: publicData),
      let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData)
    else { failures.append("DPoP proof could not be decoded"); return }
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    expect(publicKey.isValidSignature(signature, for: signingInput), "DPoP signature was invalid")
    let expectedATH = Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLForCheck
    expect(payload["ath"] as? String == expectedATH, "DPoP ath did not bind the access token")
    expect(payload["htm"] as? String == "POST", "DPoP htm was wrong")
    expect(
      payload["htu"] as? String == "https://cerebro.test/platform/telemetry/ingest",
      "DPoP htu was wrong")
  }

  private func base64URLDecode(_ value: String) -> Data? {
    var raw = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    raw.append(String(repeating: "=", count: (4 - raw.count % 4) % 4))
    return Data(base64Encoded: raw)
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

private final class TestCredentialStore: CerebroCredentialStoring, @unchecked Sendable {
  var credential: CerebroDeviceCredential?
  init(credential: CerebroDeviceCredential?) { self.credential = credential }
  func load() throws -> CerebroDeviceCredential? { credential }
  func save(_ credential: CerebroDeviceCredential) throws { self.credential = credential }
  func remove() throws { credential = nil }
}

private final class TestCursorStore: CerebroCursorStoring, @unchecked Sendable {
  var cursor: CerebroDeliveryCursor?
  func load() throws -> CerebroDeliveryCursor? { cursor }
  func save(_ cursor: CerebroDeliveryCursor) throws { self.cursor = cursor }
}

private final class CommitThenFailCursorStore: CerebroCursorStoring, @unchecked Sendable {
  var cursor: CerebroDeliveryCursor?
  func load() throws -> CerebroDeliveryCursor? { cursor }
  func save(_ cursor: CerebroDeliveryCursor) throws {
    self.cursor = cursor
    throw CheckError.cursorPostCommitFailed
  }
}

private final class AppendOnceOnLoadCursorStore: CerebroCursorStoring, @unchecked Sendable {
  var cursor: CerebroDeliveryCursor?
  private var append: (() throws -> Void)?
  init(append: @escaping () throws -> Void) { self.append = append }
  func load() throws -> CerebroDeliveryCursor? {
    if let append {
      self.append = nil
      try append()
    }
    return cursor
  }
  func save(_ cursor: CerebroDeliveryCursor) throws { self.cursor = cursor }
}

private final class AppendOnceOnSaveCursorStore: CerebroCursorStoring, @unchecked Sendable {
  var cursor: CerebroDeliveryCursor?
  private var append: (() throws -> Void)?
  init(append: @escaping () throws -> Void) { self.append = append }
  func load() throws -> CerebroDeliveryCursor? { cursor }
  func save(_ cursor: CerebroDeliveryCursor) throws {
    self.cursor = cursor
    if let append {
      self.append = nil
      try append()
    }
  }
}

private final class TestDeliveryStateStore: CerebroDeliveryStateStoring, @unchecked Sendable {
  var state: CerebroDeliveryState?
  func save(_ state: CerebroDeliveryState) throws { self.state = state }
}

private final class LockObservingDeliveryStateStore: CerebroDeliveryStateStoring,
  @unchecked Sendable
{
  let lockURL: URL
  let observedState: CerebroDeliveryStateCode
  var state: CerebroDeliveryState?
  var observedSharedReceiptLock = false

  init(lockURL: URL, observedState: CerebroDeliveryStateCode) {
    self.lockURL = lockURL
    self.observedState = observedState
  }

  func save(_ state: CerebroDeliveryState) throws {
    if state.state == observedState {
      let descriptor = open(lockURL.path, O_RDWR)
      if descriptor >= 0 {
        if flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
          observedSharedReceiptLock = true
        } else {
          _ = flock(descriptor, LOCK_UN)
        }
        close(descriptor)
      }
    }
    self.state = state
  }
}

private struct FailingDeliveryStateStore: CerebroDeliveryStateStoring {
  func save(_ state: CerebroDeliveryState) throws { throw CheckError.stateWriteFailed }
}

private final class TestHTTPClient: CerebroHTTPPerforming, @unchecked Sendable {
  var responses: [CerebroHTTPResponse]
  var requests: [URLRequest] = []
  init(responses: [CerebroHTTPResponse]) { self.responses = responses }
  func perform(_ request: URLRequest) throws -> CerebroHTTPResponse {
    requests.append(request)
    guard !responses.isEmpty else { throw URLError(.notConnectedToInternet) }
    return responses.removeFirst()
  }
}

extension Data {
  fileprivate var base64URLForCheck: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

private enum CheckError: Error {
  case missingAction
  case cursorPostCommitFailed
  case stateWriteFailed
}

do {
  var runner = CheckRunner()
  try runner.run()
} catch {
  FileHandle.standardError.write(Data("FAIL: \(error.localizedDescription)\n".utf8))
  exit(1)
}
