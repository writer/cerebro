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

    if failures.isEmpty {
      print("PASS: 19 receipt security checks")
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
      startedAt: ReceiptDate.parse("2026-07-15T08:41:04.855Z"),
      completedAt: ReceiptDate.parse("2026-07-15T08:41:30.000Z"),
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
