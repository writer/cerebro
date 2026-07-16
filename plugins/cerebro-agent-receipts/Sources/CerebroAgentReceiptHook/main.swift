import Foundation
import ReceiptCore

do {
  let arguments = Array(CommandLine.arguments.dropFirst())
  if arguments.first == "ping" {
    guard arguments.count == 1, ShieldServiceClient.isReachable(timeout: 1) else {
      throw CLIError.provider("The Cerebro Shield background collector is not reachable.")
    }
    print("Cerebro Shield background collector is reachable.")
    exit(0)
  }

  if arguments.first == "import-cloudtrail" {
    guard arguments.count == 2 else {
      throw CLIError.usage("usage: CerebroAgentReceiptHook import-cloudtrail <lookup-events.json>")
    }
    let store = ReceiptStore()
    let imported = try CloudTrailImporter.parse(
      Data(contentsOf: URL(fileURLWithPath: arguments[1])),
      provenance: .userImported
    )
    try saveMerged(imported, to: store)
    print("Imported \(imported.count) provider event(s).")
    exit(0)
  }

  if arguments.first == "fetch-cloudtrail" {
    guard arguments.count == 5 else {
      throw CLIError.usage(
        "usage: CerebroAgentReceiptHook fetch-cloudtrail <profile> <event-name> <start-time> <end-time>"
      )
    }
    let data = try fetchCloudTrail(
      profile: arguments[1],
      eventName: arguments[2],
      startTime: arguments[3],
      endTime: arguments[4]
    )
    let events = try CloudTrailImporter.parse(data, provenance: .authenticatedAWSAPI)
    try saveMerged(events, to: ReceiptStore())
    print("Fetched \(events.count) provider event(s) from the authenticated AWS API.")
    exit(0)
  }

  if arguments.first == "verify" {
    guard
      arguments.count == 1 || (arguments.count == 2 && arguments[1] == "--require-provider-bound")
    else {
      throw CLIError.usage("usage: CerebroAgentReceiptHook verify [--require-provider-bound]")
    }
    let store = ReceiptStore()
    var receipts: [ExecutionReceipt] = []
    var verification: [ReceiptVerification] = []
    for receiptStore in receiptStores() {
      let chain = try receiptStore.readReceipts()
      guard !chain.isEmpty else { continue }
      receipts.append(contentsOf: chain)
      verification.append(
        contentsOf: ReceiptVerifier.verify(
          chain, trustedPublicKeyBase64: try receiptStore.readTrustedPublicKey()))
    }
    receipts.sort {
      ($0.payload.capturedDate ?? .distantPast) < ($1.payload.capturedDate ?? .distantPast)
    }
    let providerEvents = try store.readProviderEvents()
    let verificationMap = Dictionary(uniqueKeysWithValues: verification.map { ($0.receiptID, $0) })
    let actions = ExecutionActionReducer.reduce(receipts: receipts, verifications: verificationMap)
    let assessment = ReceiptCorrelator.assess(
      actions: actions,
      providerEvents: providerEvents,
      policy: bindingPolicyFromEnvironment()
    )
    let completed = actions.filter { $0.state == .completed }.count
    let integrityPassed = !receipts.isEmpty && verification.allSatisfy(\.valid)
    let providerPolicyPassed =
      completed > 0 && assessment.providerBoundCount == completed
      && assessment.unmatchedProviderEvents.isEmpty
    let report = VerificationReport(
      receipts: receipts.count,
      validReceipts: verification.filter(\.valid).count,
      actions: actions.count,
      completedActions: completed,
      providerBound: assessment.providerBoundCount,
      candidateCorrelations: assessment.candidateCount,
      localOnlyActions: assessment.capturedOnlyCount,
      unmatchedProviderEvents: assessment.unmatchedProviderEvents.count,
      integrityPassed: integrityPassed,
      providerPolicyPassed: providerPolicyPassed
    )
    FileHandle.standardOutput.write(try CanonicalJSON.encode(report))
    FileHandle.standardOutput.write(Data("\n".utf8))
    let requireProvider = arguments.count == 2
    exit(integrityPassed && (!requireProvider || providerPolicyPassed) ? 0 : 1)
  }

  let product: AgentProduct
  if arguments.isEmpty {
    product = .codex
  } else if arguments.count == 2, arguments.first == "capture",
    let selected = AgentProduct(rawValue: arguments[1])
  {
    product = selected
  } else {
    throw CLIError.usage(
      "usage: CerebroAgentReceiptHook [capture <codex|droid|claude-code|opencode|cursor>|ping|verify|import-cloudtrail|fetch-cloudtrail]"
    )
  }
  let input = FileHandle.standardInput.readDataToEndOfFile()
  guard !input.isEmpty else { exit(0) }
  let envelope = try AgentEventNormalizer.normalize(input, product: product)
  let draft = try HookCapture.draft(from: envelope, product: product)
  if !ShieldServiceClient.submit(draft) {
    let identity = AgentBinaryAttestor.inspect(
      product: product,
      executableURL: ProcessExecutable.url()
    )
    guard ShieldFallbackPolicy.permitsUserWritableFallback(clientTrust: identity.trust) else {
      throw CLIError.provider(
        "The managed background collector rejected the event; no user-writable fallback was accepted."
      )
    }
    try ShieldFallbackSpool().enqueue(draft)
  }
} catch {
  FileHandle.standardError.write(
    Data("Cerebro receipt capture failed: \(error.localizedDescription)\n".utf8))
  exit(1)
}

private enum CLIError: Error, LocalizedError {
  case usage(String)
  case provider(String)
  var errorDescription: String? {
    switch self {
    case .usage(let message), .provider(let message): return message
    }
  }
}

private struct VerificationReport: Codable {
  let receipts: Int
  let validReceipts: Int
  let actions: Int
  let completedActions: Int
  let providerBound: Int
  let candidateCorrelations: Int
  let localOnlyActions: Int
  let unmatchedProviderEvents: Int
  let integrityPassed: Bool
  let providerPolicyPassed: Bool
}

private func saveMerged(_ events: [ProviderEvent], to store: ReceiptStore) throws {
  var merged: [String: ProviderEvent] = [:]
  for event in try store.readProviderEvents() + events { merged[event.id] = event }
  try store.saveProviderEvents(Array(merged.values))
}

private func receiptStores() -> [ReceiptStore] {
  [ReceiptStore(), ReceiptStore(directory: ReceiptStore.shieldAgentDirectory())]
}

private func bindingPolicyFromEnvironment() -> ProviderBindingPolicy? {
  let environment = ProcessInfo.processInfo.environment
  guard
    let account = environment["CEREBRO_EXPECTED_AWS_ACCOUNT_ID"],
    let role = environment["CEREBRO_EXPECTED_AWS_AGENT_ROLE"],
    !account.isEmpty,
    !role.isEmpty
  else { return nil }
  return ProviderBindingPolicy(expectedAccountID: account, expectedAgentRole: role)
}

private func fetchCloudTrail(profile: String, eventName: String, startTime: String, endTime: String)
  throws -> Data
{
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
  process.arguments = [
    "aws", "cloudtrail", "lookup-events",
    "--profile", profile,
    "--lookup-attributes", "AttributeKey=EventName,AttributeValue=\(eventName)",
    "--start-time", startTime,
    "--end-time", endTime,
    "--output", "json",
  ]
  let output = Pipe()
  let errors = Pipe()
  process.standardOutput = output
  process.standardError = errors
  try process.run()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else {
    let message = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    throw CLIError.provider(message.trimmingCharacters(in: .whitespacesAndNewlines))
  }
  return output.fileHandleForReading.readDataToEndOfFile()
}
