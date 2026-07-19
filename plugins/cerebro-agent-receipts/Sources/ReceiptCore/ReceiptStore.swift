import Darwin
import Foundation

public enum ReceiptStoreError: Error, LocalizedError {
  case lockFailed(Int32)
  case invalidRecord
  case missingTrustedPublicKey
  case signerChanged

  public var errorDescription: String? {
    switch self {
    case .lockFailed(let code): return "Could not lock the receipt store (errno \(code))."
    case .invalidRecord: return "The receipt store contains an invalid record."
    case .missingTrustedPublicKey: return "The receipt store has no enrolled public key."
    case .signerChanged:
      return "The signing key does not match the public key enrolled for this receipt store."
    }
  }
}

public struct ReceiptStore: Sendable {
  public let directory: URL
  public let receiptsURL: URL
  public let observationsURL: URL
  public let trustedPublicKeyURL: URL

  public init(directory: URL? = nil) {
    let selected = directory ?? Self.defaultDirectory()
    self.directory = selected
    self.receiptsURL = selected.appendingPathComponent("receipts.ndjson")
    self.observationsURL = selected.appendingPathComponent("provider-observations.json")
    self.trustedPublicKeyURL = selected.appendingPathComponent("trusted-public-key")
  }

  public static func defaultDirectory(
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) -> URL {
    if let override = environment["CEREBRO_AGENT_RECEIPTS_DIR"], !override.isEmpty {
      return URL(fileURLWithPath: override, isDirectory: true)
    }
    let applicationSupport = FileManager.default.urls(
      for: .applicationSupportDirectory, in: .userDomainMask)[0]
    return applicationSupport.appendingPathComponent(
      "com.writer.cerebro.agent-receipts", isDirectory: true)
  }

  public static func shieldAgentDirectory(
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) -> URL {
    if let override = environment["CEREBRO_SHIELD_AGENT_RECEIPTS_DIR"], !override.isEmpty {
      return URL(fileURLWithPath: override, isDirectory: true)
    }
    return defaultDirectory(environment: environment)
      .appendingPathComponent("shield-agent-v1", isDirectory: true)
  }

  @discardableResult
  public func append(draft: ReceiptDraft, signer: ReceiptSigning) throws -> ExecutionReceipt {
    try prepareDirectory()
    let lockURL = directory.appendingPathComponent("receipts.lock")
    let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw ReceiptStoreError.lockFailed(errno) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else { throw ReceiptStoreError.lockFailed(errno) }
    defer { flock(descriptor, LOCK_UN) }

    try enroll(publicKey: signer.publicKeyBase64)

    let existingData = (try? Data(contentsOf: receiptsURL)) ?? Data()
    let lines: [Data.SubSequence] = existingData.split(
      separator: UInt8(10),
      maxSplits: Int.max,
      omittingEmptySubsequences: true
    )
    let lastLine = lines.last.map { Data($0) }
    let previousReceipt = try lastLine.map {
      try JSONDecoder().decode(ExecutionReceipt.self, from: $0)
    }
    let previousDigest = lastLine.map(SHA256Digest.hex)
    let sequence = (previousReceipt?.payload.sequence ?? 0) + 1

    let payload = ExecutionReceiptPayload(
      id: draft.id,
      sequence: sequence,
      previousReceiptDigest: previousDigest,
      capturedAt: draft.capturedAt,
      phase: draft.phase,
      localUserClaim: draft.localUserClaim,
      localUserClaimSource: draft.localUserClaimSource,
      agent: draft.agent,
      collector: draft.collector,
      deviceID: signer.deviceID,
      permissionMode: draft.permissionMode,
      toolName: draft.toolName,
      actionSummary: draft.actionSummary,
      inputDigest: draft.inputDigest,
      resultDigest: draft.resultDigest,
      cwd: draft.cwd,
      git: draft.git
    )
    let signatureData = try signer.sign(CanonicalJSON.encode(payload))
    let receipt = ExecutionReceipt(
      payload: payload,
      signature: ReceiptSignature(
        algorithm: "P256-SHA256",
        publicKey: signer.publicKeyBase64,
        value: signatureData.base64EncodedString(),
        hardwareBacked: signer.hardwareBacked
      )
    )
    var line = try CanonicalJSON.encode(receipt)
    line.append(0x0A)

    if !FileManager.default.fileExists(atPath: receiptsURL.path) {
      FileManager.default.createFile(
        atPath: receiptsURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    }
    let handle = try FileHandle(forWritingTo: receiptsURL)
    defer { try? handle.close() }
    try handle.seekToEnd()
    try handle.write(contentsOf: line)
    try handle.synchronize()
    return receipt
  }

  public func readReceipts() throws -> [ExecutionReceipt] {
    guard FileManager.default.fileExists(atPath: receiptsURL.path) else { return [] }
    let data = try Data(contentsOf: receiptsURL)
    let lines: [Data.SubSequence] = data.split(
      separator: UInt8(10),
      maxSplits: Int.max,
      omittingEmptySubsequences: true
    )
    return try lines.map {
      try JSONDecoder().decode(ExecutionReceipt.self, from: Data($0))
    }
  }

  /// Returns a consistent, verified ledger snapshot for remote delivery. A
  /// writer cannot append a partial NDJSON record while this snapshot is read.
  public func readVerifiedReceipts() throws -> [ExecutionReceipt] {
    try withVerifiedReceipts { $0 }
  }

  /// Keeps the shared receipt lock held while a caller derives and persists a
  /// local status from the verified ledger revision. The operation must remain
  /// local and bounded; network work does not belong inside this transaction.
  public func withVerifiedReceipts<T>(
    _ operation: ([ExecutionReceipt]) throws -> T
  ) throws -> T {
    try prepareDirectory()
    let lockURL = directory.appendingPathComponent("receipts.lock")
    let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw ReceiptStoreError.lockFailed(errno) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_SH) == 0 else { throw ReceiptStoreError.lockFailed(errno) }
    defer { flock(descriptor, LOCK_UN) }

    guard FileManager.default.fileExists(atPath: receiptsURL.path) else {
      return try operation([])
    }
    let data = try Data(contentsOf: receiptsURL)
    let lines = data.split(separator: UInt8(10), omittingEmptySubsequences: true)
    let receipts = try lines.map {
      try JSONDecoder().decode(ExecutionReceipt.self, from: Data($0))
    }
    let trustedKey = try readTrustedPublicKey()
    guard ReceiptVerifier.verify(receipts, trustedPublicKeyBase64: trustedKey).allSatisfy(\.valid)
    else { throw ReceiptStoreError.invalidRecord }
    return try operation(receipts)
  }

  public func saveProviderEvents(_ events: [ProviderEvent]) throws {
    try prepareDirectory()
    let data = try CanonicalJSON.encode(events)
    try data.write(to: observationsURL, options: .atomic)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600], ofItemAtPath: observationsURL.path)
  }

  public func readProviderEvents() throws -> [ProviderEvent] {
    guard FileManager.default.fileExists(atPath: observationsURL.path) else { return [] }
    return try JSONDecoder().decode([ProviderEvent].self, from: Data(contentsOf: observationsURL))
  }

  public func readTrustedPublicKey() throws -> String {
    guard FileManager.default.fileExists(atPath: trustedPublicKeyURL.path) else {
      throw ReceiptStoreError.missingTrustedPublicKey
    }
    return try String(contentsOf: trustedPublicKeyURL, encoding: .utf8)
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private func enroll(publicKey: String) throws {
    if FileManager.default.fileExists(atPath: trustedPublicKeyURL.path) {
      guard try readTrustedPublicKey() == publicKey else { throw ReceiptStoreError.signerChanged }
      return
    }
    try Data((publicKey + "\n").utf8).write(to: trustedPublicKeyURL, options: .atomic)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o400], ofItemAtPath: trustedPublicKeyURL.path)
  }

  private func prepareDirectory() throws {
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
  }
}

public struct ReceiptVerification: Sendable {
  public let receiptID: String
  public let signatureValid: Bool
  public let chainValid: Bool
  public let sequenceValid: Bool

  public var valid: Bool { signatureValid && chainValid && sequenceValid }
}

public enum ReceiptVerifier {
  public static func verify(
    _ receipts: [ExecutionReceipt],
    trustedPublicKeyBase64: String
  ) -> [ReceiptVerification] {
    receipts.enumerated().map { index, receipt in
      let previous = index > 0 ? receipts[index - 1] : nil
      let expectedSequence = UInt64(index + 1)
      let expectedDigest = previous.flatMap { try? CanonicalJSON.encode($0) }.map(SHA256Digest.hex)
      return ReceiptVerification(
        receiptID: receipt.id,
        signatureValid: receipt.signature.publicKey == trustedPublicKeyBase64
          && DeviceKeySigner.verify(receipt),
        chainValid: receipt.payload.previousReceiptDigest == expectedDigest,
        sequenceValid: receipt.payload.sequence == expectedSequence
      )
    }
  }
}
