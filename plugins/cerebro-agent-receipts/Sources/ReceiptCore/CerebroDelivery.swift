import CryptoKit
import Foundation
import Security

public struct CerebroDeliveryConfiguration: Sendable {
  public let baseURL: URL
  public let hardwareUUID: String

  public init(baseURL: URL, hardwareUUID: String) {
    self.baseURL = baseURL
    self.hardwareUUID = hardwareUUID
  }
}

public struct CerebroDeviceCredential: Codable, Equatable, Sendable {
  public let baseURL: String
  public let hardwareUUID: String
  public let serverDeviceID: String
  public let refreshToken: String
  public let refreshExpiresAt: String

  public init(
    baseURL: String,
    hardwareUUID: String,
    serverDeviceID: String,
    refreshToken: String,
    refreshExpiresAt: String
  ) {
    self.baseURL = baseURL
    self.hardwareUUID = hardwareUUID
    self.serverDeviceID = serverDeviceID
    self.refreshToken = refreshToken
    self.refreshExpiresAt = refreshExpiresAt
  }
}

public protocol CerebroCredentialStoring: Sendable {
  func load() throws -> CerebroDeviceCredential?
  func save(_ credential: CerebroDeviceCredential) throws
  func remove() throws
}

public struct KeychainCerebroCredentialStore: CerebroCredentialStoring {
  private static let service = "com.writer.cerebro.agent-receipts.delivery"
  private static let account = "device-refresh.v1"

  public init() {}

  public func load() throws -> CerebroDeviceCredential? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = item as? Data else {
      throw SigningError.keychain(status)
    }
    return try JSONDecoder().decode(CerebroDeviceCredential.self, from: data)
  }

  public func save(_ credential: CerebroDeviceCredential) throws {
    let data = try CanonicalJSON.encode(credential)
    let identity: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
    ]
    let update: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let status = SecItemUpdate(identity as CFDictionary, update as CFDictionary)
    if status == errSecSuccess { return }
    guard status == errSecItemNotFound else { throw SigningError.keychain(status) }
    var add = identity
    add.merge(update) { _, replacement in replacement }
    let addStatus = SecItemAdd(add as CFDictionary, nil)
    guard addStatus == errSecSuccess else { throw SigningError.keychain(addStatus) }
  }

  public func remove() throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw SigningError.keychain(status)
    }
  }
}

public struct CerebroHTTPResponse: Sendable {
  public let statusCode: Int
  public let body: Data

  public init(statusCode: Int, body: Data) {
    self.statusCode = statusCode
    self.body = body
  }
}

public protocol CerebroHTTPPerforming: Sendable {
  func perform(_ request: URLRequest) throws -> CerebroHTTPResponse
}

public final class EphemeralCerebroHTTPClient: CerebroHTTPPerforming, @unchecked Sendable {
  private let session: URLSession

  public init(timeout: TimeInterval = 15) {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    configuration.urlCache = nil
    configuration.urlCredentialStorage = nil
    configuration.httpCookieStorage = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    session = URLSession(configuration: configuration)
  }

  public func perform(_ request: URLRequest) throws -> CerebroHTTPResponse {
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var captured: Result<CerebroHTTPResponse, Error>?
    session.dataTask(with: request) { data, response, error in
      let result: Result<CerebroHTTPResponse, Error>
      if let error {
        result = .failure(error)
      } else if let http = response as? HTTPURLResponse {
        result = .success(CerebroHTTPResponse(statusCode: http.statusCode, body: data ?? Data()))
      } else {
        result = .failure(CerebroDeliveryError.invalidHTTPResponse)
      }
      lock.lock()
      captured = result
      lock.unlock()
      semaphore.signal()
    }.resume()
    semaphore.wait()
    lock.lock()
    defer { lock.unlock() }
    guard let captured else { throw CerebroDeliveryError.invalidHTTPResponse }
    return try captured.get()
  }
}

public struct CerebroDeliveryCursor: Codable, Equatable, Sendable {
  public let schemaVersion: String
  public let serverDeviceID: String
  public let signingDeviceID: String
  public let lastSequence: UInt64
  public let lastReceiptID: String
  public let lastReceiptDigest: String

  public init(
    schemaVersion: String = "cerebro.receipt-delivery-cursor.v1",
    serverDeviceID: String,
    signingDeviceID: String,
    lastSequence: UInt64,
    lastReceiptID: String,
    lastReceiptDigest: String
  ) {
    self.schemaVersion = schemaVersion
    self.serverDeviceID = serverDeviceID
    self.signingDeviceID = signingDeviceID
    self.lastSequence = lastSequence
    self.lastReceiptID = lastReceiptID
    self.lastReceiptDigest = lastReceiptDigest
  }
}

public protocol CerebroCursorStoring: Sendable {
  func load() throws -> CerebroDeliveryCursor?
  func save(_ cursor: CerebroDeliveryCursor) throws
}

public struct FileCerebroCursorStore: CerebroCursorStoring {
  public let url: URL

  public init(url: URL) { self.url = url }

  public func load() throws -> CerebroDeliveryCursor? {
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    return try JSONDecoder().decode(CerebroDeliveryCursor.self, from: Data(contentsOf: url))
  }

  public func save(_ cursor: CerebroDeliveryCursor) throws {
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    try CanonicalJSON.encode(cursor).write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.synchronize()
  }
}

public enum CerebroDeliveryStateCode: String, Codable, Sendable {
  case notEnrolled = "not_enrolled"
  case delivering
  case queued
  case idle
  case accepted
  case retryableFailure = "retryable_failure"
  case blocked
}

public struct CerebroDeliveryState: Codable, Equatable, Sendable {
  public let schemaVersion: String
  public let state: CerebroDeliveryStateCode
  public let pendingReceipts: Int?
  public let lastAcknowledgedSequence: UInt64?
  public let lastAttemptAt: String?
  public let lastAcceptedAt: String?
  public let errorCode: String?

  public init(
    state: CerebroDeliveryStateCode,
    pendingReceipts: Int?,
    lastAcknowledgedSequence: UInt64?,
    lastAttemptAt: String?,
    lastAcceptedAt: String?,
    errorCode: String?
  ) {
    schemaVersion = "cerebro.receipt-delivery-state.v1"
    self.state = state
    self.pendingReceipts = pendingReceipts
    self.lastAcknowledgedSequence = lastAcknowledgedSequence
    self.lastAttemptAt = lastAttemptAt
    self.lastAcceptedAt = lastAcceptedAt
    self.errorCode = errorCode
  }
}

public protocol CerebroDeliveryStateStoring: Sendable {
  func save(_ state: CerebroDeliveryState) throws
}

public struct FileCerebroDeliveryStateStore: CerebroDeliveryStateStoring {
  public let url: URL
  public init(url: URL) { self.url = url }

  public func save(_ state: CerebroDeliveryState) throws {
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    // Remove the prior result first so a failed write cannot leave an old
    // accepted state visible. Missing state is rendered as unhealthy.
    if FileManager.default.fileExists(atPath: url.path) {
      try FileManager.default.removeItem(at: url)
    }
    try CanonicalJSON.encode(state).write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
  }
}

public enum CerebroDeliveryError: Error {
  case invalidHTTPResponse
  case invalidTokenResponse
  case telemetryScopeMissing
  case cursorMismatch
  case credentialBindingMismatch
  case invalidEnrollmentResponse
  case deliveryInProgress
  case serverRejected(Int)
  case acceptedResponseInvalid
}

extension CerebroDeliveryError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .invalidHTTPResponse: return "Cerebro returned an invalid HTTP response."
    case .invalidTokenResponse: return "Cerebro returned an invalid device token response."
    case .telemetryScopeMissing: return "Cerebro did not grant receipt delivery access."
    case .cursorMismatch: return "The delivery cursor does not match the verified local ledger."
    case .credentialBindingMismatch:
      return "The stored device credential belongs to another server or hardware identity."
    case .invalidEnrollmentResponse: return "Cerebro returned an invalid enrollment response."
    case .deliveryInProgress: return "A receipt delivery operation is already running."
    case .serverRejected(let status): return "Cerebro rejected the request with HTTP \(status)."
    case .acceptedResponseInvalid: return "Cerebro did not return a valid receipt acceptance."
    }
  }
}

public final class CerebroDeliveryEngine: @unchecked Sendable {
  private struct AccessToken {
    let value: String
    let expiresAt: Date
  }

  private struct VerifiedDeliveryPosition {
    let credential: CerebroDeviceCredential?
    let cursor: CerebroDeliveryCursor?
    let pending: [ExecutionReceipt]
  }

  private let configuration: CerebroDeliveryConfiguration
  private let store: ReceiptStore
  private let signer: DeviceKeySigner
  private let credentials: any CerebroCredentialStoring
  private let cursorStore: any CerebroCursorStoring
  private let stateStore: any CerebroDeliveryStateStoring
  private let http: any CerebroHTTPPerforming
  private let now: @Sendable () -> Date
  private let deliveryLock = NSLock()
  private let stateHealthLock = NSLock()
  private var accessToken: AccessToken?
  private var stateStorageHealthy = true

  public init(
    configuration: CerebroDeliveryConfiguration,
    store: ReceiptStore,
    signer: DeviceKeySigner,
    credentials: any CerebroCredentialStoring = KeychainCerebroCredentialStore(),
    cursorStore: any CerebroCursorStoring,
    stateStore: any CerebroDeliveryStateStoring,
    http: any CerebroHTTPPerforming = EphemeralCerebroHTTPClient(),
    now: @escaping @Sendable () -> Date = { Date() }
  ) {
    self.configuration = configuration
    self.store = store
    self.signer = signer
    self.credentials = credentials
    self.cursorStore = cursorStore
    self.stateStore = stateStore
    self.http = http
    self.now = now
  }

  public var deliveryStateStorageHealthy: Bool {
    stateHealthLock.lock()
    defer { stateHealthLock.unlock() }
    return stateStorageHealthy
  }

  /// Delivers at most one receipt. The shield agent calls this on its existing
  /// maintenance cadence; one-at-a-time delivery keeps acknowledgement and
  /// idempotency semantics explicit.
  public func deliverOnce() {
    guard deliveryLock.try() else { return }
    defer { deliveryLock.unlock() }
    let attemptedAt = ReceiptDate.string(from: now())
    do {
      let position = try verifiedDeliveryPosition()
      guard let credential = position.credential else {
        try saveCurrentState(
          .notEnrolled,
          attemptedAt: attemptedAt,
          error: nil)
        return
      }
      // Do not make a network request unless the UI-visible attempt marker is
      // durable. This turns local state-storage failure into fail-closed
      // delivery rather than a stale accepted result.
      try saveState(
        .delivering,
        pending: position.pending.count,
        cursor: position.cursor,
        attemptedAt: attemptedAt,
        error: nil)
      guard let receipt = position.pending.first else {
        try saveCurrentState(.idle, attemptedAt: attemptedAt, error: nil)
        return
      }
      let token = try validAccessToken(credential: credential)
      let requestBody = try telemetryBody(for: receipt)
      let digest = try CanonicalJSON.digest(receipt)
      let idempotencyKey = "agent-receipt-v1:\(receipt.payload.sequence):\(digest)"
      let ingestURL = endpoint("platform/telemetry/ingest")
      var request = URLRequest(url: ingestURL)
      request.httpMethod = "POST"
      request.httpBody = requestBody
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.setValue("Bearer \(token.value)", forHTTPHeaderField: "Authorization")
      request.setValue(idempotencyKey, forHTTPHeaderField: "Idempotency-Key")
      request.setValue(
        try dpopProof(method: "POST", url: ingestURL, accessToken: token.value),
        forHTTPHeaderField: "DPoP")
      let response = try http.perform(request)
      guard response.statusCode == 202 else {
        if response.statusCode == 401 { accessToken = nil }
        throw CerebroDeliveryError.serverRejected(response.statusCode)
      }
      struct Accepted: Decodable { let status: String; let device_id: String }
      guard
        let accepted = try? JSONDecoder().decode(Accepted.self, from: response.body),
        accepted.status == "accepted",
        accepted.device_id == credential.serverDeviceID
      else { throw CerebroDeliveryError.acceptedResponseInvalid }
      let nextCursor = CerebroDeliveryCursor(
        serverDeviceID: credential.serverDeviceID,
        signingDeviceID: receipt.payload.deviceID,
        lastSequence: receipt.payload.sequence,
        lastReceiptID: receipt.id,
        lastReceiptDigest: digest)
      try cursorStore.save(nextCursor)
      try saveCurrentState(
        .accepted,
        attemptedAt: attemptedAt,
        acceptedAt: ReceiptDate.string(from: now()),
        error: nil)
    } catch {
      let deliveryError = error
      let retryable = isRetryable(deliveryError)
      do {
        try saveCurrentState(
          retryable ? .retryableFailure : .blocked,
          attemptedAt: attemptedAt,
          error: errorCode(deliveryError))
      } catch {
        // The delivery position could not be verified, or the transactional
        // status write failed. Persist only an explicit unknown-count block;
        // if that also fails, storage health remains false over XPC.
        try? saveState(
          .blocked,
          pending: nil,
          cursor: nil,
          attemptedAt: attemptedAt,
          error: errorCode(deliveryError))
      }
    }
  }

  /// Consumes a one-time bootstrap token supplied over an authenticated local
  /// channel. The token is held only for this call and is never written to a
  /// managed preference, cursor, state file, or log.
  public func enroll(bootstrapToken: String) throws {
    guard deliveryLock.try() else { throw CerebroDeliveryError.deliveryInProgress }
    defer { deliveryLock.unlock() }
    let token = bootstrapToken.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !token.isEmpty else { throw CerebroDeliveryError.invalidEnrollmentResponse }
    struct EnrollmentBody: Encodable {
      let bootstrap_token: String
      let hardware_uuid: String
      let hostname: String
      let os_type = "macos"
      let os_version: String
      let agent_version = "cerebro-agent-receipts"
      let device_key: [String: String]
    }
    let enrollURL = endpoint("platform/devices/enroll")
    var request = URLRequest(url: enrollURL)
    request.httpMethod = "POST"
    request.httpBody = try CanonicalJSON.encode(EnrollmentBody(
      bootstrap_token: token,
      hardware_uuid: configuration.hardwareUUID,
      hostname: Host.current().localizedName ?? "",
      os_version: ProcessInfo.processInfo.operatingSystemVersionString,
      device_key: signer.dpopJWK))
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    let response = try http.perform(request)
    guard response.statusCode == 200 else {
      throw CerebroDeliveryError.serverRejected(response.statusCode)
    }
    struct EnrollmentResponse: Decodable {
      let access_token: String
      let token_type: String
      let expires_in: Int
      let refresh_token: String
      let refresh_expires_at: String
      let scopes: [String]
      let device_id: String
    }
    guard
      let enrolled = try? JSONDecoder().decode(EnrollmentResponse.self, from: response.body),
      enrolled.token_type == "Bearer",
      enrolled.expires_in > 0,
      !enrolled.access_token.isEmpty,
      !enrolled.refresh_token.isEmpty,
      !enrolled.device_id.isEmpty,
      enrolled.scopes.contains("platform.telemetry.ingest")
    else { throw CerebroDeliveryError.invalidEnrollmentResponse }
    let credential = CerebroDeviceCredential(
      baseURL: configuration.baseURL.absoluteString,
      hardwareUUID: configuration.hardwareUUID,
      serverDeviceID: enrolled.device_id,
      refreshToken: enrolled.refresh_token,
      refreshExpiresAt: enrolled.refresh_expires_at)
    do {
      try credentials.save(credential)
    } catch {
      try? credentials.remove()
      throw error
    }
    accessToken = AccessToken(
      value: enrolled.access_token,
      expiresAt: now().addingTimeInterval(TimeInterval(enrolled.expires_in)))
    do {
      try saveCurrentState(.idle, attemptedAt: ReceiptDate.string(from: now()), error: nil)
    } catch {
      try saveState(
        .blocked,
        pending: nil,
        cursor: nil,
        attemptedAt: ReceiptDate.string(from: now()),
        error: errorCode(error))
    }
  }

  private func pendingReceipts(
    _ receipts: [ExecutionReceipt], cursor: CerebroDeliveryCursor?
  ) throws -> [ExecutionReceipt] {
    guard let cursor else { return receipts }
    guard cursor.schemaVersion == "cerebro.receipt-delivery-cursor.v1" else {
      throw CerebroDeliveryError.cursorMismatch
    }
    guard cursor.lastSequence <= UInt64(receipts.count), cursor.lastSequence > 0 else {
      throw CerebroDeliveryError.cursorMismatch
    }
    let acknowledged = receipts[Int(cursor.lastSequence - 1)]
    guard
      acknowledged.payload.sequence == cursor.lastSequence,
      acknowledged.id == cursor.lastReceiptID,
      acknowledged.payload.deviceID == cursor.signingDeviceID,
      try CanonicalJSON.digest(acknowledged) == cursor.lastReceiptDigest
    else { throw CerebroDeliveryError.cursorMismatch }
    return Array(receipts.dropFirst(Int(cursor.lastSequence)))
  }

  private func verifiedDeliveryPosition() throws -> VerifiedDeliveryPosition {
    try verifiedDeliveryPosition(receipts: store.readVerifiedReceipts())
  }

  private func verifiedDeliveryPosition(
    receipts: [ExecutionReceipt]
  ) throws -> VerifiedDeliveryPosition {
    let cursor = try cursorStore.load()
    let credential = try credentials.load()
    guard let credential else {
      guard cursor == nil else { throw CerebroDeliveryError.cursorMismatch }
      return VerifiedDeliveryPosition(credential: nil, cursor: nil, pending: receipts)
    }
    guard
      credential.baseURL == configuration.baseURL.absoluteString,
      credential.hardwareUUID == configuration.hardwareUUID
    else { throw CerebroDeliveryError.credentialBindingMismatch }
    if let cursor, cursor.serverDeviceID != credential.serverDeviceID {
      throw CerebroDeliveryError.cursorMismatch
    }
    return VerifiedDeliveryPosition(
      credential: credential,
      cursor: cursor,
      pending: try pendingReceipts(receipts, cursor: cursor))
  }

  private func saveCurrentState(
    _ requestedState: CerebroDeliveryStateCode,
    attemptedAt: String,
    acceptedAt: String? = nil,
    error: String?
  ) throws {
    try store.withVerifiedReceipts { receipts in
      let position = try verifiedDeliveryPosition(receipts: receipts)
      let state =
        requestedState == .idle && !position.pending.isEmpty ? .queued : requestedState
      try saveState(
        state,
        pending: position.pending.count,
        cursor: position.cursor,
        attemptedAt: attemptedAt,
        acceptedAt: acceptedAt,
        error: error)
    }
  }

  private func validAccessToken(credential: CerebroDeviceCredential) throws -> AccessToken {
    if let accessToken, accessToken.expiresAt.timeIntervalSince(now()) > 60 { return accessToken }
    let tokenURL = endpoint("platform/devices/token")
    struct RefreshBody: Encodable { let grant_type = "refresh_token"; let refresh_token: String }
    var request = URLRequest(url: tokenURL)
    request.httpMethod = "POST"
    request.httpBody = try CanonicalJSON.encode(RefreshBody(refresh_token: credential.refreshToken))
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(try dpopProof(method: "POST", url: tokenURL, accessToken: nil), forHTTPHeaderField: "DPoP")
    let response = try http.perform(request)
    guard response.statusCode == 200 else { throw CerebroDeliveryError.serverRejected(response.statusCode) }
    struct TokenResponse: Decodable {
      let access_token: String
      let token_type: String
      let expires_in: Int
      let refresh_token: String
      let refresh_expires_at: String
      let scopes: [String]
    }
    guard
      let token = try? JSONDecoder().decode(TokenResponse.self, from: response.body),
      !token.access_token.isEmpty,
      !token.refresh_token.isEmpty,
      token.token_type == "Bearer",
      token.expires_in > 0
    else { throw CerebroDeliveryError.invalidTokenResponse }
    let rotated = CerebroDeviceCredential(
      baseURL: credential.baseURL,
      hardwareUUID: credential.hardwareUUID,
      serverDeviceID: credential.serverDeviceID,
      refreshToken: token.refresh_token,
      refreshExpiresAt: token.refresh_expires_at)
    // A rotated refresh token is single-use. Persist it before exposing the
    // corresponding access token to the uploader; failure must not reuse the
    // consumed credential or report successful delivery.
    do {
      try credentials.save(rotated)
    } catch {
      // The previous token has already been consumed. Do not leave it available
      // for a replay that would revoke the server-side refresh family.
      try? credentials.remove()
      throw error
    }
    guard token.scopes.contains("platform.telemetry.ingest") else {
      throw CerebroDeliveryError.telemetryScopeMissing
    }
    let access = AccessToken(value: token.access_token, expiresAt: now().addingTimeInterval(TimeInterval(token.expires_in)))
    accessToken = access
    return access
  }

  private func telemetryBody(for receipt: ExecutionReceipt) throws -> Data {
    struct Event: Encodable {
      let type = "agent_execution_receipt"
      let receipt_id: String
      let receipt_digest: String
      let sequence: UInt64
      let previous_receipt_digest: String?
      let captured_at: String
      let phase: String
      let agent_product: String
      let model: String
      let session_id: String
      let turn_id: String?
      let tool_call_id: String?
      let tool_name: String?
      let action_summary: String
      let permission_mode: String?
      let local_user_claim: String
      let local_user_claim_source: String
      let evidence_integrity = "local_signature_chain_valid"
    }
    struct Batch: Encodable { let events: [Event] }
    let payload = receipt.payload
    return try CanonicalJSON.encode(Batch(events: [Event(
      receipt_id: receipt.id,
      receipt_digest: try CanonicalJSON.digest(receipt),
      sequence: payload.sequence,
      previous_receipt_digest: payload.previousReceiptDigest,
      captured_at: payload.capturedAt,
      phase: payload.phase.rawValue,
      agent_product: payload.agent.product,
      model: payload.agent.model,
      session_id: payload.agent.sessionID,
      turn_id: payload.agent.turnID,
      tool_call_id: payload.agent.toolCallID,
      tool_name: payload.toolName,
      action_summary: payload.actionSummary,
      permission_mode: payload.permissionMode,
      local_user_claim: payload.localUserClaim,
      local_user_claim_source: payload.localUserClaimSource)]))
  }

  private func dpopProof(method: String, url: URL, accessToken: String?) throws -> String {
    struct Header: Encodable { let alg = "ES256"; let jwk: [String: String]; let typ = "dpop+jwt" }
    struct Payload: Encodable {
      let ath: String?
      let htm: String
      let htu: String
      let iat: Int64
      let jti: String
    }
    let ath = accessToken.map { token -> String in
      Data(SHA256.hash(data: Data(token.utf8))).base64URLString
    }
    let header = try CanonicalJSON.encode(Header(jwk: signer.dpopJWK)).base64URLString
    let payload = try CanonicalJSON.encode(Payload(
      ath: ath,
      htm: method,
      htu: url.absoluteString,
      iat: Int64(now().timeIntervalSince1970),
      jti: UUID().uuidString.lowercased())).base64URLString
    let input = Data("\(header).\(payload)".utf8)
    let signature = try signer.signDPoP(input).base64URLString
    return "\(header).\(payload).\(signature)"
  }

  private func endpoint(_ path: String) -> URL {
    configuration.baseURL.appendingPathComponent(path)
  }

  private func saveState(
    _ state: CerebroDeliveryStateCode,
    pending: Int?,
    cursor: CerebroDeliveryCursor?,
    attemptedAt: String,
    acceptedAt: String? = nil,
    error: String?
  ) throws {
    let snapshot = CerebroDeliveryState(
      state: state,
      pendingReceipts: pending.map { max(0, $0) },
      lastAcknowledgedSequence: cursor?.lastSequence,
      lastAttemptAt: attemptedAt,
      lastAcceptedAt: acceptedAt,
      errorCode: error)
    do {
      try stateStore.save(snapshot)
      stateHealthLock.lock()
      stateStorageHealthy = true
      stateHealthLock.unlock()
    } catch {
      stateHealthLock.lock()
      stateStorageHealthy = false
      stateHealthLock.unlock()
      throw error
    }
  }

  private func isRetryable(_ error: Error) -> Bool {
    if error is URLError { return true }
    if case CerebroDeliveryError.serverRejected(let status) = error {
      return status == 408 || status == 429 || status >= 500
    }
    return false
  }

  private func errorCode(_ error: Error) -> String {
    if error is URLError { return "network_unavailable" }
    switch error {
    case CerebroDeliveryError.invalidHTTPResponse: return "invalid_http_response"
    case CerebroDeliveryError.invalidTokenResponse: return "invalid_token_response"
    case CerebroDeliveryError.telemetryScopeMissing: return "telemetry_scope_missing"
    case CerebroDeliveryError.cursorMismatch: return "cursor_mismatch"
    case CerebroDeliveryError.credentialBindingMismatch: return "credential_binding_mismatch"
    case CerebroDeliveryError.invalidEnrollmentResponse: return "invalid_enrollment_response"
    case CerebroDeliveryError.deliveryInProgress: return "delivery_in_progress"
    case CerebroDeliveryError.serverRejected(let status): return "server_rejected_\(status)"
    case CerebroDeliveryError.acceptedResponseInvalid: return "accepted_response_invalid"
    default: return "local_delivery_error"
    }
  }
}

extension Data {
  fileprivate var base64URLString: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
