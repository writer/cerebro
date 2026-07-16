import CryptoKit
import Darwin
import Foundation

public enum ShieldAdminRole: String, Codable, Sendable {
  case read = "shield.read"
  case repair = "shield.repair"
  case policyOverride = "shield.policy.override"
  case export = "shield.export"
}

public enum ShieldAdminOperation: String, Codable, Sendable {
  case readDeviceStatus = "shield.device.read"
  case repairAdapters = "shield.adapters.repair"
  case exportReceipts = "shield.receipts.export"
  case overridePolicy = "shield.policy.override"
}

public struct ShieldAdminCapabilityRequest: Equatable, Sendable {
  public let operation: ShieldAdminOperation
  public let target: String

  public init(operation: ShieldAdminOperation, target: String) {
    self.operation = operation
    self.target = target
  }

  public static func device(operation: ShieldAdminOperation, deviceID: String)
    -> ShieldAdminCapabilityRequest
  {
    ShieldAdminCapabilityRequest(operation: operation, target: "device:\(deviceID)")
  }
}

public struct ShieldAdminCapabilityPayload: Codable, Equatable, Sendable {
  public let schemaVersion: String
  public let organizationID: String
  public let subject: String
  public let deviceID: String
  public let roles: [ShieldAdminRole]
  public let operation: ShieldAdminOperation
  public let target: String
  public let requestID: String
  public let issuedAt: String
  public let expiresAt: String

  public init(
    schemaVersion: String = "cerebro.shield-admin-capability.v2",
    organizationID: String,
    subject: String,
    deviceID: String,
    roles: [ShieldAdminRole],
    operation: ShieldAdminOperation,
    target: String,
    requestID: String,
    issuedAt: String,
    expiresAt: String
  ) {
    self.schemaVersion = schemaVersion
    self.organizationID = organizationID
    self.subject = subject
    self.deviceID = deviceID
    self.roles = roles
    self.operation = operation
    self.target = target
    self.requestID = requestID
    self.issuedAt = issuedAt
    self.expiresAt = expiresAt
  }
}

public struct SignedShieldAdminCapability: Codable, Equatable, Sendable {
  public let algorithm: String
  public let payload: ShieldAdminCapabilityPayload
  public let signature: String

  public init(
    algorithm: String = "P256-SHA256",
    payload: ShieldAdminCapabilityPayload,
    signature: String
  ) {
    self.algorithm = algorithm
    self.payload = payload
    self.signature = signature
  }
}

public enum ShieldAdminAccess: Equatable, Sendable {
  case unavailable
  case authorized(ShieldAdminCapabilityPayload)
  case denied(String)

  public var isAuthorized: Bool {
    if case .authorized = self { return true }
    return false
  }

  public var subject: String? {
    guard case .authorized(let capability) = self else { return nil }
    return capability.subject
  }
}

public enum ShieldAdminCapabilityVerifier {
  public static func verify(
    _ capability: SignedShieldAdminCapability,
    organizationPublicKeyBase64: String,
    expectedDeviceID: String,
    expectedRequest: ShieldAdminCapabilityRequest,
    requiredRole: ShieldAdminRole = .read,
    now: Date = Date()
  ) -> ShieldAdminAccess {
    guard capability.algorithm == "P256-SHA256" else {
      return .denied("The organization capability uses an unsupported signature algorithm.")
    }
    guard capability.payload.schemaVersion == "cerebro.shield-admin-capability.v2" else {
      return .denied("The organization capability schema is not supported.")
    }
    guard capability.payload.deviceID == expectedDeviceID else {
      return .denied("The organization capability was issued to another device.")
    }
    guard capability.payload.operation == expectedRequest.operation else {
      return .denied("The organization capability does not authorize this operation.")
    }
    guard capability.payload.target == expectedRequest.target else {
      return .denied("The organization capability does not authorize this target.")
    }
    guard !capability.payload.requestID.isEmpty else {
      return .denied("The organization capability has no grant ID.")
    }
    guard capability.payload.roles.contains(requiredRole) else {
      return .denied("The organization capability does not grant \(requiredRole.rawValue).")
    }
    guard
      let issuedAt = ReceiptDate.parse(capability.payload.issuedAt),
      let expiresAt = ReceiptDate.parse(capability.payload.expiresAt),
      issuedAt <= now.addingTimeInterval(5 * 60),
      expiresAt > now,
      expiresAt.timeIntervalSince(issuedAt) <= 60 * 60
    else {
      return .denied("The organization capability is expired or outside its allowed lifetime.")
    }
    guard
      let publicKeyData = Data(base64Encoded: organizationPublicKeyBase64),
      let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyData),
      let signatureData = Data(base64Encoded: capability.signature),
      let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureData),
      let payloadData = try? CanonicalJSON.encode(capability.payload),
      publicKey.isValidSignature(signature, for: payloadData)
    else {
      return .denied("The organization capability signature is invalid.")
    }
    return .authorized(capability.payload)
  }
}

public struct ShieldCapabilityReplayStore: Sendable {
  public let ledgerURL: URL

  public init(ledgerURL: URL) {
    self.ledgerURL = ledgerURL
  }

  public func consume(requestID: String, expiresAt: String, now: Date = Date()) throws -> Bool {
    let directory = ledgerURL.deletingLastPathComponent()
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let lockURL = directory.appendingPathComponent("capability-use.lock")
    let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw ShieldCapabilityReplayError.lockFailed(errno) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw ShieldCapabilityReplayError.lockFailed(errno)
    }
    defer { flock(descriptor, LOCK_UN) }

    let decoder = JSONDecoder()
    var ledger: [String: String] = [:]
    if FileManager.default.fileExists(atPath: ledgerURL.path) {
      do {
        ledger = try decoder.decode([String: String].self, from: Data(contentsOf: ledgerURL))
      } catch {
        throw ShieldCapabilityReplayError.invalidLedger
      }
    }
    ledger = ledger.filter { _, expiry in
      guard let date = ReceiptDate.parse(expiry) else { return false }
      return date > now
    }
    let requestDigest = SHA256Digest.hex(Data(requestID.utf8))
    guard ledger[requestDigest] == nil else { return false }
    ledger[requestDigest] = expiresAt
    let data = try JSONEncoder().encode(ledger)
    try data.write(to: ledgerURL, options: [.atomic])
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600], ofItemAtPath: ledgerURL.path)
    return true
  }
}

public enum ShieldCapabilityReplayError: Error, LocalizedError {
  case lockFailed(Int32)
  case invalidLedger

  public var errorDescription: String? {
    switch self {
    case .lockFailed(let code):
      return "Could not lock the organization capability ledger (errno \(code))."
    case .invalidLedger:
      return "The organization capability ledger is invalid."
    }
  }
}

public struct ManagedShieldConfiguration: Sendable {
  public let organizationPublicKeyBase64: String
  public let expectedTeamIdentifier: String
  public let expectedSigningIdentifier: String
  public let capabilityURL: URL
  public let autoRepair: Bool

  public init(
    organizationPublicKeyBase64: String,
    expectedTeamIdentifier: String,
    expectedSigningIdentifier: String,
    capabilityURL: URL,
    autoRepair: Bool
  ) {
    self.organizationPublicKeyBase64 = organizationPublicKeyBase64
    self.expectedTeamIdentifier = expectedTeamIdentifier
    self.expectedSigningIdentifier = expectedSigningIdentifier
    self.capabilityURL = capabilityURL
    self.autoRepair = autoRepair
  }

  public static func load(
    from url: URL = URL(
      fileURLWithPath: "/Library/Managed Preferences/com.writer.cerebro.shield.plist")
  ) throws -> ManagedShieldConfiguration? {
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
    let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0o777
    guard owner == 0, permissions & 0o022 == 0 else {
      throw ManagedShieldConfigurationError.insecureManagedConfiguration(url)
    }
    let propertyList = try PropertyListSerialization.propertyList(
      from: Data(contentsOf: url), options: [], format: nil)
    guard
      let dictionary = propertyList as? [String: Any],
      let key = dictionary["OrganizationPublicKey"] as? String,
      !key.isEmpty,
      let teamIdentifier = dictionary["ExpectedTeamIdentifier"] as? String,
      !teamIdentifier.isEmpty,
      let signingIdentifier = dictionary["ExpectedSigningIdentifier"] as? String,
      !signingIdentifier.isEmpty,
      let capabilityPath = dictionary["AdminCapabilityPath"] as? String,
      capabilityPath.hasPrefix("/")
    else {
      throw ManagedShieldConfigurationError.invalidManagedConfiguration(url)
    }
    return ManagedShieldConfiguration(
      organizationPublicKeyBase64: key,
      expectedTeamIdentifier: teamIdentifier,
      expectedSigningIdentifier: signingIdentifier,
      capabilityURL: URL(fileURLWithPath: capabilityPath),
      autoRepair: dictionary["AutoRepair"] as? Bool ?? true
    )
  }

  public func accepts(applicationIdentity: AgentBinaryIdentity) -> Bool {
    applicationIdentity.trust == .verifiedPublisher
      && applicationIdentity.teamIdentifier == expectedTeamIdentifier
      && applicationIdentity.signingIdentifier == expectedSigningIdentifier
  }
}

public enum ManagedShieldConfigurationError: Error, LocalizedError {
  case insecureManagedConfiguration(URL)
  case invalidManagedConfiguration(URL)

  public var errorDescription: String? {
    switch self {
    case .insecureManagedConfiguration(let url):
      return "The managed shield configuration is not root-owned and read-only: \(url.path)"
    case .invalidManagedConfiguration(let url):
      return "The managed shield configuration is missing required values: \(url.path)"
    }
  }
}

public enum ShieldAdminCapabilityLoader {
  public static func load(
    configuration: ManagedShieldConfiguration?,
    deviceID: String,
    request: ShieldAdminCapabilityRequest,
    requiredRole: ShieldAdminRole,
    now: Date = Date()
  ) -> ShieldAdminAccess {
    guard let configuration else { return .unavailable }
    do {
      let capability = try JSONDecoder().decode(
        SignedShieldAdminCapability.self,
        from: Data(contentsOf: configuration.capabilityURL)
      )
      return ShieldAdminCapabilityVerifier.verify(
        capability,
        organizationPublicKeyBase64: configuration.organizationPublicKeyBase64,
        expectedDeviceID: deviceID,
        expectedRequest: request,
        requiredRole: requiredRole,
        now: now
      )
    } catch {
      return .denied("No valid organization capability is available on this device.")
    }
  }

  public static func authorize(
    configuration: ManagedShieldConfiguration?,
    deviceID: String,
    request: ShieldAdminCapabilityRequest,
    requiredRole: ShieldAdminRole,
    replayStore: ShieldCapabilityReplayStore,
    now: Date = Date()
  ) -> ShieldAdminAccess {
    guard let configuration else { return .unavailable }
    do {
      let capability = try JSONDecoder().decode(
        SignedShieldAdminCapability.self,
        from: Data(contentsOf: configuration.capabilityURL)
      )
      let access = ShieldAdminCapabilityVerifier.verify(
        capability,
        organizationPublicKeyBase64: configuration.organizationPublicKeyBase64,
        expectedDeviceID: deviceID,
        expectedRequest: request,
        requiredRole: requiredRole,
        now: now
      )
      guard case .authorized(let payload) = access else { return access }
      guard
        try replayStore.consume(
          requestID: payload.requestID, expiresAt: payload.expiresAt, now: now)
      else {
        return .denied("This organization capability has already been used.")
      }
      return access
    } catch {
      return .denied("No valid organization capability is available on this device.")
    }
  }
}
