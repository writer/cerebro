import CryptoKit
import Foundation
import Security

public enum SHA256Digest {
  public static func hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
}

public protocol ReceiptSigning: Sendable {
  var deviceID: String { get }
  var publicKeyBase64: String { get }
  var hardwareBacked: Bool { get }
  func sign(_ data: Data) throws -> Data
}

public enum SigningError: Error, LocalizedError {
  case keychain(OSStatus)
  case keyFilePermissions
  case invalidStoredKey
  case invalidSignature

  public var errorDescription: String? {
    switch self {
    case .keychain(let status): return "Keychain operation failed with status \(status)."
    case .keyFilePermissions:
      return "The development signing key must be a regular file owned by this user with mode 0600."
    case .invalidStoredKey: return "The stored receipt signing key is invalid."
    case .invalidSignature: return "The receipt signature could not be decoded."
    }
  }
}

public struct DeviceKeySigner: ReceiptSigning {
  private static let service = "com.writer.cerebro.agent-receipts"
  private let material: P256.Signing.PrivateKey

  public let hardwareBacked = false

  public init(keyAccount: String = "device-signing-key.v1") throws {
    if let data = try Self.loadKey(account: keyAccount) {
      guard let material = try? P256.Signing.PrivateKey(rawRepresentation: data) else {
        throw SigningError.invalidStoredKey
      }
      self.material = material
    } else {
      let generated = P256.Signing.PrivateKey()
      if try Self.storeKey(generated.rawRepresentation, account: keyAccount) {
        self.material = generated
      } else if let winningData = try Self.loadKey(account: keyAccount),
        let winningKey = try? P256.Signing.PrivateKey(rawRepresentation: winningData)
      {
        self.material = winningKey
      } else {
        throw SigningError.invalidStoredKey
      }
    }
  }

  public init(rawKey: Data) throws {
    self.material = try P256.Signing.PrivateKey(rawRepresentation: rawKey)
  }

  /// Development-only storage for ad-hoc builds whose changing CDHash cannot retain Keychain ACLs.
  /// Managed builds must use the Keychain initializer above with a stable signing identity.
  public init(developmentKeyFileURL url: URL) throws {
    let manager = FileManager.default
    if manager.fileExists(atPath: url.path) {
      var status = stat()
      guard
        lstat(url.path, &status) == 0,
        status.st_mode & S_IFMT == S_IFREG,
        status.st_uid == geteuid(),
        status.st_mode & 0o077 == 0
      else { throw SigningError.keyFilePermissions }
      self.material = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: url))
      return
    }

    try manager.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let generated = P256.Signing.PrivateKey()
    try generated.rawRepresentation.write(to: url, options: .atomic)
    try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    self.material = generated
  }

  public var publicKeyBase64: String {
    material.publicKey.x963Representation.base64EncodedString()
  }

  public var deviceID: String {
    "sha256:" + SHA256Digest.hex(material.publicKey.x963Representation)
  }

  public static func deviceID(publicKeyBase64: String) -> String? {
    guard
      let publicData = Data(base64Encoded: publicKeyBase64),
      (try? P256.Signing.PublicKey(x963Representation: publicData)) != nil
    else { return nil }
    return "sha256:" + SHA256Digest.hex(publicData)
  }

  public func sign(_ data: Data) throws -> Data {
    try material.signature(for: data).derRepresentation
  }

  /// Public key representation accepted by Cerebro's RFC 9449 DPoP verifier.
  /// Receipt signatures remain DER encoded; DPoP JWS signatures use the fixed
  /// width IEEE P1363 representation required by ES256.
  public var dpopJWK: [String: String] {
    let raw = material.publicKey.x963Representation
    precondition(raw.count == 65 && raw.first == 0x04)
    return [
      "kty": "EC",
      "crv": "P-256",
      "x": Data(raw[1..<33]).base64URLEncodedString(),
      "y": Data(raw[33..<65]).base64URLEncodedString(),
    ]
  }

  public func signDPoP(_ signingInput: Data) throws -> Data {
    try material.signature(for: signingInput).rawRepresentation
  }

  public static func verify(_ receipt: ExecutionReceipt) -> Bool {
    guard
      receipt.signature.algorithm == "P256-SHA256",
      let publicData = Data(base64Encoded: receipt.signature.publicKey),
      let signatureData = Data(base64Encoded: receipt.signature.value),
      let publicKey = try? P256.Signing.PublicKey(x963Representation: publicData),
      let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureData),
      let payload = try? CanonicalJSON.encode(receipt.payload)
    else { return false }
    return publicKey.isValidSignature(signature, for: payload)
  }

  private static func loadKey(account: String) throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw SigningError.keychain(status) }
    return result as? Data
  }

  private static func storeKey(_ data: Data, account: String) throws -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: data,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecSuccess { return true }
    if status == errSecDuplicateItem { return false }
    throw SigningError.keychain(status)
  }
}

extension Data {
  fileprivate func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
