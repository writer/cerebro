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
  case invalidStoredKey
  case invalidSignature

  public var errorDescription: String? {
    switch self {
    case .keychain(let status): return "Keychain operation failed with status \(status)."
    case .invalidStoredKey: return "The stored receipt signing key is invalid."
    case .invalidSignature: return "The receipt signature could not be decoded."
    }
  }
}

public struct DeviceKeySigner: ReceiptSigning {
  private static let service = "com.writer.cerebro.agent-receipts"
  private static let account = "device-signing-key.v1"
  private let material: P256.Signing.PrivateKey

  public let hardwareBacked = false

  public init() throws {
    if let data = try Self.loadKey() {
      guard let material = try? P256.Signing.PrivateKey(rawRepresentation: data) else {
        throw SigningError.invalidStoredKey
      }
      self.material = material
    } else {
      let generated = P256.Signing.PrivateKey()
      if try Self.storeKey(generated.rawRepresentation) {
        self.material = generated
      } else if let winningData = try Self.loadKey(),
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

  public var publicKeyBase64: String {
    material.publicKey.x963Representation.base64EncodedString()
  }

  public var deviceID: String {
    "sha256:" + SHA256Digest.hex(material.publicKey.x963Representation)
  }

  public func sign(_ data: Data) throws -> Data {
    try material.signature(for: data).derRepresentation
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

  private static func loadKey() throws -> Data? {
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

  private static func storeKey(_ data: Data) throws -> Bool {
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
