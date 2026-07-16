import CryptoKit
import Foundation
import Security

public enum AgentBinaryTrust: String, Codable, Sendable {
  case verifiedPublisher = "verified_publisher"
  case validAdHocSignature = "valid_ad_hoc_signature"
  case unsigned
  case invalidSignature = "invalid_signature"
  case unavailable
}

public struct AgentBinaryIdentity: Codable, Equatable, Identifiable, Sendable {
  public let product: AgentProduct
  public let path: String?
  public let trust: AgentBinaryTrust
  public let signingIdentifier: String?
  public let teamIdentifier: String?
  public let cdHash: String?
  public let contentDigest: String?
  public let modifiedAt: String?

  public var id: String { product.id }

  public init(
    product: AgentProduct,
    path: String?,
    trust: AgentBinaryTrust,
    signingIdentifier: String?,
    teamIdentifier: String?,
    cdHash: String?,
    contentDigest: String?,
    modifiedAt: String?
  ) {
    self.product = product
    self.path = path
    self.trust = trust
    self.signingIdentifier = signingIdentifier
    self.teamIdentifier = teamIdentifier
    self.cdHash = cdHash
    self.contentDigest = contentDigest
    self.modifiedAt = modifiedAt
  }
}

public enum AgentBinaryAttestor {
  public static func inspect(
    product: AgentProduct,
    executableURL: URL?
  ) -> AgentBinaryIdentity {
    guard let executableURL else {
      return AgentBinaryIdentity(
        product: product,
        path: nil,
        trust: .unavailable,
        signingIdentifier: nil,
        teamIdentifier: nil,
        cdHash: nil,
        contentDigest: nil,
        modifiedAt: nil
      )
    }

    let attributes = try? FileManager.default.attributesOfItem(atPath: executableURL.path)
    let modifiedAt = (attributes?[.modificationDate] as? Date).map(ReceiptDate.string)
    let contentDigest: String?
    if let type = attributes?[.type] as? FileAttributeType, type == .typeRegular,
      let data = try? Data(contentsOf: executableURL, options: [.mappedIfSafe])
    {
      contentDigest = "sha256:" + SHA256Digest.hex(data)
    } else {
      contentDigest = nil
    }

    var staticCode: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(
      executableURL as CFURL, SecCSFlags(), &staticCode)
    guard createStatus == errSecSuccess, let staticCode else {
      return AgentBinaryIdentity(
        product: product,
        path: executableURL.path,
        trust: createStatus == errSecCSUnsigned ? .unsigned : .invalidSignature,
        signingIdentifier: nil,
        teamIdentifier: nil,
        cdHash: nil,
        contentDigest: contentDigest,
        modifiedAt: modifiedAt
      )
    }

    let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
    let validity = SecStaticCodeCheckValidity(staticCode, flags, nil)
    var rawInformation: CFDictionary?
    let informationStatus = SecCodeCopySigningInformation(
      staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &rawInformation)
    let information = informationStatus == errSecSuccess
      ? rawInformation as? [String: Any]
      : nil
    let signingIdentifier = information?[kSecCodeInfoIdentifier as String] as? String
    let teamIdentifier = information?[kSecCodeInfoTeamIdentifier as String] as? String
    let cdHashData = information?[kSecCodeInfoUnique as String] as? Data
    let trust: AgentBinaryTrust
    if validity == errSecSuccess {
      trust = teamIdentifier == nil ? .validAdHocSignature : .verifiedPublisher
    } else if validity == errSecCSUnsigned {
      trust = .unsigned
    } else {
      trust = .invalidSignature
    }

    return AgentBinaryIdentity(
      product: product,
      path: executableURL.path,
      trust: trust,
      signingIdentifier: signingIdentifier,
      teamIdentifier: teamIdentifier,
      cdHash: cdHashData.map { "sha256:" + $0.map { String(format: "%02x", $0) }.joined() },
      contentDigest: contentDigest,
      modifiedAt: modifiedAt
    )
  }
}

public struct AgentBinaryBaseline: Codable, Equatable, Sendable {
  public let schemaVersion: String
  public let capturedAt: String
  public let identities: [AgentBinaryIdentity]

  public init(
    schemaVersion: String = "cerebro.agent-binary-baseline.v1",
    capturedAt: String,
    identities: [AgentBinaryIdentity]
  ) {
    self.schemaVersion = schemaVersion
    self.capturedAt = capturedAt
    self.identities = identities
  }
}

public enum AgentBinaryDrift: Equatable, Sendable {
  case unchanged
  case firstObservation
  case changed(previous: AgentBinaryIdentity, current: AgentBinaryIdentity)
}

public enum AgentBinaryBaselineComparator {
  public static func compare(
    current: [AgentBinaryIdentity],
    previous: AgentBinaryBaseline?
  ) -> [AgentProduct: AgentBinaryDrift] {
    let old = Dictionary(uniqueKeysWithValues: (previous?.identities ?? []).map { ($0.product, $0) })
    return Dictionary(uniqueKeysWithValues: current.map { identity in
      guard let prior = old[identity.product] else {
        return (identity.product, .firstObservation)
      }
      let same = prior.path == identity.path
        && prior.teamIdentifier == identity.teamIdentifier
        && prior.signingIdentifier == identity.signingIdentifier
        && prior.cdHash == identity.cdHash
        && prior.contentDigest == identity.contentDigest
      return (identity.product, same ? .unchanged : .changed(previous: prior, current: identity))
    })
  }
}
