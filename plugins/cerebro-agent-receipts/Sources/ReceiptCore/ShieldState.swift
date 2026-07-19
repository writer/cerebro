import Foundation

public enum ShieldLevel: String, Codable, Sendable {
  case active
  case attention
  case inactive
}

public enum ShieldTrustBoundary: String, Codable, Sendable {
  case development
  case organizationManaged = "organization_managed"
}

public enum ShieldIncidentKind: String, Codable, Sendable {
  case adapterCoverage = "adapter_coverage"
  case adapterConflict = "adapter_conflict"
  case binaryIntegrity = "binary_integrity"
  case binaryDrift = "binary_drift"
  case receiptIntegrity = "receipt_integrity"
  case backgroundService = "background_service"
}

public enum ShieldIncidentSeverity: String, Codable, Sendable {
  case notice
  case warning
  case critical
}

public struct ShieldIncident: Codable, Equatable, Identifiable, Sendable {
  public let id: String
  public let kind: ShieldIncidentKind
  public let severity: ShieldIncidentSeverity
  public let product: AgentProduct?
  public let title: String
  public let detail: String

  public init(
    id: String,
    kind: ShieldIncidentKind,
    severity: ShieldIncidentSeverity,
    product: AgentProduct?,
    title: String,
    detail: String
  ) {
    self.id = id
    self.kind = kind
    self.severity = severity
    self.product = product
    self.title = title
    self.detail = detail
  }
}

public struct ShieldSnapshot: Codable, Equatable, Sendable {
  public let capturedAt: String
  public let level: ShieldLevel
  public let trustBoundary: ShieldTrustBoundary
  public let detectedIntegrations: Int
  public let currentIntegrations: Int
  public let recentAgentEvents: Int
  public let incidents: [ShieldIncident]
  public let binaryIdentities: [AgentBinaryIdentity]

  public init(
    capturedAt: String,
    level: ShieldLevel,
    trustBoundary: ShieldTrustBoundary,
    detectedIntegrations: Int,
    currentIntegrations: Int,
    recentAgentEvents: Int,
    incidents: [ShieldIncident],
    binaryIdentities: [AgentBinaryIdentity]
  ) {
    self.capturedAt = capturedAt
    self.level = level
    self.trustBoundary = trustBoundary
    self.detectedIntegrations = detectedIntegrations
    self.currentIntegrations = currentIntegrations
    self.recentAgentEvents = recentAgentEvents
    self.incidents = incidents
    self.binaryIdentities = binaryIdentities
  }
}

public enum ShieldSnapshotBuilder {
  public static func build(
    statuses: [AgentAdapterStatus],
    binaryIdentities: [AgentBinaryIdentity],
    binaryDrift: [AgentProduct: AgentBinaryDrift] = [:],
    recentValidEventByProduct: [String: Date],
    invalidReceiptCount: Int,
    collectorReachable: Bool = true,
    trustBoundary: ShieldTrustBoundary,
    now: Date = Date()
  ) -> ShieldSnapshot {
    var incidents: [ShieldIncident] = []
    let detected = statuses.filter(\.executableAvailable)
    let conforming = detected.filter {
      $0.state == .configured || $0.state == .managedByPlugin
    }

    for status in detected {
      switch status.state {
      case .notInstalled, .needsRepair:
        incidents.append(
          ShieldIncident(
            id: "adapter:\(status.product.rawValue)",
            kind: .adapterCoverage,
            severity: .warning,
            product: status.product,
            title: "\(status.product.displayName) capture is not current",
            detail: status.state == .notInstalled
              ? "The agent is installed but its native event adapter is missing."
              : "The agent adapter or receipt helper changed and requires repair."
          ))
      case .invalidConfiguration, .unmanagedConflict:
        incidents.append(
          ShieldIncident(
            id: "adapter-conflict:\(status.product.rawValue)",
            kind: .adapterConflict,
            severity: .critical,
            product: status.product,
            title: "\(status.product.displayName) configuration needs an operator",
            detail: status.state == .invalidConfiguration
              ? "The existing configuration is invalid and was left unchanged."
              : "The managed plugin path contains an unrelated plugin and was left unchanged."
          ))
      case .configured, .managedByPlugin:
        break
      }
    }

    for identity in binaryIdentities where identity.path != nil {
      if identity.trust == .invalidSignature {
        incidents.append(
          ShieldIncident(
            id: "binary-integrity:\(identity.product.rawValue)",
            kind: .binaryIntegrity,
            severity: .critical,
            product: identity.product,
            title: "\(identity.product.displayName) has an invalid code signature",
            detail:
              "The executable at \(identity.path ?? "the detected path") failed static code validation."
          ))
      }
      if case .changed = binaryDrift[identity.product] {
        incidents.append(
          ShieldIncident(
            id: "binary-drift:\(identity.product.rawValue)",
            kind: .binaryDrift,
            severity: .warning,
            product: identity.product,
            title: "\(identity.product.displayName) executable changed",
            detail: "Publisher identity and content measurements were recorded for investigation."
          ))
      }
    }

    if invalidReceiptCount > 0 {
      incidents.append(
        ShieldIncident(
          id: "receipt-integrity",
          kind: .receiptIntegrity,
          severity: .critical,
          product: nil,
          title: "Local evidence integrity failed",
          detail:
            "\(invalidReceiptCount) receipt records failed signature, chain, or sequence validation."
        ))
    }

    if !collectorReachable {
      incidents.append(
        ShieldIncident(
          id: "background-service",
          kind: .backgroundService,
          severity: .critical,
          product: nil,
          title: "Background collector is not reachable",
          detail: "The native collection service did not answer its local health check."
        ))
    }

    let recentEvents = detected.filter { status in
      guard let event = recentValidEventByProduct[status.product.displayName] else { return false }
      return now.timeIntervalSince(event) >= -30 && now.timeIntervalSince(event) <= 5 * 60
    }.count
    let level: ShieldLevel
    if detected.isEmpty {
      level = .inactive
    } else if incidents.contains(where: { $0.severity != .notice }) {
      level = .attention
    } else {
      level = .active
    }
    return ShieldSnapshot(
      capturedAt: ReceiptDate.string(from: now),
      level: level,
      trustBoundary: trustBoundary,
      detectedIntegrations: detected.count,
      currentIntegrations: conforming.count,
      recentAgentEvents: recentEvents,
      incidents: incidents,
      binaryIdentities: binaryIdentities
    )
  }
}
