import Foundation

public enum ProviderEventProvenance: String, Codable, Sendable {
  case userImported = "user_imported_json"
  case authenticatedAWSAPI = "authenticated_aws_api"
}

public struct ProviderEvent: Codable, Equatable, Identifiable, Sendable {
  public let id: String
  public let eventName: String
  public let eventTime: String
  public let principal: String?
  public let recipientAccountID: String?
  public let userAgent: String?
  public let sourceIPAddress: String?
  public let resources: [String]
  public let sourceIdentity: String?
  public let actionTag: String?
  public let provenance: ProviderEventProvenance

  public init(
    id: String,
    eventName: String,
    eventTime: String,
    principal: String?,
    recipientAccountID: String? = nil,
    userAgent: String?,
    sourceIPAddress: String?,
    resources: [String],
    sourceIdentity: String? = nil,
    actionTag: String? = nil,
    provenance: ProviderEventProvenance = .userImported
  ) {
    self.id = id
    self.eventName = eventName
    self.eventTime = eventTime
    self.principal = principal
    self.recipientAccountID = recipientAccountID
    self.userAgent = userAgent
    self.sourceIPAddress = sourceIPAddress
    self.resources = resources
    self.sourceIdentity = sourceIdentity
    self.actionTag = actionTag
    self.provenance = provenance
  }

  public var eventDate: Date? {
    ReceiptDate.parse(eventTime) ?? ISO8601DateFormatter().date(from: eventTime)
  }
}

public enum CloudTrailImportError: Error, LocalizedError {
  case unsupportedShape
  public var errorDescription: String? {
    "The selected file is not a CloudTrail LookupEvents response or event."
  }
}

public enum CloudTrailImporter {
  public static func parse(
    _ data: Data,
    provenance: ProviderEventProvenance = .userImported
  ) throws -> [ProviderEvent] {
    let root = try JSONSerialization.jsonObject(with: data)
    if let object = root as? [String: Any], let events = object["Events"] as? [[String: Any]] {
      return try events.map { try parseLookupEvent($0, provenance: provenance) }
    }
    if let events = root as? [[String: Any]] {
      return try events.map { try parseRawOrLookupEvent($0, provenance: provenance) }
    }
    if let event = root as? [String: Any] {
      return [try parseRawOrLookupEvent(event, provenance: provenance)]
    }
    throw CloudTrailImportError.unsupportedShape
  }

  private static func parseLookupEvent(_ value: [String: Any], provenance: ProviderEventProvenance)
    throws -> ProviderEvent
  {
    if let raw = value["CloudTrailEvent"] as? String,
      let data = raw.data(using: .utf8),
      let nested = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    {
      return parseRawEvent(nested, fallback: value, provenance: provenance)
    }
    return try parseRawOrLookupEvent(value, provenance: provenance)
  }

  private static func parseRawOrLookupEvent(
    _ value: [String: Any], provenance: ProviderEventProvenance
  ) throws -> ProviderEvent {
    if value["eventName"] != nil {
      return parseRawEvent(value, fallback: value, provenance: provenance)
    }
    if value["EventName"] != nil { return try parseLookupEvent(value, provenance: provenance) }
    throw CloudTrailImportError.unsupportedShape
  }

  private static func parseRawEvent(
    _ event: [String: Any],
    fallback: [String: Any],
    provenance: ProviderEventProvenance
  ) -> ProviderEvent {
    let identity = event["userIdentity"] as? [String: Any]
    let sessionContext = identity?["sessionContext"] as? [String: Any]
    let issuer = sessionContext?["sessionIssuer"] as? [String: Any]
    let resources =
      (fallback["Resources"] as? [[String: Any]])?.compactMap { $0["ResourceName"] as? String }
      ?? flattenResourceNames(event["resources"])
    let timestamp =
      event["eventTime"] as? String
      ?? normalizeLookupTime(fallback["EventTime"])
      ?? ReceiptDate.string(from: Date.distantPast)
    let parameters = event["requestParameters"] as? [String: Any]

    return ProviderEvent(
      id: event["eventID"] as? String ?? fallback["EventId"] as? String ?? UUID().uuidString,
      eventName: event["eventName"] as? String ?? fallback["EventName"] as? String ?? "Unknown",
      eventTime: timestamp,
      principal: identity?["arn"] as? String ?? issuer?["arn"] as? String ?? fallback["Username"]
        as? String,
      recipientAccountID: event["recipientAccountId"] as? String,
      userAgent: event["userAgent"] as? String,
      sourceIPAddress: event["sourceIPAddress"] as? String,
      resources: resources,
      sourceIdentity: sessionContext?["sourceIdentity"] as? String,
      actionTag: exactTag(named: "CerebroActionId", in: parameters?["tags"]),
      provenance: provenance
    )
  }

  private static func exactTag(named name: String, in value: Any?) -> String? {
    guard let tags = value as? [[String: Any]] else { return nil }
    for tag in tags {
      let key = tag["key"] as? String ?? tag["Key"] as? String
      if key == name { return tag["value"] as? String ?? tag["Value"] as? String }
    }
    return nil
  }

  private static func normalizeLookupTime(_ value: Any?) -> String? {
    if let value = value as? String {
      if let date = ISO8601DateFormatter().date(from: value) {
        return ReceiptDate.string(from: date)
      }
      return value
    }
    if let value = value as? Double {
      return ReceiptDate.string(from: Date(timeIntervalSince1970: value))
    }
    return nil
  }

  private static func flattenResourceNames(_ value: Any?) -> [String] {
    guard let resources = value as? [[String: Any]] else { return [] }
    return resources.compactMap { $0["ARN"] as? String ?? $0["resourceName"] as? String }
  }
}

public struct ProviderBindingPolicy: Sendable {
  public let expectedAccountID: String
  public let expectedAgentRole: String
  public let correlationWindow: TimeInterval

  public init(
    expectedAccountID: String, expectedAgentRole: String, correlationWindow: TimeInterval = 90
  ) {
    self.expectedAccountID = expectedAccountID
    self.expectedAgentRole = expectedAgentRole
    self.correlationWindow = correlationWindow
  }
}

public enum AttributionLevel: String, Codable, Sendable {
  case agentCaptured = "agent_captured"
  case candidateCorrelation = "candidate_correlation"
  case providerBound = "provider_bound"
}

public struct AttributionMatch: Identifiable, Sendable {
  public let actionID: String
  public let providerEvent: ProviderEvent?
  public let level: AttributionLevel
  public let evidence: [String]
  public let deltaSeconds: TimeInterval?

  public var id: String { actionID }
}

public struct AttributionAssessment: Sendable {
  public let actionMatches: [String: AttributionMatch]
  public let unmatchedProviderEvents: [ProviderEvent]

  public init(actionMatches: [String: AttributionMatch], unmatchedProviderEvents: [ProviderEvent]) {
    self.actionMatches = actionMatches
    self.unmatchedProviderEvents = unmatchedProviderEvents
  }

  public var providerBoundCount: Int {
    actionMatches.values.filter { $0.level == .providerBound }.count
  }
  public var candidateCount: Int {
    actionMatches.values.filter { $0.level == .candidateCorrelation }.count
  }
  public var capturedOnlyCount: Int {
    actionMatches.values.filter { $0.level == .agentCaptured }.count
  }
}

public enum ReceiptCorrelator {
  public static func assess(
    actions: [ExecutionAction],
    providerEvents: [ProviderEvent],
    policy: ProviderBindingPolicy? = nil
  ) -> AttributionAssessment {
    var unused = Dictionary(uniqueKeysWithValues: providerEvents.map { ($0.id, $0) })
    var matches: [String: AttributionMatch] = [:]

    for action in actions where action.state == .completed {
      if let policy,
        let bound = unused.values.first(where: { bindingMatches(action, $0, policy: policy) })
      {
        matches[action.id] = AttributionMatch(
          actionID: action.id,
          providerEvent: bound,
          level: .providerBound,
          evidence: [
            "authenticated AWS API", "dedicated agent role", "action ID", "account", "time",
          ],
          deltaSeconds: delta(action, bound)
        )
        unused.removeValue(forKey: bound.id)
        continue
      }

      let candidates = unused.values.compactMap { event -> (ProviderEvent, TimeInterval)? in
        guard let seconds = delta(action, event), seconds >= -5,
          seconds <= (policy?.correlationWindow ?? 90)
        else { return nil }
        return (event, seconds)
      }.sorted { lhs, rhs in
        candidateScore(action, lhs.0, delta: lhs.1) > candidateScore(action, rhs.0, delta: rhs.1)
      }
      if let candidate = candidates.first,
        candidateScore(action, candidate.0, delta: candidate.1) >= 2
      {
        matches[action.id] = AttributionMatch(
          actionID: action.id,
          providerEvent: candidate.0,
          level: .candidateCorrelation,
          evidence: candidateEvidence(action, candidate.0, delta: candidate.1),
          deltaSeconds: candidate.1
        )
        unused.removeValue(forKey: candidate.0.id)
      }
    }

    for action in actions where matches[action.id] == nil {
      matches[action.id] = AttributionMatch(
        actionID: action.id,
        providerEvent: nil,
        level: .agentCaptured,
        evidence: ["signed local hook evidence"],
        deltaSeconds: nil
      )
    }

    return AttributionAssessment(
      actionMatches: matches,
      unmatchedProviderEvents: unused.values.sorted {
        ($0.eventDate ?? .distantPast) > ($1.eventDate ?? .distantPast)
      }
    )
  }

  private static func bindingMatches(
    _ action: ExecutionAction, _ event: ProviderEvent, policy: ProviderBindingPolicy
  ) -> Bool {
    guard event.provenance == .authenticatedAWSAPI else { return false }
    guard event.recipientAccountID == policy.expectedAccountID else { return false }
    guard event.principal?.contains(":assumed-role/\(policy.expectedAgentRole)/") == true else {
      return false
    }
    guard event.sourceIdentity == action.id || event.actionTag == action.id else { return false }
    guard let seconds = delta(action, event), seconds >= -5, seconds <= policy.correlationWindow
    else { return false }
    return actionCompatible(action.actionSummary, event.eventName)
  }

  private static func delta(_ action: ExecutionAction, _ event: ProviderEvent) -> TimeInterval? {
    guard let start = action.startedAt, let eventDate = event.eventDate else { return nil }
    return eventDate.timeIntervalSince(start)
  }

  private static func candidateScore(
    _ action: ExecutionAction, _ event: ProviderEvent, delta: TimeInterval
  ) -> Int {
    var score = delta <= 30 ? 1 : 0
    if actionCompatible(action.actionSummary, event.eventName) { score += 2 }
    if event.principal?.lowercased().contains(action.localUserClaim.lowercased()) == true {
      score += 1
    }
    return score
  }

  private static func candidateEvidence(
    _ action: ExecutionAction, _ event: ProviderEvent, delta: TimeInterval
  ) -> [String] {
    var evidence = ["time window"]
    if actionCompatible(action.actionSummary, event.eventName) { evidence.append("action name") }
    if event.principal?.lowercased().contains(action.localUserClaim.lowercased()) == true {
      evidence.append("local user claim")
    }
    if event.provenance == .userImported { evidence.append("user-imported JSON") }
    return evidence
  }

  private static func actionCompatible(_ action: String, _ eventName: String) -> Bool {
    let normalized = action.lowercased().replacingOccurrences(of: "-", with: "")
    return normalized.contains(eventName.lowercased())
  }
}
