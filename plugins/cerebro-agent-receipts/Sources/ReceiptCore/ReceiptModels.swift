import Foundation

public struct HookEnvelope: Codable, Equatable, Sendable {
  public let sessionID: String
  public let transcriptPath: String?
  public let cwd: String
  public let hookEventName: String
  public let model: String
  public let turnID: String?
  public let permissionMode: String?
  public let toolName: String?
  public let toolUseID: String?
  public let toolInput: JSONValue?
  public let toolResponse: JSONValue?
  public let source: String?

  enum CodingKeys: String, CodingKey {
    case sessionID = "session_id"
    case transcriptPath = "transcript_path"
    case cwd
    case hookEventName = "hook_event_name"
    case model
    case turnID = "turn_id"
    case permissionMode = "permission_mode"
    case toolName = "tool_name"
    case toolUseID = "tool_use_id"
    case toolInput = "tool_input"
    case toolResponse = "tool_response"
    case source
  }

  public init(
    sessionID: String,
    transcriptPath: String? = nil,
    cwd: String,
    hookEventName: String,
    model: String,
    turnID: String? = nil,
    permissionMode: String? = nil,
    toolName: String? = nil,
    toolUseID: String? = nil,
    toolInput: JSONValue? = nil,
    toolResponse: JSONValue? = nil,
    source: String? = nil
  ) {
    self.sessionID = sessionID
    self.transcriptPath = transcriptPath
    self.cwd = cwd
    self.hookEventName = hookEventName
    self.model = model
    self.turnID = turnID
    self.permissionMode = permissionMode
    self.toolName = toolName
    self.toolUseID = toolUseID
    self.toolInput = toolInput
    self.toolResponse = toolResponse
    self.source = source
  }
}

public enum ReceiptPhase: String, Codable, Sendable {
  case session
  case attempted
  case approvalRequested = "approval_requested"
  case completed
  case failed
}

public struct GitContext: Codable, Equatable, Sendable {
  public let repositoryRoot: String?
  public let commit: String?
  public let branch: String?

  public init(repositoryRoot: String?, commit: String?, branch: String?) {
    self.repositoryRoot = repositoryRoot
    self.commit = commit
    self.branch = branch
  }
}

public struct AgentIdentity: Codable, Equatable, Sendable {
  public let product: String
  public let model: String
  public let sessionID: String
  public let turnID: String?
  public let toolCallID: String?

  public init(
    product: String, model: String, sessionID: String, turnID: String?, toolCallID: String?
  ) {
    self.product = product
    self.model = model
    self.sessionID = sessionID
    self.turnID = turnID
    self.toolCallID = toolCallID
  }
}

public struct ExecutionReceiptPayload: Codable, Equatable, Identifiable, Sendable {
  public let schemaVersion: String
  public let id: String
  public let sequence: UInt64
  public let previousReceiptDigest: String?
  public let capturedAt: String
  public let phase: ReceiptPhase
  public let localUserClaim: String
  public let localUserClaimSource: String
  public let agent: AgentIdentity
  public let collector: CollectorIdentity?
  public let deviceID: String
  public let permissionMode: String?
  public let toolName: String?
  public let actionSummary: String
  public let inputDigest: String?
  public let resultDigest: String?
  public let cwd: String
  public let git: GitContext

  public init(
    schemaVersion: String = "cerebro.agent-execution-receipt.v1",
    id: String,
    sequence: UInt64,
    previousReceiptDigest: String?,
    capturedAt: String,
    phase: ReceiptPhase,
    localUserClaim: String,
    localUserClaimSource: String,
    agent: AgentIdentity,
    collector: CollectorIdentity? = nil,
    deviceID: String,
    permissionMode: String?,
    toolName: String?,
    actionSummary: String,
    inputDigest: String?,
    resultDigest: String?,
    cwd: String,
    git: GitContext
  ) {
    self.schemaVersion = schemaVersion
    self.id = id
    self.sequence = sequence
    self.previousReceiptDigest = previousReceiptDigest
    self.capturedAt = capturedAt
    self.phase = phase
    self.localUserClaim = localUserClaim
    self.localUserClaimSource = localUserClaimSource
    self.agent = agent
    self.collector = collector
    self.deviceID = deviceID
    self.permissionMode = permissionMode
    self.toolName = toolName
    self.actionSummary = actionSummary
    self.inputDigest = inputDigest
    self.resultDigest = resultDigest
    self.cwd = cwd
    self.git = git
  }

  public var capturedDate: Date? { ReceiptDate.parser.date(from: capturedAt) }
}

public struct ReceiptSignature: Codable, Equatable, Sendable {
  public let algorithm: String
  public let publicKey: String
  public let value: String
  public let hardwareBacked: Bool

  public init(algorithm: String, publicKey: String, value: String, hardwareBacked: Bool) {
    self.algorithm = algorithm
    self.publicKey = publicKey
    self.value = value
    self.hardwareBacked = hardwareBacked
  }
}

public struct ExecutionReceipt: Codable, Equatable, Identifiable, Sendable {
  public let payload: ExecutionReceiptPayload
  public let signature: ReceiptSignature

  public var id: String { payload.id }

  public init(payload: ExecutionReceiptPayload, signature: ReceiptSignature) {
    self.payload = payload
    self.signature = signature
  }
}

public enum ReceiptDate {
  public static let parser: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter
  }()

  public static func string(from date: Date) -> String {
    parser.string(from: date)
  }
}
