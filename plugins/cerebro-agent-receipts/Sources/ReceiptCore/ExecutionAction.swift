import Foundation

public enum ExecutionState: String, Sendable {
  case attempted
  case completed
  case failed
}

public enum AuthorizationEvidence: String, Sendable {
  case approvalGateObserved = "approval_gate_observed"
  case nonInteractiveMode = "non_interactive_mode"
  case notObserved = "not_observed"

  public var description: String {
    switch self {
    case .approvalGateObserved:
      return
        "The agent requested approval. The hook does not identify who decided or what the decision was."
    case .nonInteractiveMode:
      return "The agent reported a non-interactive permission mode."
    case .notObserved:
      return "No authorization decision was observed."
    }
  }
}

public struct ExecutionAction: Identifiable, Sendable {
  public let id: String
  public let sessionID: String
  public let turnID: String?
  public let toolCallID: String?
  public let toolName: String?
  public let actionSummary: String
  public let inputDigest: String?
  public let resultDigest: String?
  public let localUserClaim: String
  public let localUserClaimSource: String
  public let product: String
  public let collector: CollectorIdentity?
  public let model: String
  public let permissionMode: String?
  public let state: ExecutionState
  public let authorizationEvidence: AuthorizationEvidence
  public let startedAt: Date?
  public let completedAt: Date?
  public let receiptIDs: [String]
  public let integrityValid: Bool
  public let repositoryRoot: String?
  public let commit: String?

  public init(
    id: String,
    sessionID: String,
    turnID: String?,
    toolCallID: String?,
    toolName: String?,
    actionSummary: String,
    inputDigest: String?,
    resultDigest: String?,
    localUserClaim: String,
    localUserClaimSource: String,
    product: String = "Codex",
    collector: CollectorIdentity? = nil,
    model: String,
    permissionMode: String?,
    state: ExecutionState,
    authorizationEvidence: AuthorizationEvidence,
    startedAt: Date?,
    completedAt: Date?,
    receiptIDs: [String],
    integrityValid: Bool,
    repositoryRoot: String?,
    commit: String?
  ) {
    self.id = id
    self.sessionID = sessionID
    self.turnID = turnID
    self.toolCallID = toolCallID
    self.toolName = toolName
    self.actionSummary = actionSummary
    self.inputDigest = inputDigest
    self.resultDigest = resultDigest
    self.localUserClaim = localUserClaim
    self.localUserClaimSource = localUserClaimSource
    self.product = product
    self.collector = collector
    self.model = model
    self.permissionMode = permissionMode
    self.state = state
    self.authorizationEvidence = authorizationEvidence
    self.startedAt = startedAt
    self.completedAt = completedAt
    self.receiptIDs = receiptIDs
    self.integrityValid = integrityValid
    self.repositoryRoot = repositoryRoot
    self.commit = commit
  }
}

public enum ExecutionActionReducer {
  public static func reduce(
    receipts: [ExecutionReceipt],
    verifications: [String: ReceiptVerification]
  ) -> [ExecutionAction] {
    let actionable = receipts.filter {
      $0.payload.phase == .attempted || $0.payload.phase == .completed
        || $0.payload.phase == .failed
    }
    let approvals = receipts.filter { $0.payload.phase == .approvalRequested }
    let groups = Dictionary(grouping: actionable, by: actionKey)
    return groups.values.compactMap { group in
      guard let attempted = group.first(where: { $0.payload.phase == .attempted }) ?? group.first
      else { return nil }
      let terminal = group.first {
        $0.payload.phase == .completed || $0.payload.phase == .failed
      }
      let approvalObserved = approvals.contains { approval in
        approval.payload.agent.sessionID == attempted.payload.agent.sessionID
          && approval.payload.agent.product == attempted.payload.agent.product
          && approval.payload.agent.turnID == attempted.payload.agent.turnID
          && approval.payload.toolName == attempted.payload.toolName
      }
      let mode = attempted.payload.permissionMode
      let authorization: AuthorizationEvidence
      if approvalObserved {
        authorization = .approvalGateObserved
      } else if mode == "dontAsk" || mode == "bypassPermissions" {
        authorization = .nonInteractiveMode
      } else {
        authorization = .notObserved
      }
      let key = actionKey(attempted)
      let actionID = SHA256Digest.hex(Data(key.utf8))
      return ExecutionAction(
        id: actionID,
        sessionID: attempted.payload.agent.sessionID,
        turnID: attempted.payload.agent.turnID,
        toolCallID: attempted.payload.agent.toolCallID,
        toolName: attempted.payload.toolName,
        actionSummary: attempted.payload.actionSummary,
        inputDigest: attempted.payload.inputDigest,
        resultDigest: terminal?.payload.resultDigest,
        localUserClaim: attempted.payload.localUserClaim,
        localUserClaimSource: attempted.payload.localUserClaimSource,
        product: attempted.payload.agent.product,
        collector: attempted.payload.collector,
        model: attempted.payload.agent.model,
        permissionMode: mode,
        state: terminal.map { $0.payload.phase == .failed ? .failed : .completed } ?? .attempted,
        authorizationEvidence: authorization,
        startedAt: attempted.payload.capturedDate,
        completedAt: terminal?.payload.capturedDate,
        receiptIDs: group.sorted { $0.payload.sequence < $1.payload.sequence }.map(\.id),
        integrityValid: group.allSatisfy { verifications[$0.id]?.valid == true },
        repositoryRoot: attempted.payload.git.repositoryRoot,
        commit: attempted.payload.git.commit
      )
    }.sorted { ($0.startedAt ?? .distantPast) > ($1.startedAt ?? .distantPast) }
  }

  private static func actionKey(_ receipt: ExecutionReceipt) -> String {
    let agent = receipt.payload.agent
    if let call = agent.toolCallID {
      return [
        agent.product, agent.sessionID, agent.turnID ?? "", call, receipt.payload.inputDigest ?? "",
      ].joined(
        separator: "|")
    }
    return [
      agent.product, agent.sessionID, agent.turnID ?? "", receipt.payload.toolName ?? "",
      receipt.payload.inputDigest ?? receipt.id,
    ].joined(separator: "|")
  }
}
