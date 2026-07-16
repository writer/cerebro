import Foundation

public struct ReceiptDraft: Sendable {
  public let id: String
  public let capturedAt: String
  public let phase: ReceiptPhase
  public let localUserClaim: String
  public let localUserClaimSource: String
  public let agent: AgentIdentity
  public let permissionMode: String?
  public let toolName: String?
  public let actionSummary: String
  public let inputDigest: String?
  public let resultDigest: String?
  public let cwd: String
  public let git: GitContext

  public init(
    id: String,
    capturedAt: String,
    phase: ReceiptPhase,
    localUserClaim: String,
    localUserClaimSource: String,
    agent: AgentIdentity,
    permissionMode: String?,
    toolName: String?,
    actionSummary: String,
    inputDigest: String?,
    resultDigest: String?,
    cwd: String,
    git: GitContext
  ) {
    self.id = id
    self.capturedAt = capturedAt
    self.phase = phase
    self.localUserClaim = localUserClaim
    self.localUserClaimSource = localUserClaimSource
    self.agent = agent
    self.permissionMode = permissionMode
    self.toolName = toolName
    self.actionSummary = actionSummary
    self.inputDigest = inputDigest
    self.resultDigest = resultDigest
    self.cwd = cwd
    self.git = git
  }
}

public enum HookCapture {
  public static func draft(
    from envelope: HookEnvelope,
    capturedAt: Date = Date(),
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) throws -> ReceiptDraft {
    let command = envelope.toolInput?.objectValue?["command"]?.stringValue
    let override = environment["CEREBRO_LOCAL_USER_CLAIM"]
    return ReceiptDraft(
      id: UUID().uuidString.lowercased(),
      capturedAt: ReceiptDate.string(from: capturedAt),
      phase: phase(for: envelope.hookEventName),
      localUserClaim: override ?? NSUserName(),
      localUserClaimSource: override == nil ? "macos_account" : "environment_override",
      agent: AgentIdentity(
        product: "Codex",
        model: envelope.model,
        sessionID: envelope.sessionID,
        turnID: envelope.turnID,
        toolCallID: envelope.toolUseID
      ),
      permissionMode: envelope.permissionMode,
      toolName: envelope.toolName,
      actionSummary: actionSummary(
        command: command, toolName: envelope.toolName, source: envelope.source),
      inputDigest: try envelope.toolInput.map(CanonicalJSON.digest),
      resultDigest: try envelope.toolResponse.map(CanonicalJSON.digest),
      cwd: envelope.cwd,
      git: gitContext(at: envelope.cwd)
    )
  }

  private static func phase(for event: String) -> ReceiptPhase {
    switch event {
    case "SessionStart": return .session
    case "PermissionRequest": return .approvalRequested
    case "PostToolUse": return .completed
    default: return .attempted
    }
  }

  public static func actionSummary(command: String?, toolName: String?, source: String?) -> String {
    guard let command, !command.isEmpty else {
      if let toolName, !toolName.isEmpty { return toolName }
      if let source, !source.isEmpty { return "Codex session \(source)" }
      return "Codex lifecycle event"
    }

    let safe =
      command
      .split(whereSeparator: { $0.isWhitespace })
      .map(String.init)
      .filter { token in
        !token.hasPrefix("-") && !token.contains("=")
          && token.range(of: #"^[A-Za-z0-9_./:-]+$"#, options: .regularExpression) != nil
      }

    guard let executable = safe.first else { return toolName ?? "Shell command" }
    if executable == "aws" {
      return safe.prefix(3).joined(separator: " ")
    }
    if executable.hasSuffix(".sh") || executable.contains("/") {
      return URL(fileURLWithPath: executable).lastPathComponent
    }
    return safe.prefix(2).joined(separator: " ")
  }

  private static func gitContext(at cwd: String) -> GitContext {
    GitContext(
      repositoryRoot: git(["rev-parse", "--show-toplevel"], cwd: cwd),
      commit: git(["rev-parse", "HEAD"], cwd: cwd),
      branch: git(["branch", "--show-current"], cwd: cwd)
    )
  }

  private static func git(_ arguments: [String], cwd: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = ["-C", cwd] + arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do {
      try process.run()
      process.waitUntilExit()
      guard process.terminationStatus == 0 else { return nil }
      let data = output.fileHandleForReading.readDataToEndOfFile()
      let value = String(decoding: data, as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
      return value.isEmpty ? nil : value
    } catch {
      return nil
    }
  }
}
