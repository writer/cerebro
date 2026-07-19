import Foundation

public enum AgentProduct: String, CaseIterable, Codable, Identifiable, Sendable {
  case codex
  case droid
  case claudeCode = "claude-code"
  case openCode = "opencode"
  case cursor

  public var id: String { rawValue }

  public var displayName: String {
    switch self {
    case .codex: return "Codex"
    case .droid: return "Droid"
    case .claudeCode: return "Claude Code"
    case .openCode: return "OpenCode"
    case .cursor: return "Cursor"
    }
  }

  public var integration: AgentIntegration {
    self == .openCode ? .pluginEvent : .nativeHook
  }

  public var eventSchema: String { "\(rawValue).agent-event.v1" }
}

public enum AgentIntegration: String, Codable, Sendable {
  case nativeHook = "native_hook"
  case pluginEvent = "plugin_event"
  case structuredStream = "structured_stream"
}

public struct CollectorIdentity: Codable, Equatable, Sendable {
  public let adapterID: String
  public let integration: AgentIntegration
  public let eventName: String
  public let eventSchema: String
  public let originEvidence: String

  public init(
    adapterID: String,
    integration: AgentIntegration,
    eventName: String,
    eventSchema: String,
    originEvidence: String = "agent_supplied_event"
  ) {
    self.adapterID = adapterID
    self.integration = integration
    self.eventName = eventName
    self.eventSchema = eventSchema
    self.originEvidence = originEvidence
  }
}

public enum AgentEventError: Error, LocalizedError {
  case invalidObject
  case missingSessionID(AgentProduct)
  case missingEventName(AgentProduct)

  public var errorDescription: String? {
    switch self {
    case .invalidObject: return "The agent event is not a JSON object."
    case .missingSessionID(let product):
      return "The \(product.displayName) event has no session identifier."
    case .missingEventName(let product):
      return "The \(product.displayName) event has no lifecycle event name."
    }
  }
}

public enum AgentEventNormalizer {
  public static func normalize(_ data: Data, product: AgentProduct) throws -> HookEnvelope {
    let value = try JSONDecoder().decode(JSONValue.self, from: data)
    guard let root = value.objectValue else { throw AgentEventError.invalidObject }

    guard
      let sessionID = firstString(
        in: root,
        keys: ["session_id", "sessionId", "conversation_id", "conversationId"],
        nested: [("session", "id"), ("properties", "sessionID")]
      )
    else {
      throw AgentEventError.missingSessionID(product)
    }

    guard
      let rawEvent = firstString(
        in: root, keys: ["hook_event_name", "hookEventName", "event_name", "eventName", "event"]
      )
    else {
      throw AgentEventError.missingEventName(product)
    }

    let eventName = canonicalEventName(rawEvent)
    let command = firstString(in: root, keys: ["command"])
    let input =
      firstValue(in: root, keys: ["tool_input", "toolInput", "input", "args"])
      ?? command.map { JSONValue.object(["command": .string($0)]) }
    let response = firstValue(
      in: root,
      keys: ["tool_response", "toolResponse", "tool_result", "toolResult", "result", "output"])
    let workspaceRoot = firstStringInArray(in: root, key: "workspace_roots")

    return HookEnvelope(
      sessionID: sessionID,
      transcriptPath: firstString(in: root, keys: ["transcript_path", "transcriptPath"]),
      cwd: firstString(in: root, keys: ["cwd", "directory", "worktree"])
        ?? workspaceRoot ?? FileManager.default.currentDirectoryPath,
      hookEventName: eventName,
      model: firstString(in: root, keys: ["model", "model_id", "modelId"]) ?? "Not reported",
      turnID: firstString(
        in: root,
        keys: [
          "turn_id", "turnId", "prompt_id", "promptId", "generation_id", "generationId",
          "message_id",
        ]
      ),
      permissionMode: firstString(
        in: root, keys: ["permission_mode", "permissionMode", "permission"]),
      toolName: firstString(in: root, keys: ["tool_name", "toolName", "tool"])
        ?? inferredToolName(for: rawEvent),
      toolUseID: firstString(
        in: root,
        keys: ["tool_use_id", "toolUseId", "tool_call_id", "toolCallId", "call_id", "callId"]
      ),
      toolInput: input,
      toolResponse: response,
      source: firstString(in: root, keys: ["source", "reason", "status"])
    )
  }

  public static func collector(product: AgentProduct, eventName: String) -> CollectorIdentity {
    CollectorIdentity(
      adapterID: product.rawValue,
      integration: product.integration,
      eventName: eventName,
      eventSchema: product.eventSchema
    )
  }

  private static func canonicalEventName(_ event: String) -> String {
    switch event.lowercased() {
    case "sessionstart", "session.created": return "SessionStart"
    case "pretooluse", "tool.execute.before", "beforeshellexecution", "beforemcpexecution":
      return "PreToolUse"
    case "posttooluse", "tool.execute.after", "aftershellexecution", "aftermcpexecution":
      return "PostToolUse"
    case "posttoolusefailure": return "PostToolUseFailure"
    case "permissionrequest", "permission.asked": return "PermissionRequest"
    default: return event
    }
  }

  private static func inferredToolName(for event: String) -> String? {
    switch event.lowercased() {
    case "beforeshellexecution", "aftershellexecution": return "Shell"
    case "beforemcpexecution", "aftermcpexecution": return "MCP"
    default: return nil
    }
  }

  private static func firstString(
    in object: [String: JSONValue],
    keys: [String],
    nested: [(String, String)] = []
  ) -> String? {
    for key in keys {
      if let value = object[key]?.stringValue, !value.isEmpty { return value }
    }
    for (parent, child) in nested {
      if let value = object[parent]?.objectValue?[child]?.stringValue, !value.isEmpty {
        return value
      }
    }
    return nil
  }

  private static func firstValue(
    in object: [String: JSONValue], keys: [String]
  ) -> JSONValue? {
    for key in keys where object[key] != nil { return object[key] }
    return nil
  }

  private static func firstStringInArray(
    in object: [String: JSONValue], key: String
  ) -> String? {
    guard case .array(let values) = object[key] else { return nil }
    return values.compactMap(\.stringValue).first
  }
}
