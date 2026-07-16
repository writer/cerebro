import CryptoKit
import Foundation

public enum AdapterInstallState: String, Codable, Sendable {
  case managedByPlugin = "managed_by_plugin"
  case configured
  case notInstalled = "not_installed"
  case needsRepair = "needs_repair"
  case invalidConfiguration = "invalid_configuration"
  case unmanagedConflict = "unmanaged_conflict"
}

public struct AgentAdapterStatus: Identifiable, Sendable {
  public let product: AgentProduct
  public let state: AdapterInstallState
  public let executableAvailable: Bool
  public let configurationPath: String?
  public let helperCurrent: Bool?
  public let configurationModifiedAt: Date?

  public var id: String { product.id }

  public init(
    product: AgentProduct,
    state: AdapterInstallState,
    executableAvailable: Bool,
    configurationPath: String?,
    helperCurrent: Bool? = nil,
    configurationModifiedAt: Date? = nil
  ) {
    self.product = product
    self.state = state
    self.executableAvailable = executableAvailable
    self.configurationPath = configurationPath
    self.helperCurrent = helperCurrent
    self.configurationModifiedAt = configurationModifiedAt
  }
}

public enum AgentAdapterReconciliationOutcome: String, Codable, Sendable {
  case alreadyProtected = "already_protected"
  case installed
  case repaired
  case managedByPlugin = "managed_by_plugin"
  case agentNotDetected = "agent_not_detected"
  case requiresOperator = "requires_operator"
  case failed
}

public struct AgentAdapterReconciliation: Identifiable, Sendable {
  public let product: AgentProduct
  public let outcome: AgentAdapterReconciliationOutcome
  public let detail: String

  public var id: String { product.id }

  public init(
    product: AgentProduct,
    outcome: AgentAdapterReconciliationOutcome,
    detail: String
  ) {
    self.product = product
    self.outcome = outcome
    self.detail = detail
  }
}

public enum AgentAdapterInstallError: Error, LocalizedError {
  case codexManagedByPlugin
  case invalidConfiguration(URL)
  case missingBundledHelper(URL)
  case unmanagedPlugin(URL)

  public var errorDescription: String? {
    switch self {
    case .codexManagedByPlugin:
      return "Codex receipt capture is installed through the Codex plugin."
    case .invalidConfiguration(let url):
      return "The existing agent configuration is not valid JSON: \(url.path)"
    case .missingBundledHelper(let url):
      return "The verified receipt helper is missing from the app bundle: \(url.path)"
    case .unmanagedPlugin(let url):
      return "An unmanaged OpenCode plugin already exists at \(url.path)."
    }
  }
}

public struct AgentAdapterInstaller: Sendable {
  public let homeDirectory: URL
  public let bundledHelperURL: URL
  public let installedHelperURL: URL

  private static let marker = "cerebro-agent-receipts-managed-adapter"

  public init(
    homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
    bundledHelperURL: URL,
    installedHelperURL: URL? = nil
  ) {
    self.homeDirectory = homeDirectory
    self.bundledHelperURL = bundledHelperURL
    self.installedHelperURL =
      installedHelperURL
      ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
      .appendingPathComponent("com.writer.cerebro.agent-receipts/bin", isDirectory: true)
      .appendingPathComponent("CerebroAgentReceiptHook")
  }

  public func statuses() -> [AgentAdapterStatus] {
    let helperCurrent = helperIsCurrentAndValid()
    return AgentProduct.allCases.map { status(for: $0, helperCurrent: helperCurrent) }
  }

  public func reconcileDetectedAgents() -> [AgentAdapterReconciliation] {
    AgentProduct.allCases.map { product in
      let current = status(for: product)
      if product == .codex {
        return AgentAdapterReconciliation(
          product: product,
          outcome: .managedByPlugin,
          detail: "Codex capture remains owned by the installed plugin."
        )
      }
      guard current.executableAvailable else {
        return AgentAdapterReconciliation(
          product: product,
          outcome: .agentNotDetected,
          detail: "No local executable was detected."
        )
      }
      switch current.state {
      case .configured:
        return AgentAdapterReconciliation(
          product: product,
          outcome: .alreadyProtected,
          detail: "The native event adapter and bundled helper are current."
        )
      case .notInstalled, .needsRepair:
        do {
          try install(product)
          return AgentAdapterReconciliation(
            product: product,
            outcome: current.state == .notInstalled ? .installed : .repaired,
            detail: current.state == .notInstalled
              ? "Native event capture was installed automatically."
              : "Native event capture was restored automatically."
          )
        } catch {
          return AgentAdapterReconciliation(
            product: product,
            outcome: .failed,
            detail: error.localizedDescription
          )
        }
      case .invalidConfiguration, .unmanagedConflict:
        return AgentAdapterReconciliation(
          product: product,
          outcome: .requiresOperator,
          detail: current.state == .invalidConfiguration
            ? "The existing configuration is invalid and was not changed."
            : "The managed plugin path contains an unrelated plugin and was not changed."
        )
      case .managedByPlugin:
        return AgentAdapterReconciliation(
          product: product,
          outcome: .managedByPlugin,
          detail: "Capture is owned by the product plugin."
        )
      }
    }
  }

  public func status(for product: AgentProduct) -> AgentAdapterStatus {
    status(for: product, helperCurrent: product == .codex ? false : helperIsCurrentAndValid())
  }

  private func status(for product: AgentProduct, helperCurrent: Bool) -> AgentAdapterStatus {
    if product == .codex {
      return AgentAdapterStatus(
        product: product,
        state: .managedByPlugin,
        executableAvailable: executableExists(for: product),
        configurationPath: nil,
        helperCurrent: nil
      )
    }

    let configuration = configurationURL(for: product)
    let state: AdapterInstallState
    do {
      if product == .openCode {
        guard FileManager.default.fileExists(atPath: configuration.path) else {
          return AgentAdapterStatus(
            product: product,
            state: .notInstalled,
            executableAvailable: executableExists(for: product),
            configurationPath: configuration.path,
            helperCurrent: nil
          )
        }
        let body = try String(contentsOf: configuration, encoding: .utf8)
        if body.contains(Self.marker) && body.contains(installedHelperURL.path) {
          state = helperCurrent ? .configured : .needsRepair
        } else if body.contains(Self.marker) {
          state = .needsRepair
        } else {
          state = .unmanagedConflict
        }
      } else {
        guard FileManager.default.fileExists(atPath: configuration.path) else {
          return AgentAdapterStatus(
            product: product,
            state: .notInstalled,
            executableAvailable: executableExists(for: product),
            configurationPath: configuration.path,
            helperCurrent: nil
          )
        }
        let root = try readJSONObject(at: configuration)
        try validateHookSchema(root, for: product, at: configuration)
        let commands = hookCommands(in: root)
        let productCommands = commands.filter { isManagedCommand($0, product: product) }
        if productCommands.contains(command(for: product)) {
          state = helperCurrent ? .configured : .needsRepair
        } else if !productCommands.isEmpty {
          state = .needsRepair
        } else {
          state = .notInstalled
        }
      }
    } catch {
      state = .invalidConfiguration
    }

    return AgentAdapterStatus(
      product: product,
      state: state,
      executableAvailable: executableExists(for: product),
      configurationPath: configuration.path,
      helperCurrent: state == .configured ? true : (state == .needsRepair ? false : nil),
      configurationModifiedAt: configurationModificationDate(configuration)
    )
  }

  public func install(_ product: AgentProduct) throws {
    guard product != .codex else { throw AgentAdapterInstallError.codexManagedByPlugin }
    try installHelper()
    if product == .openCode {
      try installOpenCodePlugin()
    } else if product == .cursor {
      try installCursorHooks()
    } else {
      try installNestedHooks(for: product)
    }
  }

  public func remove(_ product: AgentProduct) throws {
    guard product != .codex else { throw AgentAdapterInstallError.codexManagedByPlugin }
    let url = configurationURL(for: product)
    guard FileManager.default.fileExists(atPath: url.path) else { return }
    if product == .openCode {
      let body = try String(contentsOf: url, encoding: .utf8)
      if body.contains(Self.marker) { try FileManager.default.removeItem(at: url) }
      return
    }

    var root = try readJSONObject(at: url)
    try validateHookSchema(root, for: product, at: url)
    guard var hooks = root["hooks"] as? [String: Any] else { return }
    for event in hooks.keys {
      guard let groups = hooks[event] as? [[String: Any]] else { continue }
      hooks[event] = groups.compactMap { group in
        if product == .cursor {
          guard let command = group["command"] as? String else { return group }
          return isManagedCommand(command, product: product) ? nil : group
        }
        guard let handlers = group["hooks"] as? [[String: Any]] else { return group }
        let retained = handlers.filter {
          guard let command = $0["command"] as? String else { return true }
          return !isManagedCommand(command, product: product)
        }
        if retained.isEmpty { return nil }
        var updated = group
        updated["hooks"] = retained
        return updated
      }
    }
    root["hooks"] = hooks
    try writeJSONObject(root, to: url)
  }

  private func installHelper() throws {
    guard
      FileManager.default.isExecutableFile(atPath: bundledHelperURL.path),
      codeSignatureIsValid(at: bundledHelperURL)
    else {
      throw AgentAdapterInstallError.missingBundledHelper(bundledHelperURL)
    }
    try FileManager.default.createDirectory(
      at: installedHelperURL.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let data = try Data(contentsOf: bundledHelperURL)
    try data.write(to: installedHelperURL, options: .atomic)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o755], ofItemAtPath: installedHelperURL.path)
    guard helperIsCurrentAndValid() else {
      try? FileManager.default.removeItem(at: installedHelperURL)
      throw AgentAdapterInstallError.missingBundledHelper(bundledHelperURL)
    }
  }

  private func installNestedHooks(for product: AgentProduct) throws {
    let url = configurationURL(for: product)
    var root = try readJSONObjectIfPresent(at: url)
    try validateHookSchema(root, for: product, at: url)
    var hooks = root["hooks"] as? [String: Any] ?? [:]
    let events =
      product == .claudeCode
      ? ["SessionStart", "PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure"]
      : ["SessionStart", "PreToolUse", "PostToolUse"]

    for event in events {
      var groups = hooks[event] as? [[String: Any]] ?? []
      groups = removeManagedGroups(groups, product: product)
      let handler: [String: Any] = [
        "type": "command",
        "command": command(for: product),
        "timeout": event == "SessionStart" ? 120 : 30,
      ]
      var group: [String: Any] = ["hooks": [handler]]
      if event != "SessionStart" || product == .claudeCode {
        group["matcher"] = event == "SessionStart" ? "startup|resume|clear|compact" : "*"
      }
      groups.append(group)
      hooks[event] = groups
    }
    root["hooks"] = hooks
    try writeJSONObject(root, to: url)
  }

  private func installCursorHooks() throws {
    let url = configurationURL(for: .cursor)
    var root = try readJSONObjectIfPresent(at: url)
    try validateHookSchema(root, for: .cursor, at: url)
    var hooks = root["hooks"] as? [String: Any] ?? [:]
    for event in ["sessionStart", "preToolUse", "postToolUse", "postToolUseFailure"] {
      var handlers = hooks[event] as? [[String: Any]] ?? []
      handlers.removeAll {
        guard let existing = $0["command"] as? String else { return false }
        return isManagedCommand(existing, product: .cursor)
      }
      handlers.append([
        "command": command(for: .cursor),
        "timeout": event == "sessionStart" ? 120 : 30,
      ])
      hooks[event] = handlers
    }
    root["version"] = 1
    root["hooks"] = hooks
    try writeJSONObject(root, to: url)
  }

  private func installOpenCodePlugin() throws {
    let url = configurationURL(for: .openCode)
    if FileManager.default.fileExists(atPath: url.path) {
      let existing = try String(contentsOf: url, encoding: .utf8)
      guard existing.contains(Self.marker) else {
        throw AgentAdapterInstallError.unmanagedPlugin(url)
      }
    }
    let helper = try jsonString(installedHelperURL.path)
    let script = """
      // \(Self.marker)
      import { spawn } from "node:child_process"

      const helper = \(helper)
      const capture = (payload) => new Promise((resolve, reject) => {
        const child = spawn(helper, ["capture", "opencode"], { stdio: ["pipe", "ignore", "pipe"] })
        let error = ""
        child.stderr.on("data", (chunk) => { error += chunk.toString() })
        child.on("error", reject)
        child.on("close", (code) => code === 0 ? resolve() : reject(new Error(error || `receipt helper exited ${code}`)))
        child.stdin.end(JSON.stringify(payload))
      })

      export const CerebroAgentReceipts = async ({ directory }) => ({
        event: async ({ event }) => {
          if (event.type !== "session.created") return
          const sessionID = event.properties?.info?.id ?? event.properties?.sessionID ?? event.properties?.id
          if (sessionID) await capture({ event: event.type, session_id: sessionID, directory })
        },
        "tool.execute.before": async (input, output) => {
          const sessionID = input.sessionID ?? input.session_id ?? input.session?.id
          if (!sessionID) return
          await capture({
            event: "tool.execute.before",
            session_id: sessionID,
            call_id: input.callID ?? input.call_id,
            tool: input.tool,
            args: output.args,
            directory
          })
        },
        "tool.execute.after": async (input, output) => {
          const sessionID = input.sessionID ?? input.session_id ?? input.session?.id
          if (!sessionID) return
          await capture({
            event: "tool.execute.after",
            session_id: sessionID,
            call_id: input.callID ?? input.call_id,
            tool: input.tool,
            args: input.args,
            result: output,
            directory
          })
        }
      })
      """
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    try Data(script.utf8).write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
  }

  private func configurationURL(for product: AgentProduct) -> URL {
    switch product {
    case .codex:
      return homeDirectory.appendingPathComponent(".codex/config.toml")
    case .droid:
      return homeDirectory.appendingPathComponent(".factory/settings.json")
    case .claudeCode:
      return homeDirectory.appendingPathComponent(".claude/settings.json")
    case .openCode:
      return homeDirectory.appendingPathComponent(
        ".config/opencode/plugins/cerebro-agent-receipts.js")
    case .cursor:
      return homeDirectory.appendingPathComponent(".cursor/hooks.json")
    }
  }

  private func command(for product: AgentProduct) -> String {
    "\"\(installedHelperURL.path)\" capture \(product.rawValue)"
  }

  public func executableURL(for product: AgentProduct) -> URL? {
    let candidates: [String]
    switch product {
    case .codex:
      candidates = [
        ".local/bin/codex", ".cargo/bin/codex", ".codex/bin/codex", "Applications/Codex.app",
      ]
    case .droid: candidates = [".local/bin/droid", ".factory/bin/droid"]
    case .claudeCode: candidates = [".local/bin/claude", ".claude/local/claude"]
    case .openCode:
      candidates = [
        ".local/bin/opencode", ".opencode/bin/opencode", "Applications/OpenCode.app",
      ]
    case .cursor: candidates = [".local/bin/cursor-agent", "Applications/Cursor.app"]
    }
    let configuredPaths = Array(
      Set(
        (ProcessInfo.processInfo.environment["PATH"] ?? "")
          .split(separator: ":")
          .map(String.init)
          + [
            "/opt/homebrew/bin", "/usr/local/bin",
            homeDirectory.appendingPathComponent(".local/bin").path,
            homeDirectory.appendingPathComponent(".bun/bin").path,
            homeDirectory.appendingPathComponent("Library/pnpm").path,
          ]
      ))
    let commandNames: [String]
    switch product {
    case .codex: commandNames = ["codex"]
    case .droid: commandNames = ["droid"]
    case .claudeCode: commandNames = ["claude"]
    case .openCode: commandNames = ["opencode"]
    case .cursor: commandNames = ["cursor", "cursor-agent"]
    }
    for candidate in candidates {
      let url = homeDirectory.appendingPathComponent(candidate)
      if FileManager.default.fileExists(atPath: url.path) { return url }
    }
    for directory in configuredPaths {
      for name in commandNames {
        let url = URL(fileURLWithPath: directory).appendingPathComponent(name)
        if FileManager.default.isExecutableFile(atPath: url.path) { return url }
      }
    }
    let globalApplications: [AgentProduct: String] = [
      .codex: "/Applications/Codex.app",
      .openCode: "/Applications/OpenCode.app",
      .cursor: "/Applications/Cursor.app",
    ]
    if let applicationPath = globalApplications[product] {
      let application = URL(fileURLWithPath: applicationPath, isDirectory: true)
      if FileManager.default.fileExists(atPath: application.path) { return application }
    }
    return nil
  }

  private func executableExists(for product: AgentProduct) -> Bool {
    executableURL(for: product) != nil
  }

  private func validateHookSchema(
    _ root: [String: Any], for product: AgentProduct, at url: URL
  ) throws {
    guard let rawHooks = root["hooks"] else { return }
    guard let hooks = rawHooks as? [String: Any] else {
      throw AgentAdapterInstallError.invalidConfiguration(url)
    }
    for rawGroups in hooks.values {
      guard let groups = rawGroups as? [[String: Any]] else {
        throw AgentAdapterInstallError.invalidConfiguration(url)
      }
      for group in groups {
        if product == .cursor {
          guard group["command"] is String else {
            throw AgentAdapterInstallError.invalidConfiguration(url)
          }
        } else {
          guard group["hooks"] is [[String: Any]] else {
            throw AgentAdapterInstallError.invalidConfiguration(url)
          }
        }
      }
    }
  }

  private func helperIsCurrentAndValid() -> Bool {
    guard
      FileManager.default.isExecutableFile(atPath: bundledHelperURL.path),
      FileManager.default.isExecutableFile(atPath: installedHelperURL.path),
      let bundled = try? Data(contentsOf: bundledHelperURL),
      let installed = try? Data(contentsOf: installedHelperURL),
      SHA256.hash(data: bundled) == SHA256.hash(data: installed),
      codeSignatureIsValid(at: bundledHelperURL),
      codeSignatureIsValid(at: installedHelperURL)
    else { return false }
    return true
  }

  private func codeSignatureIsValid(at url: URL) -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    process.arguments = ["--verify", "--strict", url.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
      try process.run()
      process.waitUntilExit()
      return process.terminationStatus == 0
    } catch {
      return false
    }
  }

  private func readJSONObjectIfPresent(at url: URL) throws -> [String: Any] {
    guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
    return try readJSONObject(at: url)
  }

  private func configurationModificationDate(_ url: URL) -> Date? {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    return attributes?[.modificationDate] as? Date
  }

  private func readJSONObject(at url: URL) throws -> [String: Any] {
    let value = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    guard let root = value as? [String: Any] else {
      throw AgentAdapterInstallError.invalidConfiguration(url)
    }
    return root
  }

  private func writeJSONObject(_ object: [String: Any], to url: URL) throws {
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let data = try JSONSerialization.data(
      withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
  }

  private func removeManagedGroups(
    _ groups: [[String: Any]], product: AgentProduct
  ) -> [[String: Any]] {
    groups.compactMap { group in
      guard let handlers = group["hooks"] as? [[String: Any]] else { return group }
      let retained = handlers.filter {
        guard let command = $0["command"] as? String else { return true }
        return !isManagedCommand(command, product: product)
      }
      if retained.isEmpty { return nil }
      var updated = group
      updated["hooks"] = retained
      return updated
    }
  }

  private func hookCommands(in root: [String: Any]) -> [String] {
    guard let hooks = root["hooks"] as? [String: Any] else { return [] }
    return hooks.values.flatMap { value -> [String] in
      guard let groups = value as? [[String: Any]] else { return [] }
      return groups.flatMap { group -> [String] in
        if let command = group["command"] as? String { return [command] }
        guard let handlers = group["hooks"] as? [[String: Any]] else { return [] }
        return handlers.compactMap { $0["command"] as? String }
      }
    }
  }

  private func isManagedCommand(_ command: String, product: AgentProduct) -> Bool {
    command.contains("CerebroAgentReceiptHook") && command.contains("capture \(product.rawValue)")
  }

  private func jsonString(_ value: String) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    return String(decoding: try encoder.encode(value), as: UTF8.self)
  }
}
