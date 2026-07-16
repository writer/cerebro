import Darwin
import Foundation
import ReceiptCore
import Security

enum ShieldAgentStartupError: Error, LocalizedError {
  case untrustedSigningIdentity
  case deliveryNotConfigured

  var errorDescription: String? {
    switch self {
    case .untrustedSigningIdentity:
      return "The shield agent requires an identified publisher signature or an explicit ad-hoc development build."
    case .deliveryNotConfigured:
      return "Receipt delivery is not configured by this organization."
    }
  }
}

final class ShieldAgentRuntime: @unchecked Sendable {
  private let store: ReceiptStore
  private let signer: DeviceKeySigner
  private let spool: ShieldFallbackSpool
  private let installer: AgentAdapterInstaller
  private let delivery: CerebroDeliveryEngine?
  private let deliveryQueue = DispatchQueue(
    label: "com.writer.cerebro.agent-receipts.delivery", qos: .utility)
  private let receiptLock = NSLock()
  private var receiptIDs: Set<String>
  let developmentMode: Bool

  init() throws {
    store = ReceiptStore(directory: ReceiptStore.shieldAgentDirectory())
    guard let executableURL = ProcessExecutable.url() else {
      throw ShieldAgentStartupError.untrustedSigningIdentity
    }
    let executableIdentity = AgentBinaryAttestor.inspect(
      product: .codex,
      executableURL: executableURL
    )
    if executableIdentity.trust == .verifiedPublisher {
      developmentMode = false
      signer = try DeviceKeySigner(keyAccount: "shield-agent-device-signing-key.v1")
    } else if executableIdentity.trust == .validAdHocSignature
      && ProcessInfo.processInfo.environment["CEREBRO_SHIELD_DEVELOPMENT_KEY_FILE"] == "1"
    {
      developmentMode = true
      signer = try DeviceKeySigner(
        developmentKeyFileURL: store.directory.appendingPathComponent("development-signing-key"))
    } else {
      throw ShieldAgentStartupError.untrustedSigningIdentity
    }
    spool = ShieldFallbackSpool()
    installer = AgentAdapterInstaller(bundledHelperURL: Self.bundledHelperURL())
    receiptIDs = Set(try store.readReceipts().map(\.id))
    if
      let managed = try ManagedShieldConfiguration.load(),
      managed.receiptUploadEnabled,
      let baseURL = managed.cerebroBaseURL,
      let hardwareUUID = managed.hardwareUUID
    {
      delivery = CerebroDeliveryEngine(
        configuration: CerebroDeliveryConfiguration(
          baseURL: baseURL, hardwareUUID: hardwareUUID),
        store: store,
        signer: signer,
        cursorStore: FileCerebroCursorStore(
          url: store.directory.appendingPathComponent("delivery-cursor.json")),
        stateStore: FileCerebroDeliveryStateStore(
          url: store.directory.appendingPathComponent("delivery-state.json")))
    } else {
      delivery = nil
    }
  }

  func submit(_ data: Data) throws {
    let draft = try JSONDecoder().decode(ReceiptDraft.self, from: data)
    try submit(draft)
  }

  func enroll(bootstrapToken: String) throws {
    guard let delivery else { throw ShieldAgentStartupError.deliveryNotConfigured }
    try delivery.enroll(bootstrapToken: bootstrapToken)
  }

  func deliveryHealth() -> ShieldDeliveryHealth {
    guard let delivery else {
      return ShieldDeliveryHealth(configured: false, stateStorageHealthy: true)
    }
    return ShieldDeliveryHealth(
      configured: true,
      stateStorageHealthy: delivery.deliveryStateStorageHealthy)
  }

  func maintain() {
    let autoRepair: Bool
    do {
      autoRepair = try ManagedShieldConfiguration.load()?.autoRepair ?? true
    } catch {
      autoRepair = false
    }
    if autoRepair {
      _ = installer.reconcileDetectedAgents()
    }
    if developmentMode {
      _ = try? spool.drain { draft in
        try submit(draft)
      }
    }
    if let delivery {
      deliveryQueue.async {
        delivery.deliverOnce()
      }
    }
  }

  private func submit(_ draft: ReceiptDraft) throws {
    receiptLock.lock()
    defer { receiptLock.unlock() }
    guard !receiptIDs.contains(draft.id) else { return }
    do {
      try store.append(draft: draft, signer: signer)
      receiptIDs.insert(draft.id)
    } catch {
      throw error
    }
  }

  static func bundledHelperURL() -> URL {
    var cursor = ProcessExecutable.url() ?? URL(fileURLWithPath: "/")
    while cursor.pathExtension != "app" && cursor.path != "/" {
      cursor.deleteLastPathComponent()
    }
    return
      cursor
      .appendingPathComponent("Contents/Helpers", isDirectory: true)
      .appendingPathComponent("CerebroAgentReceiptHook")
  }

  static func bundledApplicationURL() -> URL {
    var cursor = ProcessExecutable.url() ?? URL(fileURLWithPath: "/")
    while cursor.pathExtension != "app" && cursor.path != "/" {
      cursor.deleteLastPathComponent()
    }
    return cursor
      .appendingPathComponent("Contents/MacOS", isDirectory: true)
      .appendingPathComponent("CerebroAgentReceipts")
  }
}

final class PeerCodeRequirement: @unchecked Sendable {
  private let requirement: SecRequirement

  init(executableURL: URL) throws {
    var staticCode: SecStaticCode?
    guard
      SecStaticCodeCreateWithPath(executableURL as CFURL, SecCSFlags(), &staticCode)
        == errSecSuccess,
      let staticCode
    else { throw ShieldAgentStartupError.untrustedSigningIdentity }
    var requirement: SecRequirement?
    guard
      SecCodeCopyDesignatedRequirement(staticCode, SecCSFlags(), &requirement) == errSecSuccess,
      let requirement
    else { throw ShieldAgentStartupError.untrustedSigningIdentity }
    self.requirement = requirement
  }

  func accepts(_ connection: NSXPCConnection) -> Bool {
    let attributes =
      [
        kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)
      ] as CFDictionary
    var guestCode: SecCode?
    guard
      SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &guestCode) == errSecSuccess,
      let guestCode
    else { return false }
    return SecCodeCheckValidity(
      guestCode,
      SecCSFlags(rawValue: kSecCSStrictValidate),
      requirement
    ) == errSecSuccess
  }
}

final class ShieldAgentListener: NSObject, NSXPCListenerDelegate, ShieldServiceXPC,
  @unchecked Sendable
{
  private let runtime: ShieldAgentRuntime
  private let clientRequirements: [PeerCodeRequirement]

  init(runtime: ShieldAgentRuntime, clientRequirements: [PeerCodeRequirement]) {
    self.runtime = runtime
    self.clientRequirements = clientRequirements
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    guard
      newConnection.effectiveUserIdentifier == geteuid(),
      clientRequirements.contains(where: { $0.accepts(newConnection) })
    else { return false }
    newConnection.exportedInterface = NSXPCInterface(with: ShieldServiceXPC.self)
    newConnection.exportedObject = self
    newConnection.resume()
    return true
  }

  func submitDraft(_ data: Data, reply: @escaping (Bool, String?) -> Void) {
    do {
      try runtime.submit(data)
      reply(true, nil)
    } catch {
      reply(false, error.localizedDescription)
    }
  }

  func enroll(_ bootstrapToken: String, reply: @escaping (Bool, String?) -> Void) {
    do {
      try runtime.enroll(bootstrapToken: bootstrapToken)
      reply(true, nil)
    } catch {
      reply(false, error.localizedDescription)
    }
  }

  func deliveryHealth(reply: @escaping (Bool, Bool) -> Void) {
    let health = runtime.deliveryHealth()
    reply(health.configured, health.stateStorageHealthy)
  }

  func ping(reply: @escaping (String) -> Void) {
    reply("cerebro-shield-agent.v1")
  }
}

do {
  let runtime = try ShieldAgentRuntime()
  let service = try ShieldAgentListener(
    runtime: runtime,
    clientRequirements: [
      PeerCodeRequirement(executableURL: ShieldAgentRuntime.bundledHelperURL()),
      PeerCodeRequirement(executableURL: ShieldAgentRuntime.bundledApplicationURL()),
    ]
  )
  let listener = NSXPCListener(machServiceName: ShieldServiceContract.machServiceName)
  listener.delegate = service
  listener.resume()

  let maintenanceQueue = DispatchQueue(
    label: "com.writer.cerebro.agent-receipts.shield-agent.maintenance",
    qos: .utility
  )
  maintenanceQueue.async {
    runtime.maintain()
  }

  _ = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in
    maintenanceQueue.async {
      runtime.maintain()
    }
  }

  RunLoop.current.run()
} catch {
  FileHandle.standardError.write(
    Data("Cerebro Shield Agent failed: \(error.localizedDescription)\n".utf8))
  exit(1)
}
