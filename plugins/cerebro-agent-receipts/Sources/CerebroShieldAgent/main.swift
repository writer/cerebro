import Darwin
import Foundation
import ReceiptCore
import Security

enum ShieldAgentStartupError: Error, LocalizedError {
  case untrustedSigningIdentity

  var errorDescription: String? {
    "The shield agent requires an identified publisher signature or an explicit ad-hoc development build."
  }
}

final class ShieldAgentRuntime: @unchecked Sendable {
  private let store: ReceiptStore
  private let signer: DeviceKeySigner
  private let spool: ShieldFallbackSpool
  private let installer: AgentAdapterInstaller
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
  }

  func submit(_ data: Data) throws {
    let draft = try JSONDecoder().decode(ReceiptDraft.self, from: data)
    try submit(draft)
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
  private let clientRequirement: PeerCodeRequirement

  init(runtime: ShieldAgentRuntime, clientRequirement: PeerCodeRequirement) {
    self.runtime = runtime
    self.clientRequirement = clientRequirement
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    guard
      newConnection.effectiveUserIdentifier == geteuid(),
      clientRequirement.accepts(newConnection)
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

  func ping(reply: @escaping (String) -> Void) {
    reply("cerebro-shield-agent.v1")
  }
}

do {
  let runtime = try ShieldAgentRuntime()
  runtime.maintain()
  let service = try ShieldAgentListener(
    runtime: runtime,
    clientRequirement: PeerCodeRequirement(executableURL: ShieldAgentRuntime.bundledHelperURL())
  )
  let listener = NSXPCListener(machServiceName: ShieldServiceContract.machServiceName)
  listener.delegate = service
  listener.resume()

  _ = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in
    runtime.maintain()
  }

  RunLoop.current.run()
} catch {
  FileHandle.standardError.write(
    Data("Cerebro Shield Agent failed: \(error.localizedDescription)\n".utf8))
  exit(1)
}
