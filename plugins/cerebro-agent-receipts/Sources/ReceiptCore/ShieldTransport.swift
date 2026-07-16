import Darwin
import Foundation

public enum ShieldServiceContract {
  public static let machServiceName = "com.writer.cerebro.agent-receipts.shield-agent"
  public static let launchAgentPlistName =
    "com.writer.cerebro.agent-receipts.shield-agent.v3.plist"
}

public enum ProcessExecutable {
  public static func url() -> URL? {
    var capacity: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &capacity)
    guard capacity > 0 else { return nil }
    var buffer = [CChar](repeating: 0, count: Int(capacity))
    let result = buffer.withUnsafeMutableBufferPointer {
      _NSGetExecutablePath($0.baseAddress, &capacity)
    }
    guard result == 0 else { return nil }
    return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
  }
}

@objc public protocol ShieldServiceXPC {
  func submitDraft(_ data: Data, reply: @escaping (Bool, String?) -> Void)
  func ping(reply: @escaping (String) -> Void)
}

private final class ShieldReplyBox: @unchecked Sendable {
  private let lock = NSLock()
  private var accepted = false

  func set(_ value: Bool) {
    lock.lock()
    accepted = value
    lock.unlock()
  }

  func get() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return accepted
  }
}

public enum ShieldServiceClient {
  public static func submit(
    _ draft: ReceiptDraft,
    timeout: TimeInterval = 2
  ) -> Bool {
    guard let data = try? CanonicalJSON.encode(draft) else { return false }
    let connection = NSXPCConnection(
      machServiceName: ShieldServiceContract.machServiceName,
      options: []
    )
    connection.remoteObjectInterface = NSXPCInterface(with: ShieldServiceXPC.self)
    let reply = ShieldReplyBox()
    let completed = DispatchSemaphore(value: 0)
    connection.resume()
    guard
      let service = connection.remoteObjectProxyWithErrorHandler({ _ in
        completed.signal()
      }) as? ShieldServiceXPC
    else {
      connection.invalidate()
      return false
    }
    service.submitDraft(data) { accepted, _ in
      reply.set(accepted)
      completed.signal()
    }
    let result = completed.wait(timeout: .now() + timeout)
    connection.invalidate()
    return result == .success && reply.get()
  }

  public static func isReachable(timeout: TimeInterval = 0.25) -> Bool {
    let connection = NSXPCConnection(
      machServiceName: ShieldServiceContract.machServiceName,
      options: []
    )
    connection.remoteObjectInterface = NSXPCInterface(with: ShieldServiceXPC.self)
    let reply = ShieldReplyBox()
    let completed = DispatchSemaphore(value: 0)
    connection.resume()
    guard
      let service = connection.remoteObjectProxyWithErrorHandler({ _ in
        completed.signal()
      }) as? ShieldServiceXPC
    else {
      connection.invalidate()
      return false
    }
    service.ping { value in
      reply.set(value == "cerebro-shield-agent.v1")
      completed.signal()
    }
    let result = completed.wait(timeout: .now() + timeout)
    connection.invalidate()
    return result == .success && reply.get()
  }
}

public enum ShieldFallbackSpoolError: Error, LocalizedError {
  case lockFailed(Int32)
  case capacityExceeded

  public var errorDescription: String? {
    switch self {
    case .lockFailed(let code): return "Could not lock the fallback queue (errno \(code))."
    case .capacityExceeded: return "The bounded fallback queue is full."
    }
  }
}

public struct ShieldFallbackSpool: Sendable {
  public let directory: URL
  public let maximumRecords: Int
  public let maximumBytes: Int

  public init(
    directory: URL? = nil,
    maximumRecords: Int = 1_000,
    maximumBytes: Int = 10 * 1_024 * 1_024
  ) {
    self.directory =
      directory
      ?? ReceiptStore.defaultDirectory().appendingPathComponent("fallback", isDirectory: true)
    self.maximumRecords = maximumRecords
    self.maximumBytes = maximumBytes
  }

  public func enqueue(_ draft: ReceiptDraft) throws {
    try withLock {
      try prepareDirectory()
      let data = try CanonicalJSON.encode(draft)
      let records = try recordURLs()
      let bytes = records.reduce(0) { total, url in
        total + ((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
      }
      guard records.count < maximumRecords, bytes + data.count <= maximumBytes else {
        throw ShieldFallbackSpoolError.capacityExceeded
      }
      let monotonic = String(format: "%020llu", DispatchTime.now().uptimeNanoseconds)
      let name = "\(monotonic)-\(UUID().uuidString.lowercased()).json"
      let url = directory.appendingPathComponent(name)
      try data.write(to: url, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
  }

  @discardableResult
  public func drain(_ consume: (ReceiptDraft) throws -> Void) throws -> Int {
    try withLock {
      var drained = 0
      for url in try recordURLs() {
        let draft = try JSONDecoder().decode(ReceiptDraft.self, from: Data(contentsOf: url))
        try consume(draft)
        try FileManager.default.removeItem(at: url)
        drained += 1
      }
      return drained
    }
  }

  public func queuedCount() -> Int {
    (try? recordURLs().count) ?? 0
  }

  private func recordURLs() throws -> [URL] {
    guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
    return try FileManager.default.contentsOfDirectory(
      at: directory,
      includingPropertiesForKeys: [.fileSizeKey],
      options: [.skipsHiddenFiles]
    )
    .filter { $0.pathExtension == "json" }
    .sorted { $0.lastPathComponent < $1.lastPathComponent }
  }

  private func prepareDirectory() throws {
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
  }

  private func withLock<T>(_ operation: () throws -> T) throws -> T {
    try FileManager.default.createDirectory(
      at: directory.deletingLastPathComponent(),
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let lockURL = directory.deletingLastPathComponent().appendingPathComponent("fallback.lock")
    let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw ShieldFallbackSpoolError.lockFailed(errno) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw ShieldFallbackSpoolError.lockFailed(errno)
    }
    defer { flock(descriptor, LOCK_UN) }
    return try operation()
  }
}
