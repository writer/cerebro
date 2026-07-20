import Foundation
import ReceiptCore
import ServiceManagement

enum ShieldBackgroundState: Equatable, Sendable {
  case enabled
  case requiresApproval
  case notRegistered
  case unavailable
  case failed(String)

  var label: String {
    switch self {
    case .enabled: return "Starts at login"
    case .requiresApproval: return "Login approval required"
    case .notRegistered: return "Not registered at login"
    case .unavailable: return "Background registration unavailable"
    case .failed(let message): return "Background registration failed: \(message)"
    }
  }
}

@MainActor
enum ShieldBackgroundManager {
  private static var service: SMAppService {
    SMAppService.agent(plistName: ShieldServiceContract.launchAgentPlistName)
  }

  static func ensureRegistered(forceUpdate: Bool = false) -> ShieldBackgroundState {
    let service = self.service
    if forceUpdate && service.status != .notRegistered {
      do {
        try service.unregister()
        try service.register()
      } catch {
        return .failed(error.localizedDescription)
      }
      return state()
    }
    switch service.status {
    case .enabled:
      return .enabled
    case .requiresApproval:
      return .requiresApproval
    case .notFound:
      do {
        try service.register()
      } catch {
        return .failed(error.localizedDescription)
      }
      return state()
    case .notRegistered:
      do {
        try service.register()
      } catch {
        return .failed(error.localizedDescription)
      }
      return state()
    @unknown default:
      return .unavailable
    }
  }

  static func state() -> ShieldBackgroundState {
    switch service.status {
    case .enabled: return .enabled
    case .requiresApproval: return .requiresApproval
    case .notFound: return .unavailable
    case .notRegistered: return .notRegistered
    @unknown default: return .unavailable
    }
  }

  static func unregisterForUpdate(
    completionHandler: @escaping @Sendable (Error?) -> Void
  ) {
    let service = self.service
    guard service.status != .notRegistered else {
      completionHandler(nil)
      return
    }
    service.unregister(completionHandler: completionHandler)
  }
}
