import Foundation
import ServiceManagement

enum ShieldBackgroundState: Equatable {
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
    case .failed: return "Background registration failed"
    }
  }
}

@MainActor
enum ShieldBackgroundManager {
  static func ensureRegistered() -> ShieldBackgroundState {
    let service = SMAppService.mainApp
    switch service.status {
    case .enabled:
      return .enabled
    case .requiresApproval:
      return .requiresApproval
    case .notFound:
      return .unavailable
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
    switch SMAppService.mainApp.status {
    case .enabled: return .enabled
    case .requiresApproval: return .requiresApproval
    case .notFound: return .unavailable
    case .notRegistered: return .notRegistered
    @unknown default: return .unavailable
    }
  }
}
