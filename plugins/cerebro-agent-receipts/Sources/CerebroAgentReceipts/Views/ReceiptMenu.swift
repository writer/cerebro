import AppKit
import SwiftUI

struct ReceiptMenu: View {
  @ObservedObject var store: ReceiptViewStore
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Label(statusTitle, systemImage: statusImage)
    Text("\(store.shieldSnapshot.detectedIntegrations) integrations detected")
    Text("\(store.shieldSnapshot.incidents.count) items to review")
    Text(store.backgroundState.label)
    Divider()
    Button("Open Device Status") {
      openWindow(id: "main")
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
    }
    Button("Refresh") { store.reload() }
    Divider()
    Button("Quit Status App") { NSApplication.shared.terminate(nil) }
  }

  private var statusTitle: String {
    switch store.shieldSnapshot.level {
    case .active: return "Collector running"
    case .attention: return "Collection needs attention"
    case .inactive: return "No supported integrations detected"
    }
  }

  private var statusImage: String {
    switch store.shieldSnapshot.level {
    case .active: return "checkmark.shield.fill"
    case .attention: return "exclamationmark.shield.fill"
    case .inactive: return "shield.slash"
    }
  }
}
