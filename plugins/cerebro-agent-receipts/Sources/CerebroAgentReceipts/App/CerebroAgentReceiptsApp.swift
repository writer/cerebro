import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    let showStatus = CommandLine.arguments.contains("--show-status")
    NSApp.setActivationPolicy(showStatus ? .regular : .accessory)
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(windowDidClose),
      name: NSWindow.willCloseNotification,
      object: nil
    )
    DispatchQueue.main.async {
      if showStatus {
        NSApp.activate(ignoringOtherApps: true)
      } else {
        NSApp.windows.forEach { $0.close() }
      }
    }
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

  @objc private func windowDidClose(_ notification: Notification) {
    DispatchQueue.main.async {
      if !NSApp.windows.contains(where: { $0.isVisible }) {
        NSApp.setActivationPolicy(.accessory)
      }
    }
  }
}

@main
struct CerebroAgentReceiptsApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @StateObject private var store = ReceiptViewStore()

  var body: some Scene {
    WindowGroup("Cerebro Shield", id: "main") {
      ContentView(store: store)
        .frame(minWidth: 940, minHeight: 620)
    }
    .commands {
      CommandGroup(after: .newItem) {
        Button("Import CloudTrail Events…") { store.showImporter = true }
          .keyboardShortcut("i", modifiers: [.command, .shift])
          .disabled(!store.canImportProviderEvidence)
        Button("Refresh Receipts") { store.reload() }
          .keyboardShortcut("r")
      }
    }

    MenuBarExtra {
      ReceiptMenu(store: store)
    } label: {
      Label("Cerebro Shield", systemImage: shieldImage)
    }
  }

  private var shieldImage: String {
    switch store.shieldSnapshot.level {
    case .active: return "checkmark.shield.fill"
    case .attention: return "exclamationmark.shield.fill"
    case .inactive: return "shield.slash"
    }
  }
}
