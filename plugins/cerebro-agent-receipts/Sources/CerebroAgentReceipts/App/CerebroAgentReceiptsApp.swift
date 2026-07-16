import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    if CommandLine.arguments.contains("--unregister-agent-and-quit") {
      ShieldBackgroundManager.unregisterForUpdate { error in
        if let error {
          FileHandle.standardError.write(
            Data("Could not unregister Cerebro Shield Agent: \(error.localizedDescription)\n".utf8))
          exit(1)
        }
        Task { @MainActor in
          self.waitForBackgroundUnregistration(remainingAttempts: 100)
        }
      }
      return
    }
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
        for window in NSApp.windows { window.close() }
      }
    }
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

  private func waitForBackgroundUnregistration(remainingAttempts: Int) {
    if ShieldBackgroundManager.state() == .notRegistered {
      NSApplication.shared.terminate(nil)
      return
    }
    guard remainingAttempts > 0 else {
      FileHandle.standardError.write(
        Data("Could not confirm Cerebro Shield Agent unregistration.\n".utf8))
      exit(1)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
      self?.waitForBackgroundUnregistration(remainingAttempts: remainingAttempts - 1)
    }
  }

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
      ShieldMenuLabel(systemImage: shieldImage)
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

private struct ShieldMenuLabel: View {
  @Environment(\.openWindow) private var openWindow
  let systemImage: String

  var body: some View {
    Label("Cerebro Shield", systemImage: systemImage)
      .task {
        guard CommandLine.arguments.contains("--show-status") else { return }
        if !NSApp.windows.contains(where: { $0.canBecomeMain }) {
          openWindow(id: "main")
        }
      }
  }
}
