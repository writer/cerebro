import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct CerebroAgentReceiptsApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @StateObject private var store = ReceiptViewStore()

  var body: some Scene {
    WindowGroup("Agent execution receipts", id: "main") {
      ContentView(store: store)
        .frame(minWidth: 940, minHeight: 620)
    }
    .commands {
      CommandGroup(after: .newItem) {
        Button("Import CloudTrail Events…") { store.showImporter = true }
          .keyboardShortcut("i", modifiers: [.command, .shift])
        Button("Refresh Receipts") { store.reload() }
          .keyboardShortcut("r")
      }
    }

    MenuBarExtra("Agent receipts", systemImage: "checkmark.seal") {
      ReceiptMenu(store: store)
    }
  }
}
