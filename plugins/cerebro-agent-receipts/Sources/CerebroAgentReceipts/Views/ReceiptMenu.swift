import AppKit
import SwiftUI

struct ReceiptMenu: View {
  @ObservedObject var store: ReceiptViewStore
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Text("\(store.boundCount) provider bound")
    Text("\(store.providerGapCount) provider gaps")
    Divider()
    Button("Open Receipts") {
      openWindow(id: "main")
      NSApp.activate(ignoringOtherApps: true)
    }
    Button("Refresh") { store.reload() }
    Divider()
    Button("Quit") { NSApplication.shared.terminate(nil) }
  }
}
