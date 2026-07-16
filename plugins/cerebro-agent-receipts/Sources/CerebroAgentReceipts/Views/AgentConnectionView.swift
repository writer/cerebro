import AppKit
import ReceiptCore
import SwiftUI

struct AgentConnectionView: View {
  let status: AgentAdapterStatus
  @ObservedObject var store: ReceiptViewStore

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        VStack(alignment: .leading, spacing: 6) {
          Label(statusLabel, systemImage: statusImage)
            .font(.title2.weight(.semibold))
            .foregroundStyle(statusColor)
          Text(statusDescription)
            .foregroundStyle(.secondary)
        }

        HStack {
          primaryAction
          if status.state == .configured || status.state == .needsRepair {
            Button("Remove capture", role: .destructive) {
              store.removeAdapter(status.product)
            }
          }
          if let path = status.configurationPath {
            Button("Show configuration") {
              let url = URL(fileURLWithPath: path)
              if FileManager.default.fileExists(atPath: path) {
                NSWorkspace.shared.activateFileViewerSelecting([url])
              } else {
                NSWorkspace.shared.open(url.deletingLastPathComponent())
              }
            }
          }
        }

        DetailCard(title: "Connection") {
          DetailRow(label: "Agent", value: status.product.displayName)
          DetailRow(label: "Adapter", value: integrationLabel)
          DetailRow(
            label: "Executable", value: status.executableAvailable ? "Detected" : "Not detected")
          DetailRow(
            label: "Capture", value: hasObservedEvent ? "Event observed" : "No event observed")
          if let helperCurrent = status.helperCurrent {
            DetailRow(
              label: "Helper", value: helperCurrent ? "Current bundle build" : "Repair required")
          }
          DetailRow(label: "Recorded actions", value: "\(store.actionCount(for: status.product))")
          DetailRow(
            label: "Last action",
            value: store.lastSeen(for: status.product)?.formatted(
              date: .abbreviated, time: .standard) ?? "None recorded")
          if let path = status.configurationPath {
            DetailRow(label: "Configuration", value: path)
          }
        }

        DetailCard(title: "Evidence boundary") {
          Text(evidenceBoundary)
            .foregroundStyle(.secondary)
        }
      }
      .padding(24)
      .frame(maxWidth: 760, alignment: .leading)
    }
    .navigationTitle(status.product.displayName)
  }

  @ViewBuilder
  private var primaryAction: some View {
    switch status.state {
    case .notInstalled:
      Button("Install capture") { store.installAdapter(status.product) }
        .buttonStyle(.borderedProminent)
    case .needsRepair:
      Button("Repair capture") { store.installAdapter(status.product) }
        .buttonStyle(.borderedProminent)
    case .configured:
      Button("Repair capture") { store.installAdapter(status.product) }
    case .managedByPlugin:
      Text("Managed by the Codex plugin")
        .foregroundStyle(.secondary)
    case .invalidConfiguration:
      Text("Fix the JSON configuration before installing capture.")
        .foregroundStyle(.red)
    case .unmanagedConflict:
      Text("Move or remove the existing unmanaged plugin before installing capture.")
        .foregroundStyle(.red)
    }
  }

  private var statusLabel: String {
    switch status.state {
    case .managedByPlugin:
      return hasObservedEvent ? "Agent event observed" : "Capture managed by plugin"
    case .configured:
      return hasObservedEvent ? "Agent event observed" : "Capture configured"
    case .notInstalled: return "Capture not installed"
    case .needsRepair: return "Capture needs repair"
    case .invalidConfiguration: return "Configuration cannot be read"
    case .unmanagedConflict: return "Plugin path is already in use"
    }
  }

  private var statusDescription: String {
    switch status.state {
    case .managedByPlugin:
      return hasObservedEvent
        ? "Cerebro recorded a lifecycle event from the Codex plugin."
        : "Start a new Codex session to verify the plugin hook."
    case .configured:
      return hasObservedEvent
        ? "Cerebro recorded a lifecycle event through this adapter."
        : "Start a new agent session to load the adapter and verify capture."
    case .notInstalled:
      return "No Cerebro event adapter is present in this agent's local configuration."
    case .needsRepair:
      return "The adapter points to an older receipt helper and must be updated."
    case .invalidConfiguration:
      return "Cerebro will not replace an existing configuration that is not valid JSON."
    case .unmanagedConflict:
      return "Cerebro will not replace an existing OpenCode plugin at the managed path."
    }
  }

  private var integrationLabel: String {
    switch status.product.integration {
    case .nativeHook: return "Native lifecycle hooks"
    case .pluginEvent: return "Native plugin event bus"
    case .structuredStream: return "Structured event stream"
    }
  }

  private var evidenceBoundary: String {
    switch status.product {
    case .codex, .droid, .claudeCode:
      return
        "Command hooks record the lifecycle events supplied by the local agent. Disabled hooks, manual terminal commands, and remote sessions outside this configuration are not observed."
    case .cursor:
      return
        "User-level Cursor hooks cover local sessions. Cloud agents only receive project-level hooks, so this local connection does not claim cloud coverage."
    case .openCode:
      return
        "The OpenCode plugin records session and tool events exposed by the plugin API. It does not observe commands run outside OpenCode."
    }
  }

  private var statusImage: String {
    switch status.state {
    case .managedByPlugin, .configured:
      return hasObservedEvent ? "checkmark.circle.fill" : "circle.dashed"
    case .needsRepair: return "wrench.and.screwdriver.fill"
    case .notInstalled: return "circle"
    case .invalidConfiguration, .unmanagedConflict: return "exclamationmark.triangle.fill"
    }
  }

  private var statusColor: Color {
    switch status.state {
    case .managedByPlugin, .configured: return hasObservedEvent ? .green : .blue
    case .needsRepair: return .orange
    case .notInstalled: return .secondary
    case .invalidConfiguration, .unmanagedConflict: return .red
    }
  }

  private var hasObservedEvent: Bool {
    store.actionCount(for: status.product) > 0
  }
}
