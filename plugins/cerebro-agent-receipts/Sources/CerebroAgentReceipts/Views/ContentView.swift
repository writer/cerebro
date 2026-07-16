import ReceiptCore
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
  @ObservedObject var store: ReceiptViewStore

  var body: some View {
    NavigationSplitView {
      List(selection: $store.sidebarSelection) {
        Section("Device") {
          Label("Status", systemImage: "shield")
            .tag(SidebarSelection.overview)
        }
        Section("Evidence") {
          ForEach(ReceiptFilter.allCases) { filter in
            Label(filter.label, systemImage: filter.image)
              .tag(SidebarSelection.activity(filter))
          }
        }
        Section("Agent connections") {
          ForEach(store.adapterStatuses) { status in
            AdapterSidebarRow(
              status: status,
              actionCount: store.actionCount(for: status.product),
              eventObserved: store.recentValidEvent(for: status.product) != nil
            )
            .tag(SidebarSelection.agent(status.product))
          }
        }
      }
      .listStyle(.sidebar)
      .navigationTitle("Cerebro Shield")
      .navigationSplitViewColumnWidth(min: 170, ideal: 190)
    } content: {
      Group {
        if store.showsOverview {
          List(store.shieldSnapshot.incidents) { incident in
            VStack(alignment: .leading, spacing: 3) {
              Text(incident.title)
              Text(incident.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
            }
            .padding(.vertical, 3)
          }
          .overlay {
            if store.shieldSnapshot.incidents.isEmpty {
              ContentUnavailableView(
                "No items to review",
                systemImage: "checkmark.shield",
                description: Text("Detected adapters and local evidence are current.")
              )
            }
          }
        } else {
          List(selection: $store.selection) {
            if store.showsProviderGaps {
              ForEach(store.assessment.unmatchedProviderEvents) { event in
                ProviderGapRow(event: event)
                  .tag("provider:\(event.id)")
              }
            } else {
              ForEach(store.filteredActions) { action in
                ActionRow(action: action, match: store.assessment.actionMatches[action.id])
                  .tag("action:\(action.id)")
              }
            }
          }
          .overlay {
            if (store.showsProviderGaps && store.assessment.unmatchedProviderEvents.isEmpty)
              || (!store.showsProviderGaps && store.filteredActions.isEmpty)
            {
              ContentUnavailableView(
                "No matching records",
                systemImage: "checkmark.seal",
                description: Text(emptyDescription)
              )
            }
          }
        }
      }
      .navigationTitle(
        store.showsOverview ? "Items to review" : (store.selectedProduct?.displayName ?? store.filter.label)
      )
    } detail: {
      if store.showsOverview {
        ShieldOverviewView(store: store)
      } else if let action = store.selectedAction {
        ActionDetailView(action: action, match: store.assessment.actionMatches[action.id])
      } else if let event = store.selectedProviderGap {
        ProviderGapDetailView(event: event)
      } else if let status = store.selectedAdapterStatus {
        AgentConnectionView(status: status, store: store)
      } else {
        ContentUnavailableView("Select a record", systemImage: "doc.text.magnifyingglass")
      }
    }
    .toolbar {
      ToolbarItemGroup {
        if store.isStale {
          Label("Evidence refresh failed", systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.red)
            .help(store.lastRefreshError ?? "The last evidence refresh failed.")
        }
        Button {
          store.reload()
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        if store.canImportProviderEvidence {
          Button {
            store.showImporter = true
          } label: {
            Label("Import CloudTrail", systemImage: "square.and.arrow.down")
          }
        }
      }
    }
    .fileImporter(
      isPresented: $store.showImporter,
      allowedContentTypes: [.json],
      allowsMultipleSelection: false
    ) { result in
      if case .success(let urls) = result, let url = urls.first {
        store.importCloudTrail(from: url)
      } else if case .failure(let error) = result {
        store.errorMessage = error.localizedDescription
      }
    }
    .alert(
      "Receipt operation failed",
      isPresented: Binding(
        get: { store.errorMessage != nil },
        set: { if !$0 { store.errorMessage = nil } }
      )
    ) {
      Button("OK") { store.errorMessage = nil }
    } message: {
      Text(store.errorMessage ?? "Unknown error")
    }
  }

  private var emptyDescription: String {
    if let product = store.selectedProduct, let status = store.selectedAdapterStatus {
      switch status.state {
      case .notInstalled:
        return "Install capture, then start a new \(product.displayName) session."
      case .needsRepair:
        return "Repair capture, then start a new \(product.displayName) session."
      case .invalidConfiguration, .unmanagedConflict:
        return "Resolve the configuration issue before starting \(product.displayName)."
      case .configured, .managedByPlugin:
        return "Start a new \(product.displayName) session to verify capture."
      }
    }
    return "Run a connected coding agent or import provider events."
  }
}

private struct AdapterSidebarRow: View {
  let status: AgentAdapterStatus
  let actionCount: Int
  let eventObserved: Bool

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: statusImage)
        .foregroundStyle(statusColor)
        .frame(width: 16)
      VStack(alignment: .leading, spacing: 2) {
        Text(status.product.displayName)
        Text("\(statusLabel) · \(actionCount) actions")
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
    }
    .padding(.vertical, 2)
  }

  private var statusLabel: String {
    if eventObserved { return "Recent event" }
    switch status.state {
    case .managedByPlugin: return "Plugin · no event"
    case .configured: return "Configured · no event"
    case .notInstalled: return "Not installed"
    case .needsRepair: return "Repair required"
    case .invalidConfiguration: return "Config error"
    case .unmanagedConflict: return "Path in use"
    }
  }

  private var statusImage: String {
    switch status.state {
    case .managedByPlugin, .configured:
      return eventObserved ? "checkmark.circle.fill" : "circle.dashed"
    case .needsRepair: return "wrench.and.screwdriver.fill"
    case .invalidConfiguration, .unmanagedConflict: return "exclamationmark.triangle.fill"
    case .notInstalled: return "circle"
    }
  }

  private var statusColor: Color {
    switch status.state {
    case .managedByPlugin, .configured: return eventObserved ? .green : .blue
    case .needsRepair: return .orange
    case .invalidConfiguration, .unmanagedConflict: return .red
    case .notInstalled: return .secondary
    }
  }
}

private struct ActionRow: View {
  let action: ExecutionAction
  let match: AttributionMatch?

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: statusImage)
        .foregroundStyle(statusColor)
        .frame(width: 16)
      VStack(alignment: .leading, spacing: 2) {
        Text(action.actionSummary).lineLimit(1)
        Text(rowDetail)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
    }
    .padding(.vertical, 3)
  }

  private var rowDetail: String {
    let date = action.startedAt?.formatted(date: .abbreviated, time: .standard) ?? "unknown time"
    return "\(action.state.rawValue) · \(date)"
  }

  private var statusImage: String {
    if !action.integrityValid { return "xmark.shield.fill" }
    if action.state == .failed { return "xmark.circle.fill" }
    switch match?.level {
    case .providerBound: return "link.circle.fill"
    case .candidateCorrelation: return "questionmark.circle.fill"
    default: return "desktopcomputer"
    }
  }

  private var statusColor: Color {
    if !action.integrityValid { return .red }
    if action.state == .failed { return .red }
    switch match?.level {
    case .providerBound: return .green
    case .candidateCorrelation: return .blue
    default: return .orange
    }
  }
}

private struct ProviderGapRow: View {
  let event: ProviderEvent

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: "exclamationmark.triangle.fill")
        .foregroundStyle(.red)
        .frame(width: 16)
      VStack(alignment: .leading, spacing: 2) {
        Text(event.eventName).lineLimit(1)
        Text(event.eventDate?.formatted(date: .abbreviated, time: .standard) ?? event.eventTime)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
    .padding(.vertical, 3)
  }
}
