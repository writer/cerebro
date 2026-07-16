import ReceiptCore
import SwiftUI

struct ShieldOverviewView: View {
  @ObservedObject var store: ReceiptViewStore

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 22) {
        HStack(alignment: .top, spacing: 16) {
          Image(systemName: statusImage)
            .font(.system(size: 38))
            .foregroundStyle(statusColor)
          VStack(alignment: .leading, spacing: 4) {
            Text(statusTitle)
              .font(.title.weight(.semibold))
            Text(statusDetail)
              .foregroundStyle(.secondary)
          }
          Spacer()
          Text(trustLabel)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(.quaternary, in: Capsule())
        }

        HStack(spacing: 12) {
          MetricTile(
            value: "\(store.shieldSnapshot.detectedAgents)",
            label: "Agents detected")
          MetricTile(
            value: "\(store.shieldSnapshot.conformingAdapters)",
            label: "Adapters current")
          MetricTile(
            value: "\(store.shieldSnapshot.recentAgentEvents)",
            label: "Recently active")
          MetricTile(
            value: "\(store.shieldSnapshot.incidents.count)",
            label: "Items to review")
        }

        DetailCard(title: "Background collection") {
          DetailRow(label: "Login item", value: store.backgroundState.label)
          DetailRow(
            label: "Collector",
            value: store.shieldSnapshot.incidents.contains { $0.kind == .backgroundService }
              ? "Not reachable" : "Running")
          DetailRow(
            label: "Operation",
            value: "Native adapters are discovered and repaired every 30 seconds")
          Text(
            "Agent activity is recorded without opening this window. Closing the window does not stop collection."
          )
          .foregroundStyle(.secondary)
        }

        DetailCard(title: "Detected agent integrations") {
          ForEach(store.adapterStatuses) { status in
            AgentProtectionRow(
              status: status,
              identity: store.binaryIdentities.first { $0.product == status.product },
              hasRecentEvent: store.recentValidEvent(for: status.product) != nil
            )
            if status.product != store.adapterStatuses.last?.product { Divider() }
          }
        }

        DetailCard(title: "Investigation access") {
          adminStatus
        }

        if !store.shieldSnapshot.incidents.isEmpty {
          DetailCard(title: "Items to review") {
            ForEach(store.shieldSnapshot.incidents) { incident in
              HStack(alignment: .top, spacing: 10) {
                Image(
                  systemName: incident.severity == .critical
                    ? "exclamationmark.octagon.fill"
                    : "exclamationmark.triangle.fill"
                )
                .foregroundStyle(incident.severity == .critical ? .red : .orange)
                VStack(alignment: .leading, spacing: 2) {
                  Text(incident.title).fontWeight(.medium)
                  Text(incident.detail).foregroundStyle(.secondary)
                }
              }
            }
          }
        }
      }
      .padding(28)
      .frame(maxWidth: 900, alignment: .leading)
    }
    .navigationTitle("Device status")
  }

  @ViewBuilder
  private var adminStatus: some View {
    switch store.adminAccess {
    case .authorized(let capability):
      DetailRow(label: "Investigator", value: capability.subject)
      DetailRow(label: "Organization", value: capability.organizationID)
      DetailRow(
        label: "Roles",
        value: capability.roles.map(\.rawValue).sorted().joined(separator: ", "))
      DetailRow(label: "Grant ID", value: capability.requestID)
      DetailRow(label: "Expires", value: capability.expiresAt)
    case .unavailable:
      Text("Organization investigation access is not configured on this device.")
      Text(
        "Managed deployments issue short-lived roles after enterprise sign-in and bind them to this device. Local settings cannot grant access."
      )
      .foregroundStyle(.secondary)
    case .denied(let reason):
      Text("Investigation access is unavailable.").fontWeight(.medium)
      Text(reason).foregroundStyle(.red)
    }
  }

  private var statusTitle: String {
    switch store.shieldSnapshot.level {
    case .active: return "Background monitoring is active"
    case .attention: return "Device coverage needs attention"
    case .inactive: return "No supported agents detected"
    }
  }

  private var statusDetail: String {
    switch store.shieldSnapshot.level {
    case .active:
      return
        "Detected agent adapters are current. Recent activity is shown separately from device health."
    case .attention:
      return "One or more adapters, binaries, or evidence records require review."
    case .inactive:
      return "Cerebro will configure supported agents when they appear on this Mac."
    }
  }

  private var statusImage: String {
    switch store.shieldSnapshot.level {
    case .active: return "checkmark.shield.fill"
    case .attention: return "exclamationmark.shield.fill"
    case .inactive: return "shield.slash"
    }
  }

  private var statusColor: Color {
    switch store.shieldSnapshot.level {
    case .active: return .green
    case .attention: return .orange
    case .inactive: return .secondary
    }
  }

  private var trustLabel: String {
    store.shieldSnapshot.trustBoundary == .organizationManaged
      ? "Organization managed"
      : "Development trust"
  }
}

private struct MetricTile: View {
  let value: String
  let label: String

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(value).font(.title2.weight(.semibold))
      Text(label).font(.caption).foregroundStyle(.secondary)
    }
    .padding(14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.7), in: RoundedRectangle(cornerRadius: 10))
  }
}

private struct AgentProtectionRow: View {
  let status: AgentAdapterStatus
  let identity: AgentBinaryIdentity?
  let hasRecentEvent: Bool

  var body: some View {
    HStack(spacing: 12) {
      Image(systemName: rowImage)
        .foregroundStyle(rowColor)
        .frame(width: 18)
      VStack(alignment: .leading, spacing: 2) {
        Text(status.product.displayName).fontWeight(.medium)
        Text(rowDetail).font(.caption).foregroundStyle(.secondary)
      }
      Spacer()
      Text(binaryLabel).font(.caption).foregroundStyle(.secondary)
    }
    .padding(.vertical, 3)
  }

  private var rowDetail: String {
    if !status.executableAvailable { return "Not detected" }
    switch status.state {
    case .configured, .managedByPlugin:
      return hasRecentEvent ? "Adapter current · recent event" : "Adapter current · idle"
    case .notInstalled: return "Adapter missing"
    case .needsRepair: return "Adapter changed"
    case .invalidConfiguration: return "Configuration invalid"
    case .unmanagedConflict: return "Managed path in use"
    }
  }

  private var binaryLabel: String {
    guard let identity, identity.path != nil else { return "" }
    switch identity.trust {
    case .verifiedPublisher: return identity.teamIdentifier ?? "Signed"
    case .validAdHocSignature: return "Ad hoc signature"
    case .unsigned: return "Unsigned"
    case .invalidSignature: return "Invalid signature"
    case .unavailable: return ""
    }
  }

  private var rowImage: String {
    guard status.executableAvailable else { return "circle" }
    switch status.state {
    case .configured, .managedByPlugin: return "checkmark.circle.fill"
    case .notInstalled, .needsRepair: return "exclamationmark.triangle.fill"
    case .invalidConfiguration, .unmanagedConflict: return "xmark.octagon.fill"
    }
  }

  private var rowColor: Color {
    guard status.executableAvailable else { return .secondary }
    switch status.state {
    case .configured, .managedByPlugin: return .green
    case .notInstalled, .needsRepair: return .orange
    case .invalidConfiguration, .unmanagedConflict: return .red
    }
  }
}
