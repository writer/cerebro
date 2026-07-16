import ReceiptCore
import SwiftUI

struct ShieldOverviewView: View {
  @ObservedObject var store: ReceiptViewStore
  @State private var bootstrapToken = ""
  @State private var enrollmentResult: String?
  @State private var enrollmentInProgress = false

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
            value: "\(store.shieldSnapshot.detectedIntegrations)",
            label: "Integrations detected")
          MetricTile(
            value: "\(store.shieldSnapshot.currentIntegrations)",
            label: "Integrations current")
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

        if deliveryConfigured || deliveryConfigurationError != nil {
          DetailCard(title: "Cerebro delivery") {
            if let deliveryConfigurationError {
              DetailRow(label: "State", value: "Configuration invalid")
              Text(deliveryConfigurationError).foregroundStyle(.red)
            } else if let state = deliveryState {
              DetailRow(label: "State", value: deliveryStateLabel(state))
              if store.deliveryHealth?.stateStorageHealthy == false {
                DetailRow(label: "Status storage", value: "Unavailable")
              }
              DetailRow(label: "Receipts pending", value: "\(state.pendingReceipts)")
              DetailRow(
                label: "Last accepted sequence",
                value: state.lastAcknowledgedSequence.map(String.init) ?? "None")
              DetailRow(label: "Last attempt", value: state.lastAttemptAt ?? "None")
              if let error = state.errorCode {
                DetailRow(label: "Delivery error", value: error)
              }
            } else {
              Text("This device has not reported a delivery attempt.")
                .foregroundStyle(.secondary)
            }
            if deliveryConfigurationError == nil {
              SecureField("One-time bootstrap token", text: $bootstrapToken)
                .textFieldStyle(.roundedBorder)
              Button(enrollmentInProgress ? "Enrolling…" : "Enroll device") {
                enrollDevice()
              }
              .disabled(enrollmentInProgress || bootstrapToken.isEmpty)
              if let enrollmentResult {
                Text(enrollmentResult).foregroundStyle(.secondary)
              }
              Text(
                "The bootstrap token is sent directly to the background collector and is not saved by this app."
              )
              .foregroundStyle(.secondary)
            }
          }
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

  private var deliveryConfigured: Bool {
    guard let configuration = try? ManagedShieldConfiguration.load() else { return false }
    return configuration.receiptUploadEnabled
  }

  private var deliveryConfigurationError: String? {
    do {
      _ = try ManagedShieldConfiguration.load()
      return nil
    } catch {
      return error.localizedDescription
    }
  }

  private var deliveryState: CerebroDeliveryState? {
    let url = ReceiptStore.shieldAgentDirectory().appendingPathComponent("delivery-state.json")
    guard let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(CerebroDeliveryState.self, from: data)
  }

  private func deliveryStateLabel(_ state: CerebroDeliveryState) -> String {
    switch state.state {
    case .notEnrolled: return "Not enrolled"
    case .delivering: return "Delivery in progress"
    case .idle: return "No receipts pending"
    case .accepted: return "Last receipt accepted"
    case .retryableFailure: return "Retry scheduled"
    case .blocked: return "Delivery blocked"
    }
  }

  private func enrollDevice() {
    let token = bootstrapToken
    bootstrapToken = ""
    enrollmentInProgress = true
    enrollmentResult = nil
    Task {
      let result = await Task.detached {
        ShieldServiceClient.enroll(bootstrapToken: token)
      }.value
      enrollmentInProgress = false
      enrollmentResult = result.accepted
        ? "Device enrolled. Pending receipts will be delivered by the background collector."
        : (result.error ?? "Enrollment failed.")
    }
  }

  @ViewBuilder
  private var adminStatus: some View {
    switch store.adminAccess {
    case .authorized(let capability):
      DetailRow(label: "Investigator", value: capability.subject)
      DetailRow(label: "Organization", value: capability.organizationID)
      DetailRow(label: "Operation", value: capability.operation.rawValue)
      DetailRow(label: "Target", value: capability.target)
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
    if deliveryNeedsAttention { return "Collection needs attention" }
    switch store.shieldSnapshot.level {
    case .active: return "Collector is running"
    case .attention: return "Collection needs attention"
    case .inactive: return "No supported integrations detected"
    }
  }

  private var statusDetail: String {
    if deliveryNeedsAttention {
      return "Cerebro delivery is not enrolled, blocked, retrying, stale, or misconfigured."
    }
    switch store.shieldSnapshot.level {
    case .active:
      return
        "All detected integrations are current. Recent events are reported separately."
    case .attention:
      return "One or more adapters, binaries, or evidence records require review."
    case .inactive:
      return "Supported agent tools will appear here after they are detected on this Mac."
    }
  }

  private var statusImage: String {
    if deliveryNeedsAttention { return "exclamationmark.shield.fill" }
    switch store.shieldSnapshot.level {
    case .active: return "checkmark.shield.fill"
    case .attention: return "exclamationmark.shield.fill"
    case .inactive: return "shield.slash"
    }
  }

  private var statusColor: Color {
    if deliveryNeedsAttention { return .orange }
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

  private var deliveryNeedsAttention: Bool {
    if deliveryConfigurationError != nil { return true }
    guard deliveryConfigured else { return false }
    guard
      let deliveryHealth = store.deliveryHealth,
      deliveryHealth.configured,
      deliveryHealth.stateStorageHealthy
    else { return true }
    guard let state = deliveryState,
      let attemptedAt = state.lastAttemptAt.flatMap(ReceiptDate.parse),
      Date().timeIntervalSince(attemptedAt) <= 90
    else { return true }
    switch state.state {
    case .notEnrolled, .retryableFailure, .blocked: return true
    case .delivering, .idle, .accepted: return false
    }
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
