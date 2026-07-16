import ReceiptCore
import SwiftUI

struct ActionDetailView: View {
  let action: ExecutionAction
  let match: AttributionMatch?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        VStack(alignment: .leading, spacing: 6) {
          Label(stateLabel, systemImage: stateImage)
            .font(.title2.weight(.semibold))
            .foregroundStyle(stateColor)
          Text(stateDescription).foregroundStyle(.secondary)
        }
        DetailCard(title: "Action integrity") {
          DetailRow(
            label: "Local chain",
            value: action.integrityValid ? "Verified against this device key" : "Invalid")
          DetailRow(label: "State", value: action.state.rawValue)
          DetailRow(label: "Action ID", value: action.id)
          DetailRow(label: "Receipt count", value: "\(action.receiptIDs.count)")
        }
        DetailCard(title: "Identity claims") {
          DetailRow(label: "Local user claim", value: action.localUserClaim)
          DetailRow(label: "Claim source", value: action.localUserClaimSource)
          DetailRow(label: "Executor", value: "Codex")
          DetailRow(label: "Model", value: action.model)
          DetailRow(label: "Session", value: action.sessionID)
          DetailRow(label: "Turn", value: action.turnID ?? "Not supplied")
          DetailRow(label: "Tool call", value: action.toolCallID ?? "Not supplied")
        }
        DetailCard(title: "Authorization evidence") {
          DetailRow(
            label: "Observed state",
            value: action.authorizationEvidence.rawValue.replacingOccurrences(of: "_", with: " "))
          Text(action.authorizationEvidence.description).foregroundStyle(.secondary)
        }
        DetailCard(title: "Execution") {
          DetailRow(label: "Action", value: action.actionSummary)
          DetailRow(
            label: "Started",
            value: action.startedAt?.formatted(date: .complete, time: .standard) ?? "Not available")
          DetailRow(
            label: "Completed",
            value: action.completedAt?.formatted(date: .complete, time: .standard) ?? "Not observed"
          )
          DetailRow(label: "Input digest", value: action.inputDigest ?? "Not available")
          DetailRow(label: "Result digest", value: action.resultDigest ?? "Not available")
          DetailRow(label: "Repository", value: action.repositoryRoot ?? "Not a Git worktree")
          DetailRow(label: "Commit", value: action.commit ?? "Not available")
        }
        DetailCard(title: "Provider evidence") {
          if let event = match?.providerEvent {
            DetailRow(label: "Assessment", value: stateLabel)
            DetailRow(label: "Event", value: event.eventName)
            DetailRow(label: "Event ID", value: event.id)
            DetailRow(label: "Principal", value: event.principal ?? "Not supplied")
            DetailRow(
              label: "Provenance",
              value: event.provenance.rawValue.replacingOccurrences(of: "_", with: " "))
            DetailRow(
              label: "Time delta", value: String(format: "%.1f seconds", match?.deltaSeconds ?? 0))
            DetailRow(label: "Evidence", value: match?.evidence.joined(separator: ", ") ?? "None")
          } else {
            Text("No provider event was allocated to this action.").foregroundStyle(.secondary)
          }
        }
      }
      .padding(24)
      .frame(maxWidth: 760, alignment: .leading)
    }
    .navigationTitle(action.actionSummary)
  }

  private var stateLabel: String {
    if !action.integrityValid { return "Invalid local evidence" }
    switch match?.level {
    case .providerBound: return "Provider bound"
    case .candidateCorrelation: return "Candidate correlation"
    default: return "Local evidence only"
    }
  }

  private var stateDescription: String {
    if !action.integrityValid {
      return "One or more receipt signatures, sequences, or chain links failed local verification."
    }
    switch match?.level {
    case .providerBound:
      return
        "An authenticated provider event passed account, role, action ID, action, and time checks."
    case .candidateCorrelation:
      return "A provider event is a one-to-one candidate. It is not a verified binding."
    default: return "The action has local Codex evidence but no allocated provider event."
    }
  }

  private var stateImage: String {
    if !action.integrityValid { return "xmark.shield.fill" }
    switch match?.level {
    case .providerBound: return "link.circle.fill"
    case .candidateCorrelation: return "questionmark.circle.fill"
    default: return "desktopcomputer"
    }
  }

  private var stateColor: Color {
    if !action.integrityValid { return .red }
    switch match?.level {
    case .providerBound: return .green
    case .candidateCorrelation: return .blue
    default: return .orange
    }
  }
}

struct ProviderGapDetailView: View {
  let event: ProviderEvent

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        Label("Provider event without an action", systemImage: "exclamationmark.triangle.fill")
          .font(.title2.weight(.semibold))
          .foregroundStyle(.red)
        Text(
          "This in-scope provider event was not allocated to a completed local execution action."
        )
        .foregroundStyle(.secondary)
        DetailCard(title: "Provider event") {
          DetailRow(label: "Event", value: event.eventName)
          DetailRow(label: "Event ID", value: event.id)
          DetailRow(label: "Principal", value: event.principal ?? "Not supplied")
          DetailRow(label: "Account", value: event.recipientAccountID ?? "Not supplied")
          DetailRow(
            label: "Observed",
            value: event.eventDate?.formatted(date: .complete, time: .standard) ?? event.eventTime)
          DetailRow(
            label: "Provenance",
            value: event.provenance.rawValue.replacingOccurrences(of: "_", with: " "))
          DetailRow(
            label: "Resources",
            value: event.resources.joined(separator: ", ").isEmpty
              ? "Not supplied" : event.resources.joined(separator: ", "))
        }
      }
      .padding(24)
      .frame(maxWidth: 760, alignment: .leading)
    }
    .navigationTitle(event.eventName)
  }
}

struct DetailCard<Content: View>: View {
  let title: String
  @ViewBuilder let content: Content

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(title).font(.headline)
      content
    }
    .padding(16)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
  }
}

struct DetailRow: View {
  let label: String
  let value: String

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 16) {
      Text(label)
        .foregroundStyle(.secondary)
        .frame(width: 120, alignment: .leading)
      Text(value)
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}
