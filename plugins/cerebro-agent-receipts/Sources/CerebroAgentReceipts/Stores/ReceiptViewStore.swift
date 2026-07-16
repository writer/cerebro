import Foundation
import ReceiptCore

@MainActor
final class ReceiptViewStore: ObservableObject {
  @Published private(set) var actions: [ExecutionAction] = []
  @Published private(set) var verifications: [String: ReceiptVerification] = [:]
  @Published private(set) var assessment = AttributionAssessment(
    actionMatches: [:], unmatchedProviderEvents: [])
  @Published private(set) var providerEvents: [ProviderEvent] = []
  @Published var selection: String?
  @Published var filter: ReceiptFilter = .all {
    didSet { selectFirstVisibleItem() }
  }
  @Published var showImporter = false
  @Published var errorMessage: String?

  private let receiptStore: ReceiptStore
  private var timer: Timer?

  init(receiptStore: ReceiptStore = ReceiptStore()) {
    self.receiptStore = receiptStore
    reload()
    timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
      Task { @MainActor in self?.reload(silently: true) }
    }
  }

  var selectedAction: ExecutionAction? {
    guard let selection, selection.hasPrefix("action:") else { return nil }
    let id = String(selection.dropFirst("action:".count))
    return actions.first { $0.id == id }
  }

  var selectedProviderGap: ProviderEvent? {
    guard let selection, selection.hasPrefix("provider:") else { return nil }
    let id = String(selection.dropFirst("provider:".count))
    return assessment.unmatchedProviderEvents.first { $0.id == id }
  }

  var filteredActions: [ExecutionAction] {
    actions.filter { action in
      let match = assessment.actionMatches[action.id]
      switch filter {
      case .all: return true
      case .bound: return match?.level == .providerBound
      case .candidate: return match?.level == .candidateCorrelation
      case .unmatched: return match?.level == .agentCaptured
      case .providerGaps: return false
      case .invalid: return !action.integrityValid
      }
    }
  }

  var showsProviderGaps: Bool { filter == .providerGaps }
  var boundCount: Int { assessment.providerBoundCount }
  var candidateCount: Int { assessment.candidateCount }
  var capturedOnlyCount: Int { assessment.capturedOnlyCount }
  var providerGapCount: Int { assessment.unmatchedProviderEvents.count }
  var invalidCount: Int { actions.filter { !$0.integrityValid }.count }

  func reload(silently: Bool = false) {
    do {
      let receipts = try receiptStore.readReceipts()
      providerEvents = try receiptStore.readProviderEvents()
      let results =
        receipts.isEmpty
        ? []
        : ReceiptVerifier.verify(
          receipts, trustedPublicKeyBase64: try receiptStore.readTrustedPublicKey())
      verifications = Dictionary(uniqueKeysWithValues: results.map { ($0.receiptID, $0) })
      actions = ExecutionActionReducer.reduce(receipts: receipts, verifications: verifications)
      assessment = ReceiptCorrelator.assess(
        actions: actions,
        providerEvents: providerEvents,
        policy: bindingPolicyFromEnvironment()
      )
      if selection == nil { selectFirstVisibleItem() }
      if !silently { errorMessage = nil }
    } catch {
      if !silently { errorMessage = error.localizedDescription }
    }
  }

  func importCloudTrail(from url: URL) {
    do {
      let access = url.startAccessingSecurityScopedResource()
      defer { if access { url.stopAccessingSecurityScopedResource() } }
      let imported = try CloudTrailImporter.parse(Data(contentsOf: url), provenance: .userImported)
      var merged: [String: ProviderEvent] = [:]
      for event in providerEvents + imported { merged[event.id] = event }
      try receiptStore.saveProviderEvents(
        Array(merged.values).sorted { $0.eventTime < $1.eventTime })
      reload()
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  private func selectFirstVisibleItem() {
    if filter == .providerGaps {
      selection = assessment.unmatchedProviderEvents.first.map { "provider:\($0.id)" }
    } else {
      selection = filteredActions.first.map { "action:\($0.id)" }
    }
  }

  private func bindingPolicyFromEnvironment() -> ProviderBindingPolicy? {
    let environment = ProcessInfo.processInfo.environment
    guard
      let account = environment["CEREBRO_EXPECTED_AWS_ACCOUNT_ID"],
      let role = environment["CEREBRO_EXPECTED_AWS_AGENT_ROLE"],
      !account.isEmpty,
      !role.isEmpty
    else { return nil }
    return ProviderBindingPolicy(expectedAccountID: account, expectedAgentRole: role)
  }
}

enum ReceiptFilter: String, CaseIterable, Identifiable {
  case all
  case bound
  case candidate
  case unmatched
  case providerGaps
  case invalid

  var id: String { rawValue }

  var label: String {
    switch self {
    case .all: return "All actions"
    case .bound: return "Bound"
    case .candidate: return "Candidate"
    case .unmatched: return "Local only"
    case .providerGaps: return "Provider gaps"
    case .invalid: return "Invalid"
    }
  }

  var image: String {
    switch self {
    case .all: return "tray.full"
    case .bound: return "link.circle.fill"
    case .candidate: return "questionmark.circle"
    case .unmatched: return "desktopcomputer"
    case .providerGaps: return "exclamationmark.triangle.fill"
    case .invalid: return "xmark.shield"
    }
  }
}
