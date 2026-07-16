import Foundation
import ReceiptCore

@MainActor
final class ReceiptViewStore: ObservableObject {
  @Published private(set) var actions: [ExecutionAction] = []
  @Published private(set) var verifications: [String: ReceiptVerification] = [:]
  @Published private(set) var assessment = AttributionAssessment(
    actionMatches: [:], unmatchedProviderEvents: [])
  @Published private(set) var providerEvents: [ProviderEvent] = []
  @Published private(set) var adapterStatuses: [AgentAdapterStatus] = []
  @Published private(set) var latestValidEventByProduct: [String: Date] = [:]
  @Published var selection: String?
  @Published var sidebarSelection: SidebarSelection = .activity(.all) {
    didSet { selectFirstVisibleItem() }
  }
  @Published var showImporter = false
  @Published var errorMessage: String?
  @Published private(set) var isStale = false
  @Published private(set) var lastRefreshError: String?

  private let receiptStore: ReceiptStore
  private let adapterInstaller: AgentAdapterInstaller
  private var timer: Timer?
  private var reloadInProgress = false
  private var lastAdapterRefresh: Date?

  init(
    receiptStore: ReceiptStore = ReceiptStore(),
    adapterInstaller: AgentAdapterInstaller? = nil
  ) {
    self.receiptStore = receiptStore
    let bundledHelper = Bundle.main.bundleURL
      .appendingPathComponent("Contents/Helpers", isDirectory: true)
      .appendingPathComponent("CerebroAgentReceiptHook")
    self.adapterInstaller =
      adapterInstaller
      ?? AgentAdapterInstaller(bundledHelperURL: bundledHelper)
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
    if let product = selectedProduct {
      return actions.filter { $0.product == product.displayName }
    }
    return actions.filter { action in
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

  var filter: ReceiptFilter {
    guard case .activity(let filter) = sidebarSelection else { return .all }
    return filter
  }

  var selectedProduct: AgentProduct? {
    guard case .agent(let product) = sidebarSelection else { return nil }
    return product
  }

  var selectedAdapterStatus: AgentAdapterStatus? {
    guard let selectedProduct else { return nil }
    return adapterStatuses.first { $0.product == selectedProduct }
  }

  var showsProviderGaps: Bool { filter == .providerGaps }
  var boundCount: Int { assessment.providerBoundCount }
  var candidateCount: Int { assessment.candidateCount }
  var capturedOnlyCount: Int { assessment.capturedOnlyCount }
  var providerGapCount: Int { assessment.unmatchedProviderEvents.count }
  var invalidCount: Int { actions.filter { !$0.integrityValid }.count }

  func actionCount(for product: AgentProduct) -> Int {
    actions.filter { $0.product == product.displayName }.count
  }

  func lastSeen(for product: AgentProduct) -> Date? {
    actions.first { $0.product == product.displayName }?.startedAt
  }

  func recentValidEvent(for product: AgentProduct, now: Date = Date()) -> Date? {
    guard
      let status = adapterStatuses.first(where: { $0.product == product }),
      status.state == .configured || status.state == .managedByPlugin,
      let eventDate = latestValidEventByProduct[product.displayName],
      now.timeIntervalSince(eventDate) >= -30,
      now.timeIntervalSince(eventDate) <= 5 * 60
    else { return nil }
    if let configuredAt = status.configurationModifiedAt, eventDate < configuredAt {
      return nil
    }
    return eventDate
  }

  func installAdapter(_ product: AgentProduct) {
    do {
      try adapterInstaller.install(product)
      adapterStatuses = adapterInstaller.statuses()
      lastAdapterRefresh = Date()
      errorMessage = nil
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  func removeAdapter(_ product: AgentProduct) {
    do {
      try adapterInstaller.remove(product)
      adapterStatuses = adapterInstaller.statuses()
      lastAdapterRefresh = Date()
      errorMessage = nil
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  func reload(silently: Bool = false) {
    guard !reloadInProgress else { return }
    reloadInProgress = true
    let receiptStore = self.receiptStore
    let adapterInstaller = self.adapterInstaller
    let refreshAdapters =
      adapterStatuses.isEmpty || lastAdapterRefresh == nil
      || Date().timeIntervalSince(lastAdapterRefresh ?? .distantPast) >= 30
    let currentAdapterStatuses = adapterStatuses
    Task {
      defer { reloadInProgress = false }
      do {
        let snapshot = try await Task.detached(priority: .utility) {
          try Self.loadSnapshot(
            receiptStore: receiptStore,
            adapterInstaller: adapterInstaller,
            currentAdapterStatuses: currentAdapterStatuses,
            refreshAdapters: refreshAdapters
          )
        }.value
        providerEvents = snapshot.providerEvents
        verifications = snapshot.verifications
        actions = snapshot.actions
        assessment = snapshot.assessment
        adapterStatuses = snapshot.adapterStatuses
        latestValidEventByProduct = snapshot.latestValidEventByProduct
        if refreshAdapters { lastAdapterRefresh = Date() }
        isStale = false
        lastRefreshError = nil
        if selection == nil { selectFirstVisibleItem() }
        if !silently { errorMessage = nil }
      } catch {
        isStale = true
        lastRefreshError = error.localizedDescription
        if !silently { errorMessage = error.localizedDescription }
      }
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
    if selectedProduct != nil {
      selection = nil
      return
    }
    if filter == .providerGaps {
      selection = assessment.unmatchedProviderEvents.first.map { "provider:\($0.id)" }
    } else {
      selection = filteredActions.first.map { "action:\($0.id)" }
    }
  }

  nonisolated private static func loadSnapshot(
    receiptStore: ReceiptStore,
    adapterInstaller: AgentAdapterInstaller,
    currentAdapterStatuses: [AgentAdapterStatus],
    refreshAdapters: Bool
  ) throws -> ReceiptSnapshot {
    let receipts = try receiptStore.readReceipts()
    let providerEvents = try receiptStore.readProviderEvents()
    let results =
      receipts.isEmpty
      ? []
      : ReceiptVerifier.verify(
        receipts, trustedPublicKeyBase64: try receiptStore.readTrustedPublicKey())
    let verifications = Dictionary(uniqueKeysWithValues: results.map { ($0.receiptID, $0) })
    let actions = ExecutionActionReducer.reduce(receipts: receipts, verifications: verifications)
    let validReceiptIDs = Set(results.filter(\.valid).map(\.receiptID))
    var latestValidEventByProduct: [String: Date] = [:]
    for receipt in receipts
    where validReceiptIDs.contains(receipt.id) && receipt.payload.collector != nil {
      guard let capturedAt = receipt.payload.capturedDate else { continue }
      let product = receipt.payload.agent.product
      if capturedAt > (latestValidEventByProduct[product] ?? .distantPast) {
        latestValidEventByProduct[product] = capturedAt
      }
    }
    let assessment = ReceiptCorrelator.assess(
      actions: actions,
      providerEvents: providerEvents,
      policy: bindingPolicyFromEnvironment()
    )
    return ReceiptSnapshot(
      actions: actions,
      verifications: verifications,
      assessment: assessment,
      providerEvents: providerEvents,
      adapterStatuses: refreshAdapters ? adapterInstaller.statuses() : currentAdapterStatuses,
      latestValidEventByProduct: latestValidEventByProduct
    )
  }

  nonisolated private static func bindingPolicyFromEnvironment() -> ProviderBindingPolicy? {
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

private struct ReceiptSnapshot: Sendable {
  let actions: [ExecutionAction]
  let verifications: [String: ReceiptVerification]
  let assessment: AttributionAssessment
  let providerEvents: [ProviderEvent]
  let adapterStatuses: [AgentAdapterStatus]
  let latestValidEventByProduct: [String: Date]
}

enum SidebarSelection: Hashable {
  case activity(ReceiptFilter)
  case agent(AgentProduct)
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
