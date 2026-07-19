// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "CerebroAgentReceipts",
  platforms: [.macOS(.v14)],
  products: [
    .library(name: "ReceiptCore", targets: ["ReceiptCore"]),
    .executable(name: "CerebroAgentReceiptHook", targets: ["CerebroAgentReceiptHook"]),
    .executable(name: "CerebroShieldAgent", targets: ["CerebroShieldAgent"]),
    .executable(name: "CerebroAgentReceipts", targets: ["CerebroAgentReceipts"]),
    .executable(name: "ReceiptCoreChecks", targets: ["ReceiptCoreChecks"]),
  ],
  targets: [
    .target(
      name: "ReceiptCore",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .executableTarget(
      name: "CerebroAgentReceiptHook",
      dependencies: ["ReceiptCore"]
    ),
    .executableTarget(
      name: "CerebroShieldAgent",
      dependencies: ["ReceiptCore"]
    ),
    .executableTarget(
      name: "CerebroAgentReceipts",
      dependencies: ["ReceiptCore"]
    ),
    .executableTarget(
      name: "ReceiptCoreChecks",
      dependencies: ["ReceiptCore"]
    ),
  ],
  swiftLanguageModes: [.v5]
)
