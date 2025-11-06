# Security Center Vendors & Customers

This document outlines how to work with vendor and customer primitives using the Cerebro TypeScript SDK.

## Listing vendors and customers

```ts
import { CerebroSDK } from "@cerebro/sdk";

const sdk = new CerebroSDK({ baseUrl: process.env.CEREBRO_URL!, apiKey: process.env.CEREBRO_API_KEY! });

const vendorsPage = await sdk.securityCenter.listVendors("org-1", {
  limit: 25,
  category: "security",
  riskLevel: "high",
});

const customersPage = await sdk.securityCenter.listCustomers("org-1", {
  segment: "enterprise",
  lifecycleStage: "active",
});
```

- `cursor` and `limit` provide pagination.
- Vendor filters: `category`, `lifecycleStage`, `riskLevel`.
- Customer filters: `segment`, `lifecycleStage`, `accountManager`.

To retrieve the full set:

```ts
const vendors = await sdk.securityCenter.iterateVendors("org-1", { limit: 50 });
const customers = await sdk.securityCenter.iterateCustomers("org-1", { limit: 50 });
```

## Registering records

```ts
await sdk.securityCenter.registerVendor("org-1", {
  name: "Acme Cloud",
  websiteUrl: "https://acme.example.com",
  category: "security",
  businessCriticality: "high",
});

await sdk.securityCenter.registerCustomer("org-1", {
  name: "Globex",
  accountManager: "csm-jane",
  segment: "enterprise",
  lifecycleStage: "onboarding",
});
```

## Portfolio analytics

```ts
import {
  summarizeVendorPortfolio,
  summarizeCustomerPortfolio,
  assessVendorHealth,
  assessCustomerHealth,
} from "@cerebro/sdk";

const vendorPortfolio = summarizeVendorPortfolio(vendors);
console.log(vendorPortfolio.byRiskLevel);

const vendorHealth = vendors.map((vendor) => assessVendorHealth(vendor));
const overdue = vendorHealth.filter((entry) => entry.reviewStatus === "overdue");

const customerPortfolio = summarizeCustomerPortfolio(customers);
console.log(customerPortfolio.bySegment);

const customerHealth = customers.map((customer) => assessCustomerHealth(customer));
```

Analytics helpers return warnings when required data is missing or non-numeric:

```ts
const [firstVendor] = vendorHealth;
if (firstVendor.warnings.length) {
  console.warn(firstVendor.warnings.join("; "));
}
```

## Troubleshooting

- `401 status code (no body)`: verify API key/token, organization scope, and base URL.
- Empty lists: confirm the organization has access to Security Center and records exist.
- Pagination: pass `cursor` from the previous result to `listVendors`/`listCustomers` to continue.
