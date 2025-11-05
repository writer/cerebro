# Cerebro TypeScript SDK

## Installation

```bash
npm install @cerebro/sdk
```

## Quickstart

```ts
import { CerebroSDK, collectCursor } from "@cerebro/sdk";

const sdk = new CerebroSDK({
  baseUrl: "https://api.cerebro.example",
  getAccessToken: async () => process.env.CEREBRO_TOKEN,
});

const backlog = await collectCursor(async (cursor) =>
  sdk.agents.listReviewTasksPage({ cursor, limit: 25 }),
);

console.log(`Loaded ${backlog.length} review tasks`);
```

## Streaming agent responses

```ts
const result = await sdk.agents.sendSessionMessage("session-id", {
  message: "Summarize the latest findings",
  stream: true,
});

if (result.kind === "stream") {
  let buffer = "";
  for await (const chunk of result.stream.text()) {
    buffer += chunk;
  }
  console.log(buffer);
}
```

## HTTP middleware

```ts
const sdk = new CerebroSDK({
  baseUrl: "https://api.cerebro.example",
  beforeRequest: ({ init }) => {
    const headers = new Headers(init.headers);
    headers.set("x-trace-id", crypto.randomUUID());
    init.headers = headers;
  },
  afterResponse: ({ response }) => {
    console.log("status", response.status);
  },
});
```
