# Agent SDK Gateway Architecture

The historical Agent SDK gateway surface is retired on current `main`.

Earlier drafts described a separate tool gateway, managed SDK credentials, and MCP transport. Those packages, route handlers, generation scripts, and Makefile targets are not present in the current bootstrap service, so the public SDKs now expose only supported bootstrap routes.

Future agent-facing APIs should start from the current HTTP/OpenAPI or Connect contracts and add runtime handlers before adding generated client methods or contract docs.
