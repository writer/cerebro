# Shield hardening analysis context

Source root: `/Users/jonathan/Documents/Codex/2026-07-15/figure-out-who-is-running-the/work/cerebro`

This analysis uses the local source and the 2026-07-16 background collector canary. The evidence collection contains eight artifacts: the LaunchAgent runtime, XPC and fallback transport, investigation capability verifier, binary attestation, receipt store, Service Management registration, canary results, and security-boundary README.

The implementation revision at analysis start was `67ddd5ee4dcfa5580e81e3e03509473f4c45f371`; the working tree contained the LaunchAgent implementation described here.
