#![allow(dead_code, unused_imports)]

// Provider-local compile/test seam. Shared crate registration is intentionally
// deferred to its separately owned integration gate.
#[path = "../src/digitalocean/mod.rs"]
mod digitalocean;
