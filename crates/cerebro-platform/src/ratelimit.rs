//! Edge rate limiting and request-origin trust for the Rust platform server.
//!
//! This module ports the Go bootstrap edge protections to axum middleware:
//!
//! - `internal/bootstrap/ratelimit.go`: per-client-IP token bucket rate
//!   limiting (`golang.org/x/time/rate` semantics) with exempt path prefixes
//!   and a plain-text `429 Too Many Requests` response.
//! - `internal/bootstrap/request_origin.go`: trusted-proxy client IP
//!   resolution, honoring `X-Forwarded-For` only when the direct peer is
//!   inside an operator-configured trusted proxy CIDR, with either an explicit
//!   trusted hop count or automatic trailing trusted hop counting.
//!
//! Configuration reads the same service-neutral environment variables as the
//! Go bootstrap service: `CEREBRO_RATE_LIMIT_ENABLED`,
//! `CEREBRO_RATE_LIMIT_RPS`, `CEREBRO_RATE_LIMIT_BURST`,
//! `CEREBRO_RATE_LIMIT_EXEMPT_PATHS`, `CEREBRO_TRUSTED_PROXY_CIDRS`, and
//! `CEREBRO_TRUSTED_PROXY_COUNT`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Default exempt path prefixes, mirroring the Go bootstrap defaults
/// (`/healthz`, `/livez`, `/metrics`, `/.well-known/`) plus `/readyz`, the
/// Rust platform server's readiness probe path.
const DEFAULT_EXEMPT_PATHS: &[&str] =
    &["/healthz", "/livez", "/readyz", "/metrics", "/.well-known/"];

/// How long a per-IP bucket may sit idle before it is evicted. Mirrors the Go
/// limiter's 10 minute stale cutoff.
const STALE_AFTER: Duration = Duration::from_secs(10 * 60);

/// How often stale buckets are evicted. Mirrors the Go limiter's 5 minute
/// cleanup interval (the Go side uses a background goroutine; here cleanup
/// runs opportunistically during request checks, which is observably
/// equivalent).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Controls global API rate limiting. Mirrors Go `config.RateLimitConfig`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RateLimitConfig {
    pub(crate) enabled: bool,
    pub(crate) requests_per_second: f64,
    pub(crate) burst_size: usize,
    /// Route path prefixes that bypass rate limiting (liveness, metrics).
    pub(crate) exempt_paths: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100.0,
            burst_size: 150,
            exempt_paths: DEFAULT_EXEMPT_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
        }
    }
}

/// Controls how the server reconstructs client IPs when requests traverse
/// explicitly trusted reverse proxies. Mirrors Go `config.RequestOriginConfig`
/// (the `PublicOrigin` field is not needed for client IP resolution and is not
/// ported).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct RequestOriginConfig {
    pub(crate) trusted_proxy_cidrs: Vec<String>,
    pub(crate) trusted_proxy_count: usize,
}

/// Reads the edge configuration from the provided lookup, mirroring the Go
/// `internal/config` parsing rules for the shared environment variable names.
fn edge_config_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(RateLimitConfig, RequestOriginConfig), String> {
    let enabled = parse_bool_value(
        "CEREBRO_RATE_LIMIT_ENABLED",
        lookup("CEREBRO_RATE_LIMIT_ENABLED"),
        true,
    )?;
    let requests_per_second = parse_float_value(
        "CEREBRO_RATE_LIMIT_RPS",
        lookup("CEREBRO_RATE_LIMIT_RPS"),
        100.0,
    )?;
    let burst_size = parse_int_value(
        "CEREBRO_RATE_LIMIT_BURST",
        lookup("CEREBRO_RATE_LIMIT_BURST"),
        150,
    )?;
    let mut exempt_paths = parse_csv(
        lookup("CEREBRO_RATE_LIMIT_EXEMPT_PATHS")
            .as_deref()
            .unwrap_or(""),
    );
    if exempt_paths.is_empty() {
        exempt_paths = DEFAULT_EXEMPT_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect();
    }
    let trusted_proxy_cidrs = parse_csv(
        lookup("CEREBRO_TRUSTED_PROXY_CIDRS")
            .as_deref()
            .unwrap_or(""),
    );
    for raw_cidr in &trusted_proxy_cidrs {
        if parse_cidr(raw_cidr).is_none() {
            return Err(format!(
                "CEREBRO_TRUSTED_PROXY_CIDRS contains invalid CIDR {raw_cidr:?}"
            ));
        }
    }
    let trusted_proxy_count = parse_int_value(
        "CEREBRO_TRUSTED_PROXY_COUNT",
        lookup("CEREBRO_TRUSTED_PROXY_COUNT"),
        0,
    )?;
    Ok((
        RateLimitConfig {
            enabled,
            requests_per_second,
            burst_size,
            exempt_paths,
        },
        RequestOriginConfig {
            trusted_proxy_cidrs,
            trusted_proxy_count,
        },
    ))
}

/// Mirrors Go `parseBoolEnvDefault`/`parseBoolEnv`.
fn parse_bool_value(name: &str, raw: Option<String>, default: bool) -> Result<bool, String> {
    let raw = raw.unwrap_or_default();
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(default);
    }
    match value.as_str() {
        "1" | "t" | "true" | "y" | "yes" | "on" => Ok(true),
        "0" | "f" | "false" | "n" | "no" | "off" => Ok(false),
        _ => Err(format!("{name} must be a boolean")),
    }
}

/// Mirrors Go `parseFloatEnv`: empty means default, negatives are rejected.
fn parse_float_value(name: &str, raw: Option<String>, default: f64) -> Result<f64, String> {
    let raw = raw.unwrap_or_default();
    let value = raw.trim();
    if value.is_empty() {
        return Ok(default);
    }
    let parsed: f64 = value
        .parse()
        .map_err(|error| format!("parse {name}: {error}"))?;
    if parsed < 0.0 {
        return Err(format!("{name} must be greater than or equal to zero"));
    }
    Ok(parsed)
}

/// Mirrors Go `parseIntEnv`: empty means default, negatives are rejected.
fn parse_int_value(name: &str, raw: Option<String>, default: usize) -> Result<usize, String> {
    let raw = raw.unwrap_or_default();
    let value = raw.trim();
    if value.is_empty() {
        return Ok(default);
    }
    let parsed: i64 = value
        .parse()
        .map_err(|error| format!("parse {name}: {error}"))?;
    usize::try_from(parsed).map_err(|_| format!("{name} must be greater than or equal to zero"))
}

/// Mirrors Go `parseCSV`: split on commas, trim, drop empties, dedupe while
/// preserving first-seen order.
fn parse_csv(raw: &str) -> Vec<String> {
    let mut values = Vec::new();
    for item in raw.split(',') {
        let value = item.trim();
        if value.is_empty() || values.iter().any(|existing| existing == value) {
            continue;
        }
        values.push(value.to_owned());
    }
    values
}

/// Mirrors Go `accessAuditRemoteIP`: strip a port when present, otherwise
/// accept a bare IP, otherwise return empty.
fn access_audit_remote_ip(remote_addr: &str) -> String {
    let remote = remote_addr.trim();
    if remote.is_empty() {
        return String::new();
    }
    if let Some(host) = split_host_port(remote) {
        return host.trim_matches(|c| c == '[' || c == ']').to_owned();
    }
    if let Some(ip) = parse_ip(remote) {
        return canonical_ip(ip);
    }
    String::new()
}

/// Mirrors Go `net.SplitHostPort` closely enough for IP-based remote
/// addresses: `host:port` and `[host]:port` succeed; bare IPv6 addresses and
/// values without a port fail.
fn split_host_port(value: &str) -> Option<String> {
    let colon = value.rfind(':')?;
    let host = &value[..colon];
    if let Some(rest) = host.strip_prefix('[') {
        let inner = rest.strip_suffix(']')?;
        Some(inner.to_owned())
    } else {
        if host.contains(':') || host.contains(']') {
            return None;
        }
        Some(host.to_owned())
    }
}

/// Mirrors Go `net.ParseIP` for the inputs this path sees.
fn parse_ip(value: &str) -> Option<IpAddr> {
    value.parse().ok()
}

/// Mirrors Go `net.IP.String()` canonicalization: IPv4-mapped IPv6 addresses
/// render as plain IPv4.
fn canonical_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
    }
}

/// Parses a CIDR (`address/prefix`), returning the network address and prefix
/// length. Mirrors Go `net.ParseCIDR` for well-formed inputs.
fn parse_cidr(raw: &str) -> Option<(IpAddr, u8)> {
    let raw = raw.trim();
    let (address, prefix) = raw.split_once('/')?;
    let mut ip = parse_ip(address)?;
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if prefix.len() > 1 && prefix.starts_with('0') {
        return None;
    }
    let mut prefix: u8 = prefix.parse().ok()?;
    // Normalize IPv4-mapped IPv6 networks (e.g. ::ffff:10.0.0.0/104) to IPv4.
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
        && prefix >= 96
    {
        ip = IpAddr::V4(v4);
        prefix -= 96;
    }
    match ip {
        IpAddr::V4(_) if prefix > 32 => None,
        IpAddr::V6(_) if prefix > 128 => None,
        _ => Some((ip, prefix)),
    }
}

/// Whether the network identified by (`network`, `prefix`) contains `ip`,
/// following Go `net.IPNet.Contains` semantics (IPv4-mapped IPv6 addresses
/// compare as IPv4; families must otherwise match).
fn cidr_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    };
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            (u32::from_be_bytes(network.octets()) & mask)
                == (u32::from_be_bytes(ip.octets()) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            (u128::from_be_bytes(network.octets()) & mask)
                == (u128::from_be_bytes(ip.octets()) & mask)
        }
        _ => false,
    }
}

/// Mirrors Go `forwardedHopTrusted` / `requestOriginTrustsProxy`: whether the
/// IP falls inside any trusted proxy CIDR. Malformed CIDR entries are skipped.
fn hop_trusted(ip: IpAddr, cfg: &RequestOriginConfig) -> bool {
    cfg.trusted_proxy_cidrs.iter().any(|raw_cidr| {
        parse_cidr(raw_cidr)
            .map(|(network, prefix)| cidr_contains(network, prefix, ip))
            .unwrap_or(false)
    })
}

/// Mirrors Go `trailingTrustedForwardedHops`: counts trailing `X-Forwarded-For`
/// entries that parse as IPs inside a trusted proxy CIDR.
fn trailing_trusted_hops(parts: &[&str], cfg: &RequestOriginConfig) -> usize {
    let mut count = 0;
    for part in parts.iter().rev() {
        match parse_ip(part.trim()) {
            Some(ip) if hop_trusted(ip, cfg) => count += 1,
            _ => break,
        }
    }
    count
}

/// Mirrors Go `forwardedClientIP`: derives the client IP from an
/// `X-Forwarded-For` header. When `trusted_proxy_count` is zero, the number of
/// trailing trusted hops is counted automatically; the first parseable entry
/// before those hops (scanning right to left) wins. As a fallback, the
/// right-most parseable non-trusted entry wins.
fn forwarded_client_ip(header: &str, cfg: &RequestOriginConfig) -> String {
    let parts: Vec<&str> = header.split(',').collect();
    let trusted_proxy_count = if cfg.trusted_proxy_count > 0 {
        cfg.trusted_proxy_count
    } else {
        trailing_trusted_hops(&parts, cfg)
    };
    if trusted_proxy_count < parts.len() {
        for part in parts[..parts.len() - trusted_proxy_count].iter().rev() {
            if let Some(ip) = parse_ip(part.trim()) {
                return canonical_ip(ip);
            }
        }
    }
    for part in parts.iter().rev() {
        if let Some(ip) = parse_ip(part.trim())
            && !hop_trusted(ip, cfg)
        {
            return canonical_ip(ip);
        }
    }
    String::new()
}

/// Derives the rate limiting key for a request, mirroring the composition of
/// Go `resolveRequestOrigin` (client IP portion) and `rateLimiter.clientIP`:
/// `X-Forwarded-For` is honored only when the direct peer address is inside a
/// trusted proxy CIDR; otherwise the peer address is used; an unresolvable
/// origin maps to `"unknown"`.
pub(crate) fn resolve_client_ip(
    remote_addr: &str,
    forwarded_for: &str,
    cfg: &RequestOriginConfig,
) -> String {
    let remote_ip = access_audit_remote_ip(remote_addr);
    let trusted_proxy = parse_ip(&remote_ip).is_some_and(|ip| hop_trusted(ip, cfg));
    let mut client_ip = if trusted_proxy {
        forwarded_client_ip(forwarded_for, cfg)
    } else {
        String::new()
    };
    if client_ip.is_empty() {
        client_ip = remote_ip;
    }
    let client_ip = client_ip.trim();
    if client_ip.is_empty() {
        return "unknown".to_owned();
    }
    if let Some(host) = split_host_port(client_ip) {
        return host;
    }
    client_ip.to_owned()
}

/// One per-client token bucket with `golang.org/x/time/rate` `Allow`
/// semantics: buckets start full at `burst`, refill continuously at
/// `requests_per_second`, and an allowance consumes one token.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_access: Instant,
}

#[derive(Debug)]
struct LimiterState {
    buckets: HashMap<String, Bucket>,
    last_cleanup: Instant,
}

/// Per-client-IP token bucket rate limiter mirroring the Go bootstrap
/// `rateLimiter`.
#[derive(Debug)]
pub(crate) struct EdgeRateLimiter {
    rate_limit: RateLimitConfig,
    origin: RequestOriginConfig,
    cleanup_interval: Duration,
    inner: Mutex<LimiterState>,
}

impl EdgeRateLimiter {
    fn with_cleanup_interval(
        rate_limit: RateLimitConfig,
        origin: RequestOriginConfig,
        cleanup_interval: Duration,
        now: Instant,
    ) -> Self {
        Self {
            rate_limit,
            origin,
            cleanup_interval,
            inner: Mutex::new(LimiterState {
                buckets: HashMap::new(),
                last_cleanup: now,
            }),
        }
    }

    pub(crate) fn new(rate_limit: RateLimitConfig, origin: RequestOriginConfig) -> Self {
        Self::with_cleanup_interval(rate_limit, origin, CLEANUP_INTERVAL, Instant::now())
    }

    /// Mirrors Go `rateLimiter.isExemptPath`: prefix match against the exempt
    /// path list.
    fn is_exempt_path(&self, path: &str) -> bool {
        self.rate_limit
            .exempt_paths
            .iter()
            .any(|exempt| path.starts_with(exempt.as_str()))
    }

    fn lock(&self) -> MutexGuard<'_, LimiterState> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Removes buckets idle longer than the stale cutoff once per cleanup
    /// interval. Mirrors Go `cleanupStaleLimiters`, run opportunistically
    /// instead of on a background goroutine.
    fn maybe_cleanup(state: &mut LimiterState, cleanup_interval: Duration, now: Instant) {
        if now.duration_since(state.last_cleanup) < cleanup_interval {
            return;
        }
        state.last_cleanup = now;
        state
            .buckets
            .retain(|_, bucket| now.duration_since(bucket.last_access) <= STALE_AFTER);
    }

    /// Whether one request from `key` is allowed at `now`.
    fn allow(&self, key: &str, now: Instant) -> bool {
        let burst = self.rate_limit.burst_size as f64;
        let mut state = self.lock();
        Self::maybe_cleanup(&mut state, self.cleanup_interval, now);
        let bucket = state.buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
            last_access: now,
        });
        bucket.last_access = now;
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_limit.requests_per_second).min(burst);
        bucket.last_refill = now;
        if burst >= 1.0 && bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether the request may proceed. Mirrors the decision order of the Go
    /// middleware: disabled short-circuits, exempt paths bypass, then the
    /// per-client-IP bucket is consulted.
    pub(crate) fn check(
        &self,
        path: &str,
        remote_addr: &str,
        forwarded_for: &str,
        now: Instant,
    ) -> bool {
        if !self.rate_limit.enabled {
            return true;
        }
        if self.is_exempt_path(path) {
            return true;
        }
        let client_ip = resolve_client_ip(remote_addr, forwarded_for, &self.origin);
        self.allow(&client_ip, now)
    }
}

/// Shared middleware state wrapping the limiter.
#[derive(Clone, Debug)]
pub(crate) struct EdgeRateLimit {
    limiter: Arc<EdgeRateLimiter>,
}

impl EdgeRateLimit {
    pub(crate) fn with_config(rate_limit: RateLimitConfig, origin: RequestOriginConfig) -> Self {
        Self {
            limiter: Arc::new(EdgeRateLimiter::new(rate_limit, origin)),
        }
    }

    /// Builds the middleware state from the shared environment variables.
    pub(crate) fn from_env() -> Result<Self, String> {
        let (rate_limit, origin) = edge_config_from_lookup(|name| std::env::var(name).ok())?;
        Ok(Self::with_config(rate_limit, origin))
    }
}

/// Mirrors the Go limit response (`http.Error` with
/// `http.StatusTooManyRequests`): plain text status line body, UTF-8 text
/// content type, and `X-Content-Type-Options: nosniff`.
fn too_many_requests() -> Response {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests\n").into_response();
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// axum middleware entrypoint applying the edge rate limit.
pub(crate) async fn enforce(
    State(edge): State<EdgeRateLimit>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let remote_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.to_string())
        .unwrap_or_default();
    let forwarded_for = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if edge
        .limiter
        .check(&path, &remote_addr, &forwarded_for, Instant::now())
    {
        next.run(request).await
    } else {
        too_many_requests()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn origin(cidrs: &[&str], count: usize) -> RequestOriginConfig {
        RequestOriginConfig {
            trusted_proxy_cidrs: cidrs.iter().map(|cidr| (*cidr).to_owned()).collect(),
            trusted_proxy_count: count,
        }
    }

    #[test]
    fn parse_csv_trims_dedupes_and_drops_empties() {
        assert_eq!(
            parse_csv(" a , b ,a,, c ,b "),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
        assert!(parse_csv("").is_empty());
        assert!(parse_csv(" , ,").is_empty());
    }

    #[test]
    fn parse_bool_value_mirrors_go_semantics() {
        for value in ["1", "t", "TRUE", "y", "Yes", "on"] {
            assert_eq!(
                parse_bool_value("N", Some(value.to_owned()), false),
                Ok(true)
            );
        }
        for value in ["0", "f", "False", "n", "NO", "off"] {
            assert_eq!(
                parse_bool_value("N", Some(value.to_owned()), true),
                Ok(false)
            );
        }
        assert_eq!(parse_bool_value("N", None, true), Ok(true));
        assert_eq!(
            parse_bool_value("N", Some("  ".to_owned()), false),
            Ok(false)
        );
        assert_eq!(
            parse_bool_value("N", Some("maybe".to_owned()), false),
            Err("N must be a boolean".to_owned())
        );
    }

    #[test]
    fn parse_float_value_defaults_and_rejects_negatives() {
        assert_eq!(parse_float_value("N", None, 100.0), Ok(100.0));
        assert_eq!(parse_float_value("N", Some(" ".to_owned()), 7.5), Ok(7.5));
        assert_eq!(parse_float_value("N", Some("2.5".to_owned()), 0.0), Ok(2.5));
        assert!(parse_float_value("N", Some("-1".to_owned()), 0.0).is_err());
        assert!(parse_float_value("N", Some("abc".to_owned()), 0.0).is_err());
    }

    #[test]
    fn parse_int_value_defaults_and_rejects_negatives() {
        assert_eq!(parse_int_value("N", None, 150), Ok(150));
        assert_eq!(parse_int_value("N", Some("".to_owned()), 3), Ok(3));
        assert_eq!(parse_int_value("N", Some(" 42 ".to_owned()), 0), Ok(42));
        assert!(parse_int_value("N", Some("-1".to_owned()), 0).is_err());
        assert!(parse_int_value("N", Some("4.2".to_owned()), 0).is_err());
    }

    #[test]
    fn edge_config_defaults_mirror_go_bootstrap() {
        let (rate_limit, origin) = edge_config_from_lookup(lookup_from(&[])).unwrap();
        assert!(rate_limit.enabled);
        assert_eq!(rate_limit.requests_per_second, 100.0);
        assert_eq!(rate_limit.burst_size, 150);
        assert_eq!(
            rate_limit.exempt_paths,
            vec![
                "/healthz".to_owned(),
                "/livez".to_owned(),
                "/readyz".to_owned(),
                "/metrics".to_owned(),
                "/.well-known/".to_owned(),
            ]
        );
        assert_eq!(origin, RequestOriginConfig::default());
        assert_eq!(rate_limit, RateLimitConfig::default());
    }

    #[test]
    fn edge_config_reads_overrides() {
        let (rate_limit, origin) = edge_config_from_lookup(lookup_from(&[
            ("CEREBRO_RATE_LIMIT_ENABLED", "false"),
            ("CEREBRO_RATE_LIMIT_RPS", "5"),
            ("CEREBRO_RATE_LIMIT_BURST", "9"),
            ("CEREBRO_RATE_LIMIT_EXEMPT_PATHS", "/ping, /pong"),
            ("CEREBRO_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, fd00::/8"),
            ("CEREBRO_TRUSTED_PROXY_COUNT", "2"),
        ]))
        .unwrap();
        assert!(!rate_limit.enabled);
        assert_eq!(rate_limit.requests_per_second, 5.0);
        assert_eq!(rate_limit.burst_size, 9);
        assert_eq!(
            rate_limit.exempt_paths,
            vec!["/ping".to_owned(), "/pong".to_owned()]
        );
        assert_eq!(
            origin.trusted_proxy_cidrs,
            vec!["10.0.0.0/8".to_owned(), "fd00::/8".to_owned()]
        );
        assert_eq!(origin.trusted_proxy_count, 2);
    }

    #[test]
    fn edge_config_rejects_invalid_values() {
        assert!(
            edge_config_from_lookup(lookup_from(&[("CEREBRO_RATE_LIMIT_ENABLED", "sometimes")]))
                .is_err()
        );
        assert!(edge_config_from_lookup(lookup_from(&[("CEREBRO_RATE_LIMIT_RPS", "-3")])).is_err());
        assert!(
            edge_config_from_lookup(lookup_from(&[("CEREBRO_RATE_LIMIT_BURST", "x")])).is_err()
        );
        assert!(
            edge_config_from_lookup(lookup_from(&[("CEREBRO_TRUSTED_PROXY_COUNT", "-1")])).is_err()
        );
        let error = edge_config_from_lookup(lookup_from(&[(
            "CEREBRO_TRUSTED_PROXY_CIDRS",
            "10.0.0.0/40",
        )]))
        .unwrap_err();
        assert!(error.contains("invalid CIDR"), "{error}");
        assert!(
            edge_config_from_lookup(lookup_from(&[(
                "CEREBRO_TRUSTED_PROXY_CIDRS",
                "not-a-cidr"
            )]))
            .is_err()
        );
    }

    #[test]
    fn from_env_constructs_with_defaults() {
        // Environment-independent only insofar as CI does not define the
        // shared variables with invalid values; presence with valid values is
        // also fine.
        assert!(
            EdgeRateLimit::from_env().is_ok() || std::env::var("CEREBRO_RATE_LIMIT_RPS").is_ok()
        );
    }

    #[test]
    fn access_audit_remote_ip_strips_ports_and_validates() {
        assert_eq!(access_audit_remote_ip("192.0.2.10:443"), "192.0.2.10");
        assert_eq!(access_audit_remote_ip("[::1]:8080"), "::1");
        assert_eq!(access_audit_remote_ip(" 192.0.2.10 "), "192.0.2.10");
        assert_eq!(access_audit_remote_ip("::1"), "::1");
        assert_eq!(access_audit_remote_ip("::ffff:192.0.2.7"), "192.0.2.7");
        assert_eq!(access_audit_remote_ip(""), "");
        assert_eq!(access_audit_remote_ip("not an ip"), "");
    }

    #[test]
    fn split_host_port_mirrors_go() {
        assert_eq!(
            split_host_port("192.0.2.1:80"),
            Some("192.0.2.1".to_owned())
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:80"),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            split_host_port("example.com:80"),
            Some("example.com".to_owned())
        );
        assert_eq!(split_host_port("2001:db8::1"), None);
        assert_eq!(split_host_port("192.0.2.1"), None);
        assert_eq!(split_host_port("[2001:db8::1:80"), None);
    }

    #[test]
    fn cidr_matching_mirrors_go_contains() {
        let cfg = origin(&["10.0.0.0/8", "2001:db8::/32"], 0);
        assert!(hop_trusted("10.1.2.3".parse().unwrap(), &cfg));
        assert!(!hop_trusted("11.0.0.1".parse().unwrap(), &cfg));
        assert!(hop_trusted("2001:db8::5".parse().unwrap(), &cfg));
        assert!(!hop_trusted("2001:db9::5".parse().unwrap(), &cfg));
        // IPv4-mapped IPv6 addresses match IPv4 CIDRs.
        assert!(hop_trusted("::ffff:10.9.9.9".parse().unwrap(), &cfg));
        // Plain IPv4 addresses do not match IPv6 CIDRs and vice versa.
        assert!(!hop_trusted(
            "10.1.2.3".parse().unwrap(),
            &origin(&["2001:db8::/32"], 0)
        ));
        assert!(!hop_trusted(
            "2001:db8::1".parse().unwrap(),
            &origin(&["10.0.0.0/8"], 0)
        ));
        // /32 and /0 boundaries.
        assert!(hop_trusted(
            "192.0.2.9".parse().unwrap(),
            &origin(&["192.0.2.9/32"], 0)
        ));
        assert!(!hop_trusted(
            "192.0.2.8".parse().unwrap(),
            &origin(&["192.0.2.9/32"], 0)
        ));
        assert!(hop_trusted(
            "203.0.113.4".parse().unwrap(),
            &origin(&["0.0.0.0/0"], 0)
        ));
        // Malformed CIDR entries are skipped at match time.
        assert!(!hop_trusted(
            "10.0.0.1".parse().unwrap(),
            &origin(&["nonsense"], 0)
        ));
        assert!(!hop_trusted(
            "10.0.0.1".parse().unwrap(),
            &origin(&["10.0.0.1"], 0)
        ));
    }

    #[test]
    fn parse_cidr_rejects_malformed_prefixes() {
        assert!(parse_cidr("10.0.0.0/8").is_some());
        assert!(parse_cidr(" 10.0.0.0/8 ").is_some());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0/08").is_none());
        assert!(parse_cidr("10.0.0.0/").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
        assert!(parse_cidr("2001:db8::/129").is_none());
        assert!(parse_cidr("2001:db8::/64").is_some());
        // IPv4-mapped IPv6 networks normalize to IPv4.
        assert_eq!(
            parse_cidr("::ffff:10.0.0.0/104"),
            Some(("10.0.0.0".parse().unwrap(), 8))
        );
    }

    #[test]
    fn forwarded_client_ip_with_automatic_hop_counting() {
        let cfg = origin(&["10.0.0.0/8"], 0);
        // Trailing trusted hops are skipped; the first entry before them wins.
        assert_eq!(
            forwarded_client_ip("203.0.113.9, 10.0.0.1, 10.0.0.2", &cfg),
            "203.0.113.9"
        );
        // No trusted trailing hops: right-most parseable entry wins.
        assert_eq!(
            forwarded_client_ip("203.0.113.9, 198.51.100.7", &cfg),
            "198.51.100.7"
        );
        // Garbage entries are skipped.
        assert_eq!(
            forwarded_client_ip("garbage, 203.0.113.9, 10.0.0.1", &cfg),
            "203.0.113.9"
        );
        // All entries trusted: no derivable client.
        assert_eq!(forwarded_client_ip("10.0.0.1, 10.0.0.2", &cfg), "");
        // Empty header: no derivable client.
        assert_eq!(forwarded_client_ip("", &cfg), "");
        // Canonicalization of IPv4-mapped entries.
        assert_eq!(
            forwarded_client_ip("::ffff:203.0.113.9, 10.0.0.1", &cfg),
            "203.0.113.9"
        );
    }

    #[test]
    fn forwarded_client_ip_with_explicit_hop_count() {
        let cfg = origin(&["10.0.0.0/8"], 2);
        assert_eq!(
            forwarded_client_ip("203.0.113.9, 198.51.100.7, 10.0.0.1", &cfg),
            "203.0.113.9"
        );
        // Count larger than the list falls back to the right-most non-trusted
        // parseable entry.
        let cfg = origin(&["10.0.0.0/8"], 5);
        assert_eq!(
            forwarded_client_ip("203.0.113.9, 10.0.0.1", &cfg),
            "203.0.113.9"
        );
        // An explicit count skips exactly that many trailing hops, even when
        // more of them are trusted (mirrors the Go loop bound).
        let cfg = origin(&["10.0.0.0/8"], 1);
        assert_eq!(
            forwarded_client_ip("10.0.0.3, 10.0.0.1, 10.0.0.2", &cfg),
            "10.0.0.1"
        );
    }

    #[test]
    fn resolve_client_ip_requires_trusted_peer_for_forwarded_for() {
        let cfg = origin(&["10.0.0.0/8"], 0);
        // Untrusted peer: X-Forwarded-For is ignored.
        assert_eq!(
            resolve_client_ip("203.0.113.5:1234", "198.51.100.7", &cfg),
            "203.0.113.5"
        );
        // Trusted peer: X-Forwarded-For is honored.
        assert_eq!(
            resolve_client_ip("10.0.0.1:1234", "198.51.100.7", &cfg),
            "198.51.100.7"
        );
        // Trusted peer without a derivable forwarded client: falls back to peer.
        assert_eq!(resolve_client_ip("10.0.0.1:1234", "", &cfg), "10.0.0.1");
        // No usable origin at all: "unknown".
        assert_eq!(resolve_client_ip("", "", &cfg), "unknown");
        assert_eq!(resolve_client_ip("garbage", "203.0.113.5", &cfg), "unknown");
        // No trusted CIDRs configured: peer address is always the key.
        let open = RequestOriginConfig::default();
        assert_eq!(
            resolve_client_ip("203.0.113.5:9", "198.51.100.7", &open),
            "203.0.113.5"
        );
    }

    fn limiter(rps: f64, burst: usize, cidrs: &[&str]) -> EdgeRateLimiter {
        EdgeRateLimiter::new(
            RateLimitConfig {
                enabled: true,
                requests_per_second: rps,
                burst_size: burst,
                ..RateLimitConfig::default()
            },
            origin(cidrs, 0),
        )
    }

    #[test]
    fn token_bucket_allows_burst_then_denies() {
        let rl = limiter(1.0, 3, &[]);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(rl.check("/v1/graph/search", "203.0.113.5:1", "", now));
        }
        assert!(!rl.check("/v1/graph/search", "203.0.113.5:1", "", now));
    }

    #[test]
    fn token_bucket_refills_at_configured_rate() {
        let rl = limiter(2.0, 2, &[]);
        let now = Instant::now();
        assert!(rl.check("/x", "203.0.113.5:1", "", now));
        assert!(rl.check("/x", "203.0.113.5:1", "", now));
        assert!(!rl.check("/x", "203.0.113.5:1", "", now));
        // 2 rps: after 500ms one token has accrued.
        let later = now + Duration::from_millis(500);
        assert!(rl.check("/x", "203.0.113.5:1", "", later));
        assert!(!rl.check("/x", "203.0.113.5:1", "", later));
        // Refill caps at burst.
        let much_later = later + Duration::from_secs(60);
        assert!(rl.check("/x", "203.0.113.5:1", "", much_later));
        assert!(rl.check("/x", "203.0.113.5:1", "", much_later));
        assert!(!rl.check("/x", "203.0.113.5:1", "", much_later));
    }

    #[test]
    fn token_bucket_zero_burst_never_allows() {
        let rl = limiter(100.0, 0, &[]);
        let now = Instant::now();
        assert!(!rl.check("/x", "203.0.113.5:1", "", now));
        assert!(!rl.check("/x", "203.0.113.5:1", "", now + Duration::from_secs(10)));
    }

    #[test]
    fn token_bucket_zero_rate_allows_only_initial_burst() {
        let rl = limiter(0.0, 1, &[]);
        let now = Instant::now();
        assert!(rl.check("/x", "203.0.113.5:1", "", now));
        // Idle below the 10 minute stale cutoff: still empty (rate 0 never
        // refills). Past the cutoff the bucket would be evicted like Go's.
        assert!(!rl.check("/x", "203.0.113.5:1", "", now + Duration::from_secs(480)));
    }

    #[test]
    fn buckets_are_isolated_per_client_ip() {
        let rl = limiter(0.0, 1, &[]);
        let now = Instant::now();
        assert!(rl.check("/x", "203.0.113.5:1", "", now));
        assert!(!rl.check("/x", "203.0.113.5:2", "", now)); // same IP, different port
        assert!(rl.check("/x", "203.0.113.6:1", "", now)); // different IP
    }

    #[test]
    fn forwarded_clients_are_limited_individually_behind_trusted_proxy() {
        let rl = limiter(0.0, 1, &["10.0.0.0/8"]);
        let now = Instant::now();
        assert!(rl.check("/x", "10.0.0.1:9", "198.51.100.7", now));
        assert!(!rl.check("/x", "10.0.0.1:9", "198.51.100.7", now));
        assert!(rl.check("/x", "10.0.0.1:9", "198.51.100.8", now));
    }

    #[test]
    fn exempt_paths_bypass_by_prefix() {
        let rl = limiter(0.0, 0, &[]);
        let now = Instant::now();
        for path in [
            "/healthz",
            "/livez",
            "/readyz",
            "/metrics",
            "/.well-known/oauth",
        ] {
            assert!(
                rl.check(path, "203.0.113.5:1", "", now),
                "{path} should be exempt"
            );
        }
        // Prefix semantics, mirroring Go strings.HasPrefix.
        assert!(rl.check("/healthz/deep", "203.0.113.5:1", "", now));
        assert!(!rl.check("/v1/graph/search", "203.0.113.5:1", "", now));
    }

    #[test]
    fn disabled_limiter_always_allows() {
        let rl = EdgeRateLimiter::new(
            RateLimitConfig {
                enabled: false,
                requests_per_second: 0.0,
                burst_size: 0,
                ..RateLimitConfig::default()
            },
            RequestOriginConfig::default(),
        );
        let now = Instant::now();
        for _ in 0..10 {
            assert!(rl.check("/v1/graph/search", "203.0.113.5:1", "", now));
        }
    }

    #[test]
    fn stale_buckets_are_evicted_after_cleanup_interval() {
        let now = Instant::now();
        let rl = EdgeRateLimiter::with_cleanup_interval(
            RateLimitConfig {
                enabled: true,
                requests_per_second: 0.0,
                burst_size: 1,
                ..RateLimitConfig::default()
            },
            RequestOriginConfig::default(),
            Duration::from_secs(300),
            now,
        );
        // Exhaust the bucket; with rps 0 it can never refill.
        assert!(rl.check("/x", "203.0.113.5:1", "", now));
        assert!(!rl.check("/x", "203.0.113.5:1", "", now));
        // Before the stale cutoff the bucket survives cleanup.
        let later = now + Duration::from_secs(400);
        assert!(!rl.check("/x", "203.0.113.5:1", "", later));
        // Once idle past 10 minutes, cleanup evicts it and a fresh bucket
        // grants a new burst.
        let much_later = later + Duration::from_secs(11 * 60);
        assert!(rl.check("/x", "203.0.113.5:1", "", much_later));
    }

    mod middleware {
        use super::*;
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        fn app(rate_limit: RateLimitConfig, origin_cfg: RequestOriginConfig) -> Router {
            Router::new()
                .route("/hello", get(|| async { "hello" }))
                .route("/healthz", get(|| async { "ok" }))
                .layer(axum::middleware::from_fn_with_state(
                    EdgeRateLimit::with_config(rate_limit, origin_cfg),
                    enforce,
                ))
        }

        fn request(path: &str, peer: &str, forwarded_for: Option<&str>) -> Request {
            let mut builder = axum::http::Request::builder().uri(path);
            if let Some(forwarded_for) = forwarded_for {
                builder = builder.header("X-Forwarded-For", forwarded_for);
            }
            let mut request = builder.body(Body::empty()).unwrap();
            if !peer.is_empty() {
                request
                    .extensions_mut()
                    .insert(ConnectInfo::<SocketAddr>(peer.parse().unwrap()));
            }
            request
        }

        #[tokio::test]
        async fn limits_with_go_compatible_response() {
            let app = app(
                RateLimitConfig {
                    enabled: true,
                    requests_per_second: 0.0,
                    burst_size: 1,
                    ..RateLimitConfig::default()
                },
                RequestOriginConfig::default(),
            );
            let ok = app
                .clone()
                .oneshot(request("/hello", "203.0.113.5:443", None))
                .await
                .unwrap();
            assert_eq!(ok.status(), StatusCode::OK);
            let limited = app
                .clone()
                .oneshot(request("/hello", "203.0.113.5:443", None))
                .await
                .unwrap();
            assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                limited.headers().get(header::CONTENT_TYPE).unwrap(),
                "text/plain; charset=utf-8"
            );
            assert_eq!(
                limited
                    .headers()
                    .get(header::X_CONTENT_TYPE_OPTIONS)
                    .unwrap(),
                "nosniff"
            );
            let body = axum::body::to_bytes(limited.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(&body[..], b"Too Many Requests\n");
            // Exempt paths still pass after the client is limited.
            let health = app
                .oneshot(request("/healthz", "203.0.113.5:443", None))
                .await
                .unwrap();
            assert_eq!(health.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn keys_on_forwarded_client_behind_trusted_proxy() {
            let app = app(
                RateLimitConfig {
                    enabled: true,
                    requests_per_second: 0.0,
                    burst_size: 1,
                    ..RateLimitConfig::default()
                },
                RequestOriginConfig {
                    trusted_proxy_cidrs: vec!["10.0.0.0/8".to_owned()],
                    trusted_proxy_count: 0,
                },
            );
            let first = app
                .clone()
                .oneshot(request("/hello", "10.0.0.1:443", Some("198.51.100.7")))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::OK);
            let limited = app
                .clone()
                .oneshot(request("/hello", "10.0.0.1:443", Some("198.51.100.7")))
                .await
                .unwrap();
            assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
            // A different forwarded client through the same proxy has its own bucket.
            let other = app
                .oneshot(request("/hello", "10.0.0.1:443", Some("198.51.100.8")))
                .await
                .unwrap();
            assert_eq!(other.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn missing_connect_info_maps_to_unknown_key() {
            let app = app(
                RateLimitConfig {
                    enabled: true,
                    requests_per_second: 0.0,
                    burst_size: 1,
                    ..RateLimitConfig::default()
                },
                RequestOriginConfig::default(),
            );
            let first = app
                .clone()
                .oneshot(request("/hello", "", None))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::OK);
            let limited = app.oneshot(request("/hello", "", None)).await.unwrap();
            assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
