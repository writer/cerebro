"""Metrics for authentication and authorization operations."""

from prometheus_client import Counter, Histogram, Gauge
from .collection_metrics import cerebro_registry

# Login attempt metrics
login_attempts = Counter(
    'cerebro_login_attempts_total',
    'Total number of login attempts',
    ['status', 'source_ip_range'],  # success, failed, locked
    registry=cerebro_registry
)

login_duration = Histogram(
    'cerebro_login_duration_seconds',
    'Time spent processing login requests',
    ['status'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
    registry=cerebro_registry
)

# Rate limiting metrics  
rate_limit_hits = Counter(
    'cerebro_rate_limit_hits_total',
    'Number of requests blocked by rate limiting',
    ['limit_type', 'source_ip_range'],  # per_ip, per_user
    registry=cerebro_registry
)

# Account lockout metrics
account_lockouts = Counter(
    'cerebro_account_lockouts_total',
    'Total number of account lockouts',
    ['reason'],  # failed_attempts, admin_action
    registry=cerebro_registry
)

accounts_locked = Gauge(
    'cerebro_accounts_locked_current',
    'Current number of locked accounts',
    registry=cerebro_registry
)

# Password security metrics
password_strength_checks = Counter(
    'cerebro_password_strength_checks_total',
    'Password strength validation attempts',
    ['result'],  # passed, failed
    registry=cerebro_registry
)

# API authorization metrics
authorization_checks = Counter(
    'cerebro_authorization_checks_total',
    'API authorization checks',
    ['endpoint', 'required_scope', 'result'],  # allowed, denied
    registry=cerebro_registry
)

unauthorized_access_attempts = Counter(
    'cerebro_unauthorized_access_attempts_total',
    'Unauthorized access attempts',
    ['endpoint', 'user_type'],  # anonymous, authenticated_insufficient_scope
    registry=cerebro_registry
)


class AuthMetrics:
    """Helper class for authentication metrics."""
    
    @staticmethod
    def record_login_attempt(success: bool, ip_address: str, duration: float, locked: bool = False) -> None:
        """Record a login attempt with timing and outcome."""
        # Anonymize IP to IP range for privacy
        ip_range = AuthMetrics._anonymize_ip(ip_address)
        
        if locked:
            status = "locked"
        elif success:
            status = "success"
        else:
            status = "failed"
            
        login_attempts.labels(status=status, source_ip_range=ip_range).inc()
        login_duration.labels(status=status).observe(duration)
    
    @staticmethod
    def record_rate_limit_hit(limit_type: str, ip_address: str) -> None:
        """Record rate limit enforcement."""
        ip_range = AuthMetrics._anonymize_ip(ip_address)
        rate_limit_hits.labels(limit_type=limit_type, source_ip_range=ip_range).inc()

    @staticmethod
    def record_account_lockout(reason: str) -> None:
        """Record account lockout."""
        account_lockouts.labels(reason=reason).inc()
        accounts_locked.inc()

    @staticmethod
    def record_account_unlock() -> None:
        """Record account unlock."""
        accounts_locked.dec()

    @staticmethod
    def record_password_strength_check(passed: bool) -> None:
        """Record password strength validation."""
        result = "passed" if passed else "failed"
        password_strength_checks.labels(result=result).inc()

    @staticmethod
    def record_authorization_check(endpoint: str, required_scope: str, allowed: bool) -> None:
        """Record API authorization check."""
        result = "allowed" if allowed else "denied"
        authorization_checks.labels(
            endpoint=endpoint,
            required_scope=required_scope,
            result=result
        ).inc()

    @staticmethod
    def record_unauthorized_access(endpoint: str, authenticated: bool) -> None:
        """Record unauthorized access attempt."""
        user_type = "authenticated_insufficient_scope" if authenticated else "anonymous"
        unauthorized_access_attempts.labels(
            endpoint=endpoint,
            user_type=user_type
        ).inc()
    
    @staticmethod
    def _anonymize_ip(ip_address: str) -> str:
        """Convert IP address to anonymized range for privacy."""
        try:
            if ':' in ip_address:
                # IPv6 - use first 3 groups
                parts = ip_address.split(':')
                if len(parts) >= 3:
                    return f"{parts[0]}:{parts[1]}:{parts[2]}::/48"
            else:
                # IPv4 - use first 2 octets
                parts = ip_address.split('.')
                if len(parts) >= 2:
                    return f"{parts[0]}.{parts[1]}.0.0/16"
            
            return "unknown"
        except Exception:
            return "unknown"


# Global instance
auth_metrics = AuthMetrics()
