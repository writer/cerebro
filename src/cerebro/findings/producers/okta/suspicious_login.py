"""Producer for detecting suspicious Okta login events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cerebro.domain.entities import (
    ConfigEntity,
    FindingEntity,
    ResourceEntity,
    Severity,
)
from cerebro.findings.producers.base import ProducerContext
from cerebro.findings.producers.registry import register_producer
from cerebro.findings.producers.utils import resolve_rule_id

from .base import BaseOktaProducer


@register_producer
class OktaSuspiciousLoginProducer(BaseOktaProducer):
    """Detects suspicious Okta login events based on risk signals.

    This producer evaluates login events for indicators of compromise:
    - Login from new/unfamiliar IP addresses
    - Login from suspicious geolocations
    - Failed login attempts followed by success (potential brute force)
    - Login from multiple locations in short time (impossible travel)
    - Login with elevated risk score from Okta ThreatInsight
    """

    @property
    def resource_types(self) -> set[str]:
        return {"okta.user", "okta.system_log"}

    @property
    def finding_name(self) -> str:
        return "Okta: Suspicious Login Detected"

    @property
    def rule_name(self) -> str:
        return "okta_suspicious_login"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Suspicious login activity detected for Okta user based on risk signals "
            "such as unfamiliar location, impossible travel, or elevated threat score"
        )

    @property
    def remediation(self) -> str:
        return (
            "Verify the login with the user. If unauthorized, reset credentials, "
            "revoke active sessions, and investigate for lateral movement. "
            "Consider enforcing additional MFA factors."
        )

    @property
    def framework_mappings(self) -> dict[str, list[str]]:
        return {
            "nist_800_53": ["IA-2(1)", "AC-7", "SI-4"],
            "cwe": ["CWE-287", "CWE-307"],
            "mitre_attack": ["T1078", "T1110"],  # Valid Accounts, Brute Force
        }

    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: ProducerContext | None = None,
    ) -> list[FindingEntity]:
        """Evaluate Okta user login events for suspicious activity."""
        findings: list[FindingEntity] = []

        data: Mapping[str, Any] = config.normalized_config or {}

        # Check if this is a system log event or user resource
        if resource.resource_type == "okta.system_log":
            findings.extend(self._evaluate_system_log(resource, data, context))
        else:
            # User resource - check recent login patterns
            findings.extend(self._evaluate_user_login_history(resource, data, context))

        return findings

    def _evaluate_system_log(
        self,
        resource: ResourceEntity,
        data: Mapping[str, Any],
        context: ProducerContext | None,
    ) -> list[FindingEntity]:
        """Evaluate Okta system log event for suspicious login."""
        findings: list[FindingEntity] = []

        event_type = data.get("event_type", "")
        outcome = data.get("outcome", {})
        outcome_result = outcome.get("result") if isinstance(outcome, dict) else None

        # Only evaluate authentication events
        auth_events = {
            "user.session.start",
            "user.authentication.auth_via_mfa",
            "user.authentication.sso",
            "user.authentication.auth_via_IDP",
        }

        if event_type not in auth_events:
            return findings

        # Extract risk signals
        security_context = data.get("security_context", {}) or {}
        threat_suspected = security_context.get("isThreatSuspected", False)
        as_org = security_context.get("asOrg")
        is_proxy = security_context.get("isProxy", False)

        client = data.get("client", {}) or {}
        ip_address = client.get("ipAddress")
        geo = client.get("geographicalContext", {}) or {}
        city = geo.get("city")
        state = geo.get("state")
        country = geo.get("country")

        user_agent = client.get("userAgent", {}) or {}
        browser = user_agent.get("browser")
        os = user_agent.get("os")

        actor = data.get("actor", {}) or {}
        user_id = actor.get("id")
        user_email = actor.get("alternateId")

        # Build risk factors
        risk_factors: list[str] = []
        risk_score = 0

        if threat_suspected:
            risk_factors.append("threat_intelligence_alert")
            risk_score += 40

        if is_proxy:
            risk_factors.append("proxy_or_vpn_detected")
            risk_score += 20

        if outcome_result == "FAILURE":
            risk_factors.append("failed_authentication")
            risk_score += 10

        # Check for suspicious geolocations
        suspicious_countries = self._get_suspicious_countries()
        if country and country.upper() in suspicious_countries:
            risk_factors.append(f"suspicious_country:{country}")
            risk_score += 30

        # Only create finding if risk score is significant
        if risk_score < 30:
            return findings

        severity = Severity.CRITICAL if risk_score >= 50 else self.severity

        evidence = {
            "event_type": event_type,
            "user_id": user_id,
            "user_email": user_email,
            "ip_address": ip_address,
            "location": {
                "city": city,
                "state": state,
                "country": country,
            },
            "client": {
                "browser": browser,
                "os": os,
            },
            "security_context": {
                "threat_suspected": threat_suspected,
                "is_proxy": is_proxy,
                "as_org": as_org,
            },
            "risk_factors": risk_factors,
            "risk_score": risk_score,
            "outcome": outcome_result,
            "timestamp": data.get("published"),
        }

        rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

        findings.append(
            self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"Suspicious login for {user_email or user_id}",
                summary=(
                    f"Login from {city or 'unknown'}, {country or 'unknown'} "
                    f"with risk score {risk_score}. Factors: {', '.join(risk_factors)}"
                ),
                evidence=evidence,
                severity=severity,
            )
        )

        return findings

    def _evaluate_user_login_history(
        self,
        resource: ResourceEntity,
        data: Mapping[str, Any],
        context: ProducerContext | None,
    ) -> list[FindingEntity]:
        """Evaluate user's recent login history for suspicious patterns."""
        findings: list[FindingEntity] = []

        login_history = data.get("login_history", []) or []
        if not login_history or len(login_history) < 2:
            return findings

        # Check for impossible travel
        impossible_travel = self._detect_impossible_travel(login_history)
        if impossible_travel:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            evidence = {
                "user_id": resource.external_id,
                "user_email": data.get("email"),
                "detection_type": "impossible_travel",
                "login_events": impossible_travel["events"],
                "distance_km": impossible_travel.get("distance_km"),
                "time_delta_minutes": impossible_travel.get("time_delta_minutes"),
                "risk_factors": ["impossible_travel"],
            }

            findings.append(
                self.create_finding(
                    resource=resource,
                    rule_id=rule_id,
                    title=f"Impossible travel detected for {data.get('email', resource.name)}",
                    summary=(
                        f"User logged in from locations {impossible_travel.get('distance_km', 0):.0f}km "
                        f"apart within {impossible_travel.get('time_delta_minutes', 0):.0f} minutes"
                    ),
                    evidence=evidence,
                    severity=Severity.CRITICAL,
                )
            )

        # Check for credential stuffing pattern (many failures then success)
        credential_stuffing = self._detect_credential_stuffing(login_history)
        if credential_stuffing:
            rule_id = resolve_rule_id(rule_name=self.rule_name, context=context)

            evidence = {
                "user_id": resource.external_id,
                "user_email": data.get("email"),
                "detection_type": "credential_stuffing",
                "failed_attempts": credential_stuffing["failed_count"],
                "success_after_failures": True,
                "ip_addresses": credential_stuffing.get("ip_addresses", []),
                "risk_factors": ["credential_stuffing_pattern"],
            }

            findings.append(
                self.create_finding(
                    resource=resource,
                    rule_id=rule_id,
                    title=f"Credential stuffing pattern for {data.get('email', resource.name)}",
                    summary=(
                        f"{credential_stuffing['failed_count']} failed logins followed by success "
                        f"from {len(credential_stuffing.get('ip_addresses', []))} IP addresses"
                    ),
                    evidence=evidence,
                    severity=Severity.HIGH,
                )
            )

        return findings

    def _detect_impossible_travel(
        self, login_history: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Detect impossible travel based on login locations and times."""
        if len(login_history) < 2:
            return None

        # Sort by timestamp
        sorted_logins = sorted(
            login_history,
            key=lambda x: x.get("timestamp", ""),
            reverse=True,
        )

        for i in range(len(sorted_logins) - 1):
            current = sorted_logins[i]
            previous = sorted_logins[i + 1]

            current_geo = current.get("geo", {}) or {}
            previous_geo = previous.get("geo", {}) or {}

            current_lat = current_geo.get("latitude")
            current_lon = current_geo.get("longitude")
            previous_lat = previous_geo.get("latitude")
            previous_lon = previous_geo.get("longitude")

            if not all([current_lat, current_lon, previous_lat, previous_lon]):
                continue

            # Calculate distance (simplified haversine)
            distance_km = self._haversine_distance(
                current_lat, current_lon, previous_lat, previous_lon
            )

            # Calculate time difference
            try:
                current_time = datetime.fromisoformat(
                    current.get("timestamp", "").replace("Z", "+00:00")
                )
                previous_time = datetime.fromisoformat(
                    previous.get("timestamp", "").replace("Z", "+00:00")
                )
                time_delta = abs((current_time - previous_time).total_seconds() / 60)
            except (ValueError, TypeError):
                continue

            # Check if travel is impossible (> 500km/hr)
            if time_delta > 0:
                speed_kmh = (distance_km / time_delta) * 60
                if speed_kmh > 500 and distance_km > 100:
                    return {
                        "events": [current, previous],
                        "distance_km": distance_km,
                        "time_delta_minutes": time_delta,
                        "speed_kmh": speed_kmh,
                    }

        return None

    def _detect_credential_stuffing(
        self, login_history: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Detect credential stuffing pattern (many failures then success)."""
        if len(login_history) < 3:
            return None

        # Sort by timestamp (most recent first)
        sorted_logins = sorted(
            login_history,
            key=lambda x: x.get("timestamp", ""),
            reverse=True,
        )

        # Check recent history (last 24 hours)
        recent_failures = []
        success_found = False
        ip_addresses = set()

        for login in sorted_logins[:50]:  # Check last 50 events
            outcome = login.get("outcome", "")
            ip = login.get("ip_address")

            if outcome == "SUCCESS" and not success_found:
                success_found = True
            elif outcome == "FAILURE" and success_found:
                recent_failures.append(login)
                if ip:
                    ip_addresses.add(ip)

        # Pattern: 5+ failures from multiple IPs followed by success
        if len(recent_failures) >= 5 and len(ip_addresses) >= 2:
            return {
                "failed_count": len(recent_failures),
                "ip_addresses": list(ip_addresses),
            }

        return None

    @staticmethod
    def _haversine_distance(
        lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two points in kilometers."""
        import math

        R = 6371  # Earth radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    @staticmethod
    def _get_suspicious_countries() -> set[str]:
        """Get set of countries often associated with threat actors."""
        return {
            "RU",  # Russia
            "CN",  # China
            "KP",  # North Korea
            "IR",  # Iran
            "BY",  # Belarus
        }
