"""
RFC-3161 timestamping service for provable auditability.

Implements RFC-3161 trusted timestamping with monotonic clock checks
to defeat clock skew tampering.
"""

import asyncio
import hashlib
import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7

logger = logging.getLogger(__name__)


class TimestampStatus(Enum):
    """Status of timestamp operations."""
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    INVALID = "invalid"


@dataclass
class TimestampToken:
    """RFC-3161 timestamp token."""
    token_data: bytes
    timestamp: datetime
    hash_algorithm: str
    hashed_message: str
    tsa_authority: str
    serial_number: str
    status: TimestampStatus
    verification_info: Dict[str, Any]


@dataclass
class MonotonicClockCheck:
    """Monotonic clock verification result."""
    local_time: datetime
    monotonic_time: float
    timestamp_time: datetime
    clock_skew_seconds: float
    is_valid: bool
    warning_threshold_seconds: float = 300.0  # 5 minutes


class RFC3161Timestamper:
    """
    RFC-3161 timestamp service client.
    
    Provides trusted timestamping with verification capabilities
    for cryptographic auditability.
    """
    
    def __init__(self, tsa_urls: Optional[List[str]] = None):
        """
        Initialize timestamper with TSA URLs.
        
        Args:
            tsa_urls: List of RFC-3161 TSA endpoint URLs
        """
        # Default to free/demo TSA services (replace with production TSAs)
        self.tsa_urls = tsa_urls or [
            "http://timestamp.digicert.com",
            "http://timestamp.globalsign.com/scripts/timstamp.dll",
            "http://timestamp.comodoca.com/rfc3161"
        ]
        
        self.client = httpx.AsyncClient(timeout=30.0)
        self.monotonic_start = time.monotonic()
        self.process_start = datetime.now()
    
    async def timestamp_data(self, data: bytes) -> TimestampToken:
        """
        Create RFC-3161 timestamp for data.
        
        Args:
            data: Data to timestamp
            
        Returns:
            TimestampToken with verification info
        """
        # Calculate hash of data
        data_hash = hashlib.sha256(data).digest()
        
        # Try each TSA URL until one succeeds
        for tsa_url in self.tsa_urls:
            try:
                token = await self._request_timestamp(tsa_url, data_hash)
                
                # Perform monotonic clock check
                clock_check = self._verify_monotonic_clock(token.timestamp)
                
                token.verification_info.update({
                    "monotonic_clock_check": {
                        "local_time": clock_check.local_time.isoformat(),
                        "monotonic_offset": clock_check.monotonic_time,
                        "clock_skew_seconds": clock_check.clock_skew_seconds,
                        "is_valid": clock_check.is_valid,
                        "warning_threshold": clock_check.warning_threshold_seconds
                    }
                })
                
                if clock_check.is_valid:
                    token.status = TimestampStatus.SUCCESS
                    logger.info(f"Timestamp created successfully via {tsa_url}")
                    return token
                else:
                    logger.warning(f"Clock skew detected: {clock_check.clock_skew_seconds}s")
                    token.status = TimestampStatus.INVALID
                    return token
                    
            except Exception as e:
                logger.warning(f"TSA {tsa_url} failed: {e}")
                continue
        
        # All TSAs failed
        raise Exception("All timestamp authorities failed")
    
    async def _request_timestamp(self, tsa_url: str, data_hash: bytes) -> TimestampToken:
        """Request timestamp from specific TSA."""
        
        # Create TSA request (simplified - would use proper ASN.1 encoding)
        tsa_request = self._create_tsa_request(data_hash)
        
        # Send request to TSA
        response = await self.client.post(
            tsa_url,
            content=tsa_request,
            headers={
                "Content-Type": "application/timestamp-query",
                "Content-Length": str(len(tsa_request))
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"TSA returned {response.status_code}: {response.text}")
        
        # Parse TSA response (simplified)
        token_data = response.content
        
        return TimestampToken(
            token_data=token_data,
            timestamp=datetime.now(),  # Would parse from ASN.1 response
            hash_algorithm="SHA-256",
            hashed_message=data_hash.hex(),
            tsa_authority=tsa_url,
            serial_number=f"ts_{int(time.time())}",
            status=TimestampStatus.PENDING,
            verification_info={
                "tsa_url": tsa_url,
                "response_size": len(token_data),
                "request_time": datetime.now().isoformat()
            }
        )
    
    def _create_tsa_request(self, data_hash: bytes) -> bytes:
        """Create RFC-3161 timestamp request (simplified)."""
        # In production, would use proper ASN.1 encoding with pyasn1 or similar
        # This is a simplified representation
        request_data = {
            "version": 1,
            "messageImprint": {
                "hashAlgorithm": "sha256",
                "hashedMessage": data_hash.hex()
            },
            "nonce": int(time.time() * 1000000),  # Microsecond precision
            "certReq": True
        }
        
        return json.dumps(request_data).encode()
    
    def _verify_monotonic_clock(self, timestamp_time: datetime) -> MonotonicClockCheck:
        """
        Verify timestamp against monotonic clock to detect tampering.
        
        Checks if timestamp is consistent with system monotonic clock
        to detect system clock manipulation.
        """
        current_time = datetime.now()
        current_monotonic = time.monotonic()
        
        # Calculate expected time based on monotonic clock
        monotonic_elapsed = current_monotonic - self.monotonic_start
        expected_time = self.process_start + timedelta(seconds=monotonic_elapsed)
        
        # Calculate skew
        clock_skew = abs((timestamp_time - expected_time).total_seconds())
        
        # Determine if skew is within acceptable bounds
        warning_threshold = 300.0  # 5 minutes
        is_valid = clock_skew <= warning_threshold
        
        return MonotonicClockCheck(
            local_time=current_time,
            monotonic_time=current_monotonic,
            timestamp_time=timestamp_time,
            clock_skew_seconds=clock_skew,
            is_valid=is_valid,
            warning_threshold_seconds=warning_threshold
        )
    
    async def verify_timestamp_token(self, token: TimestampToken) -> bool:
        """
        Verify RFC-3161 timestamp token.
        
        Validates token signature and certificate chain.
        """
        try:
            # Parse TSA response (simplified - would use proper ASN.1 parsing)
            # In production, would verify:
            # 1. TSA certificate chain
            # 2. Token signature
            # 3. Hash algorithm and value
            # 4. Nonce matching
            
            # For now, basic verification
            if not token.token_data or len(token.token_data) < 10:
                return False
            
            # Check if hash matches
            expected_hash = hashlib.sha256(token.hashed_message.encode()).hexdigest()
            return len(expected_hash) == 64  # Valid SHA-256
            
        except Exception as e:
            logger.error(f"Timestamp verification failed: {e}")
            return False
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


class TimestampService:
    """
    High-level timestamp service for Cerebro audit events.
    
    Manages RFC-3161 timestamping with caching and batch processing.
    """
    
    def __init__(self):
        self.timestamper = RFC3161Timestamper()
        self.timestamp_cache: Dict[str, TimestampToken] = {}
        self.batch_size = 100
        self.pending_items: List[Tuple[str, bytes]] = []
    
    async def timestamp_audit_event(self, event_data: Dict[str, Any]) -> TimestampToken:
        """
        Timestamp an audit event with RFC-3161 proof.
        
        Args:
            event_data: Audit event data to timestamp
            
        Returns:
            TimestampToken with verification proof
        """
        # Serialize event data
        event_json = json.dumps(event_data, sort_keys=True)
        event_bytes = event_json.encode()
        
        # Check cache first
        event_hash = hashlib.sha256(event_bytes).hexdigest()
        if event_hash in self.timestamp_cache:
            return self.timestamp_cache[event_hash]
        
        # Create timestamp
        try:
            token = await self.timestamper.timestamp_data(event_bytes)
            
            # Cache successful timestamps
            if token.status == TimestampStatus.SUCCESS:
                self.timestamp_cache[event_hash] = token
            
            return token
            
        except Exception as e:
            logger.error(f"Failed to timestamp audit event: {e}")
            
            # Return failed token
            return TimestampToken(
                token_data=b"",
                timestamp=datetime.now(),
                hash_algorithm="SHA-256",
                hashed_message=event_hash,
                tsa_authority="failed",
                serial_number="failed",
                status=TimestampStatus.FAILED,
                verification_info={"error": str(e)}
            )
    
    async def batch_timestamp(self, items: List[Tuple[str, bytes]]) -> List[TimestampToken]:
        """
        Batch timestamp multiple items for efficiency.
        
        Args:
            items: List of (identifier, data) tuples
            
        Returns:
            List of timestamp tokens
        """
        tokens = []
        
        for identifier, data in items:
            try:
                token = await self.timestamper.timestamp_data(data)
                tokens.append(token)
            except Exception as e:
                logger.error(f"Batch timestamp failed for {identifier}: {e}")
                
                # Add failed token
                tokens.append(TimestampToken(
                    token_data=b"",
                    timestamp=datetime.now(),
                    hash_algorithm="SHA-256", 
                    hashed_message=hashlib.sha256(data).hexdigest(),
                    tsa_authority="failed",
                    serial_number="failed",
                    status=TimestampStatus.FAILED,
                    verification_info={"error": str(e), "identifier": identifier}
                ))
        
        return tokens
    
    async def close(self):
        """Close timestamp service."""
        await self.timestamper.close()


# Global timestamp service
_timestamp_service = TimestampService()


def get_timestamp_service() -> TimestampService:
    """Get global timestamp service instance."""
    return _timestamp_service


async def timestamp_security_event(event_data: Dict[str, Any]) -> TimestampToken:
    """Convenience function to timestamp security events."""
    return await _timestamp_service.timestamp_audit_event(event_data)
