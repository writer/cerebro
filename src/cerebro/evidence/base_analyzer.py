"""Base evidence analyzer pattern inspired by findings-producer."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, AsyncGenerator
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    """Evidence collected for compliance and security analysis."""
    evidence_id: str
    evidence_type: str
    source_system: str
    collected_at: str
    evidence_data: Dict[str, Any]
    quality_score: float
    compliance_controls: List[str]


@dataclass
class EvidenceRecord:
    """Input record for evidence analysis."""
    record_id: str
    source: str
    event_type: str
    payload: Dict[str, Any]
    org_id: str
    timestamp: str


class BaseEvidenceAnalyzer(ABC):
    """
    Base class for evidence analysis.
    
    Follows findings-producer pattern - each analyzer processes specific
    evidence types and produces structured evidence records.
    """
    
    evidence_type: str
    
    @abstractmethod
    async def analyze(self, record: EvidenceRecord) -> List[Evidence]:
        """
        Analyze input record and produce evidence items.
        
        Args:
            record: Input evidence record to analyze
            
        Returns:
            List of Evidence items extracted from the record
        """
        pass
    
    def _create_evidence(
        self,
        evidence_id: str,
        source_system: str,
        evidence_data: Dict[str, Any],
        quality_score: float = 1.0,
        compliance_controls: List[str] = None
    ) -> Evidence:
        """Helper to create evidence with consistent structure."""
        from datetime import datetime
        
        return Evidence(
            evidence_id=evidence_id,
            evidence_type=self.evidence_type,
            source_system=source_system,
            collected_at=datetime.utcnow().isoformat(),
            evidence_data=evidence_data,
            quality_score=quality_score,
            compliance_controls=compliance_controls or []
        )


class SecretsScannerEvidenceAnalyzer(BaseEvidenceAnalyzer):
    """
    Analyzes code and configuration for secrets and sensitive data.
    
    Provides immediate value by detecting high-entropy strings that
    could be API keys, passwords, or tokens.
    """
    
    evidence_type = "secrets_analysis"
    
    async def analyze(self, record: EvidenceRecord) -> List[Evidence]:
        """Analyze record for potential secrets."""
        evidence_items = []
        
        try:
            payload = record.payload
            
            # Look for potential secrets in various fields
            potential_secrets = []
            
            # Check environment variables
            if 'environment' in payload:
                for key, value in payload['environment'].items():
                    if self._is_potential_secret(key, value):
                        potential_secrets.append({
                            'type': 'environment_variable',
                            'key': key,
                            'entropy': self._calculate_entropy(str(value)),
                            'location': 'environment'
                        })
            
            # Check configuration files
            if 'config_files' in payload:
                for file_path, content in payload['config_files'].items():
                    secrets_in_file = self._scan_file_content(file_path, content)
                    potential_secrets.extend(secrets_in_file)
            
            # Create evidence for each potential secret
            for secret in potential_secrets:
                quality_score = min(secret['entropy'] / 6.0, 1.0)  # Normalize entropy to 0-1
                
                evidence_items.append(self._create_evidence(
                    evidence_id=f"{record.record_id}_{secret['type']}_{hash(secret['key'])}",
                    source_system=record.source,
                    evidence_data={
                        'secret_type': secret['type'],
                        'location': secret['location'],
                        'entropy_score': secret['entropy'],
                        'risk_level': 'high' if secret['entropy'] > 4.5 else 'medium'
                    },
                    quality_score=quality_score,
                    compliance_controls=['SOC2_CC6.1', 'ISO27001_A.10.1.1']
                ))
                
        except Exception as e:
            logger.error(f"Secrets analysis failed: {e}")
        
        return evidence_items
    
    def _is_potential_secret(self, key: str, value: str) -> bool:
        """Heuristics to identify potential secrets."""
        if not isinstance(value, str) or len(value) < 8:
            return False
        
        # Check key names that commonly contain secrets
        secret_keywords = [
            'key', 'secret', 'token', 'password', 'pass', 'pwd',
            'credential', 'auth', 'api_key', 'access_key'
        ]
        
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in secret_keywords):
            return self._calculate_entropy(value) > 3.5
        
        return False
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        from collections import Counter
        
        if len(data) == 0:
            return 0
        
        # Count character frequencies
        frequencies = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _scan_file_content(self, file_path: str, content: str) -> List[Dict]:
        """Scan file content for potential secrets."""
        import re
        
        secrets = []
        
        # Common patterns for API keys and tokens
        patterns = [
            (r'[A-Za-z0-9]{32,}', 'high_entropy_string'),
            (r'sk-[A-Za-z0-9]{32,}', 'openai_api_key'),
            (r'AKIA[A-Z0-9]{16}', 'aws_access_key'),
            (r'ghp_[A-Za-z0-9]{36}', 'github_token'),
        ]
        
        for pattern, secret_type in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if self._calculate_entropy(match) > 4.0:
                    secrets.append({
                        'type': secret_type,
                        'key': match[:10] + '...',  # Truncate for logging
                        'entropy': self._calculate_entropy(match),
                        'location': file_path
                    })
        
        return secrets


# Evidence analyzer registry - follows findings-producer pattern
def discover_evidence_analyzers() -> Dict[str, BaseEvidenceAnalyzer]:
    """Discover all available evidence analyzers."""
    analyzers = {
        'secrets_analysis': SecretsScannerEvidenceAnalyzer(),
    }
    
    logger.info(f"Discovered {len(analyzers)} evidence analyzers: {list(analyzers.keys())}")
    return analyzers


async def analyze_evidence_batch(records: List[EvidenceRecord]) -> List[Evidence]:
    """
    Process a batch of evidence records through all analyzers.
    
    This replaces placeholder evidence fabric functions.
    """
    analyzers = discover_evidence_analyzers()
    all_evidence = []
    
    for record in records:
        for analyzer_name, analyzer in analyzers.items():
            try:
                evidence_items = await analyzer.analyze(record)
                all_evidence.extend(evidence_items)
                logger.debug(f"Analyzer {analyzer_name} produced {len(evidence_items)} evidence items")
            except Exception as e:
                logger.error(f"Evidence analyzer {analyzer_name} failed: {e}")
    
    return all_evidence
