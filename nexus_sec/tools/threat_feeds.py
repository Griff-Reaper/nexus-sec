"""
Threat Intelligence Feed Manager for Nexus-Sec.

Integrates multiple threat intel sources:
- AbuseIPDB (IP reputation)
- AlienVault OTX (Open Threat Exchange)
- VirusTotal (multi-engine malware scanning)

Architecture designed for easy expansion to MITRE/STIX feeds.
"""

import os
import hashlib
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import json


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    UNKNOWN = 0


class IOCType(Enum):
    """Indicator of Compromise types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


@dataclass
class ThreatIntelResult:
    """Standardized threat intel result"""
    indicator: str
    ioc_type: IOCType
    is_malicious: bool
    threat_level: ThreatLevel
    confidence_score: float  # 0.0 - 1.0
    sources: List[str]
    threat_types: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}
    
    def calculate_risk_score(self) -> float:
        """
        Calculate composite risk score (0-100)
        Combines threat level, confidence, and number of sources
        """
        base_score = self.threat_level.value * 20
        confidence_factor = self.confidence_score
        source_factor = min(len(self.sources) / 3, 1.0)  # More sources = higher confidence
        
        final_score = base_score * confidence_factor * (0.8 + 0.2 * source_factor)
        return min(100, max(0, final_score))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        result = asdict(self)
        result['ioc_type'] = self.ioc_type.value
        result['threat_level'] = self.threat_level.name
        result['risk_score'] = self.calculate_risk_score()
        return result


class ThreatFeedBase:
    """Base class for threat intelligence feeds"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    @property
    def name(self) -> str:
        """Feed name"""
        raise NotImplementedError
    
    def is_configured(self) -> bool:
        """Check if feed has required API key"""
        return self.api_key is not None
    
    def _cache_key(self, indicator: str, ioc_type: IOCType) -> str:
        """Generate cache key"""
        return f"{self.name}:{ioc_type.value}:{indicator}"
    
    def _get_cached(self, indicator: str, ioc_type: IOCType) -> Optional[Dict]:
        """Get cached result if fresh"""
        key = self._cache_key(indicator, ioc_type)
        if key in self.cache:
            cached_time, result = self.cache[key]
            if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                return result
        return None
    
    def _set_cache(self, indicator: str, ioc_type: IOCType, result: Dict):
        """Cache a result"""
        key = self._cache_key(indicator, ioc_type)
        self.cache[key] = (datetime.now(), result)
    
    def lookup(self, indicator: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """
        Look up indicator in this feed
        Returns standardized threat intel dict or None
        """
        raise NotImplementedError


class AbuseIPDBFeed(ThreatFeedBase):
    """AbuseIPDB threat feed for IP reputation"""
    
    @property
    def name(self) -> str:
        return "AbuseIPDB"
    
    def lookup(self, indicator: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """Look up IP in AbuseIPDB"""
        if ioc_type != IOCType.IP:
            return None
        
        if not self.is_configured():
            return None
        
        # Check cache
        cached = self._get_cached(indicator, ioc_type)
        if cached:
            return cached
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": indicator,
                "maxAgeInDays": 90,
                "verbose": True
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "data" in data:
                abuse_score = data["data"].get("abuseConfidenceScore", 0)
                is_malicious = abuse_score > 25  # Threshold
                
                # Map abuse score to threat level
                if abuse_score >= 75:
                    threat_level = ThreatLevel.CRITICAL
                elif abuse_score >= 50:
                    threat_level = ThreatLevel.HIGH
                elif abuse_score >= 25:
                    threat_level = ThreatLevel.MEDIUM
                else:
                    threat_level = ThreatLevel.LOW
                
                result = {
                    "is_malicious": is_malicious,
                    "threat_level": threat_level,
                    "confidence": abuse_score / 100,
                    "threat_types": data["data"].get("usageType", "Unknown"),
                    "reports": data["data"].get("totalReports", 0),
                    "last_seen": data["data"].get("lastReportedAt"),
                    "tags": ["abuse", "reputation"]
                }
                
                self._set_cache(indicator, ioc_type, result)
                return result
        
        except Exception as e:
            print(f"AbuseIPDB lookup error: {e}")
            return None
        
        return None


class AlienVaultOTXFeed(ThreatFeedBase):
    """AlienVault OTX threat feed"""
    
    @property
    def name(self) -> str:
        return "AlienVault_OTX"
    
    def lookup(self, indicator: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """Look up indicator in AlienVault OTX"""
        if not self.is_configured():
            return None
        
        # Check cache
        cached = self._get_cached(indicator, ioc_type)
        if cached:
            return cached
        
        try:
            # Map IOC type to OTX endpoint
            type_map = {
                IOCType.IP: "IPv4",
                IOCType.DOMAIN: "domain",
                IOCType.URL: "url",
                IOCType.HASH: "file"
            }
            
            otx_type = type_map.get(ioc_type)
            if not otx_type:
                return None
            
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            is_malicious = pulse_count > 0
            
            # Determine threat level based on pulse count
            if pulse_count >= 10:
                threat_level = ThreatLevel.CRITICAL
            elif pulse_count >= 5:
                threat_level = ThreatLevel.HIGH
            elif pulse_count >= 1:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            tags = []
            threat_types = []
            if "pulse_info" in data and "pulses" in data["pulse_info"]:
                for pulse in data["pulse_info"]["pulses"][:5]:  # Top 5 pulses
                    tags.extend(pulse.get("tags", []))
                    if "name" in pulse:
                        threat_types.append(pulse["name"])
            
            result = {
                "is_malicious": is_malicious,
                "threat_level": threat_level,
                "confidence": min(pulse_count / 10, 1.0),
                "threat_types": threat_types,
                "pulse_count": pulse_count,
                "tags": list(set(tags)),  # Unique tags
                "reputation": data.get("reputation", 0)
            }
            
            self._set_cache(indicator, ioc_type, result)
            return result
        
        except Exception as e:
            print(f"AlienVault OTX lookup error: {e}")
            return None
        
        return None


class VirusTotalFeed(ThreatFeedBase):
    """VirusTotal multi-engine scanner"""
    
    @property
    def name(self) -> str:
        return "VirusTotal"
    
    def lookup(self, indicator: str, ioc_type: IOCType) -> Optional[Dict[str, Any]]:
        """Look up indicator in VirusTotal"""
        if not self.is_configured():
            return None
        
        # Check cache
        cached = self._get_cached(indicator, ioc_type)
        if cached:
            return cached
        
        try:
            headers = {"x-apikey": self.api_key}
            
            # Different endpoints for different IOC types
            if ioc_type == IOCType.IP:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif ioc_type == IOCType.DOMAIN:
                url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
            elif ioc_type == IOCType.HASH:
                url = f"https://www.virustotal.com/api/v3/files/{indicator}"
            elif ioc_type == IOCType.URL:
                # URL needs to be base64 encoded
                url_id = hashlib.md5(indicator.encode()).hexdigest()
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                return None
            
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "data" in data and "attributes" in data["data"]:
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                is_malicious = malicious_count > 0
                confidence = malicious_count / max(total_engines, 1)
                
                # Determine threat level
                if malicious_count >= 10:
                    threat_level = ThreatLevel.CRITICAL
                elif malicious_count >= 5:
                    threat_level = ThreatLevel.HIGH
                elif malicious_count >= 2:
                    threat_level = ThreatLevel.MEDIUM
                elif malicious_count >= 1:
                    threat_level = ThreatLevel.LOW
                else:
                    threat_level = ThreatLevel.INFO
                
                result = {
                    "is_malicious": is_malicious,
                    "threat_level": threat_level,
                    "confidence": confidence,
                    "threat_types": [f"Detected by {malicious_count}/{total_engines} engines"],
                    "malicious_count": malicious_count,
                    "total_engines": total_engines,
                    "tags": attrs.get("tags", []),
                    "reputation": attrs.get("reputation", 0)
                }
                
                self._set_cache(indicator, ioc_type, result)
                return result
        
        except Exception as e:
            print(f"VirusTotal lookup error: {e}")
            return None
        
        return None


class ThreatIntelManager:
    """
    Central manager for multiple threat intel feeds.
    Aggregates results from multiple sources for comprehensive analysis.
    """
    
    def __init__(self):
        """Initialize threat intel manager with all available feeds"""
        self.feeds: List[ThreatFeedBase] = []
        
        # Initialize feeds from environment variables
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        if abuseipdb_key:
            self.feeds.append(AbuseIPDBFeed(abuseipdb_key))
        
        otx_key = os.getenv("OTX_API_KEY")
        if otx_key:
            self.feeds.append(AlienVaultOTXFeed(otx_key))
        
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if vt_key:
            self.feeds.append(VirusTotalFeed(vt_key))
        
        print(f"✓ Threat Intel Manager initialized with {len(self.feeds)} feed(s)")
        for feed in self.feeds:
            print(f"  - {feed.name}")
    
    def enrich_ioc(self, indicator: str, ioc_type: IOCType) -> ThreatIntelResult:
        """
        Enrich an IOC by querying all available feeds.
        Aggregates and correlates results for comprehensive analysis.
        
        Args:
            indicator: The indicator to check (IP, domain, hash, etc.)
            ioc_type: Type of indicator
            
        Returns:
            ThreatIntelResult with aggregated data from all sources
        """
        if not self.feeds:
            # Fallback to demo database if no feeds configured
            return self._demo_lookup(indicator, ioc_type)
        
        results = []
        sources = []
        threat_types = []
        all_tags = []
        metadata = {}
        
        # Query all feeds
        for feed in self.feeds:
            result = feed.lookup(indicator, ioc_type)
            if result:
                results.append(result)
                sources.append(feed.name)
                
                if "threat_types" in result:
                    if isinstance(result["threat_types"], list):
                        threat_types.extend(result["threat_types"])
                    else:
                        threat_types.append(result["threat_types"])
                
                if "tags" in result:
                    all_tags.extend(result["tags"])
                
                # Store feed-specific data in metadata
                metadata[feed.name] = result
        
        if not results:
            # No results from any feed
            return ThreatIntelResult(
                indicator=indicator,
                ioc_type=ioc_type,
                is_malicious=False,
                threat_level=ThreatLevel.UNKNOWN,
                confidence_score=0.0,
                sources=[],
                threat_types=["Unknown"],
                tags=[],
                metadata={}
            )
        
        # Aggregate results
        malicious_votes = sum(1 for r in results if r.get("is_malicious", False))
        is_malicious = malicious_votes > 0
        
        # Average confidence across sources
        confidences = [r.get("confidence", 0) for r in results]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Take highest threat level
        threat_levels = [r.get("threat_level", ThreatLevel.UNKNOWN) for r in results]
        max_threat_level = max(threat_levels, key=lambda x: x.value)
        
        return ThreatIntelResult(
            indicator=indicator,
            ioc_type=ioc_type,
            is_malicious=is_malicious,
            threat_level=max_threat_level,
            confidence_score=avg_confidence,
            sources=sources,
            threat_types=list(set(threat_types)),
            tags=list(set(all_tags)),
            metadata=metadata
        )
    
    def _demo_lookup(self, indicator: str, ioc_type: IOCType) -> ThreatIntelResult:
        """
        Fallback to demo database when no real feeds configured.
        Uses the original threat_intel.py demo data.
        """
        from .threat_intel import THREAT_DATABASE
        
        # Map IOC type to database key
        db_key = {
            IOCType.IP: "ips",
            IOCType.DOMAIN: "domains",
            IOCType.HASH: "hashes"
        }.get(ioc_type)
        
        demo_result = THREAT_DATABASE.get(db_key, {}).get(indicator)
        
        if demo_result:
            is_malicious = demo_result["status"] == "malicious"
            
            # Map to threat level
            if is_malicious:
                threat_level = ThreatLevel.HIGH
            else:
                threat_level = ThreatLevel.LOW
            
            return ThreatIntelResult(
                indicator=indicator,
                ioc_type=ioc_type,
                is_malicious=is_malicious,
                threat_level=threat_level,
                confidence_score=0.8 if demo_result.get("confidence") == "high" else 0.5,
                sources=["Demo Database"],
                threat_types=[demo_result.get("threat_type", "Unknown")],
                tags=demo_result.get("tags", []),
                metadata={"demo": True}
            )
        
        return ThreatIntelResult(
            indicator=indicator,
            ioc_type=ioc_type,
            is_malicious=False,
            threat_level=ThreatLevel.UNKNOWN,
            confidence_score=0.0,
            sources=["Demo Database"],
            threat_types=["Unknown"],
            tags=[],
            metadata={"demo": True, "found": False}
        )
