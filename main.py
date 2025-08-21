from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import re
import asyncio
import aiohttp
from datetime import datetime, timedelta
import time
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import json
import hashlib
import ssl
import socket
from urllib.parse import urlparse
import Levenshtein

app = FastAPI(title="Phishing Detection API", version="2.0.0")

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Banking-specific threat detection patterns
BANKING_KEYWORDS = [
    "bank", "banking", "account", "login", "secure", "verify", "update", 
    "suspended", "locked", "confirm", "validation", "authentication", 
    "paypal", "visa", "mastercard", "amex", "chase", "wellsfargo", 
    "bankofamerica", "citibank", "hsbc", "santander"
]

SUSPICIOUS_BANKING_PATTERNS = [
    re.compile(r'bank.*secure', re.IGNORECASE),
    re.compile(r'verify.*account', re.IGNORECASE),
    re.compile(r'update.*banking', re.IGNORECASE),
    re.compile(r'suspended.*account', re.IGNORECASE),
    re.compile(r'confirm.*identity', re.IGNORECASE),
    re.compile(r'security.*alert', re.IGNORECASE),
    re.compile(r'urgent.*action', re.IGNORECASE),
    re.compile(r'click.*here.*verify', re.IGNORECASE)
]

LEGITIMATE_BANKING_DOMAINS = [
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", 
    "usbank.com", "pnc.com", "capitalone.com", "ally.com", "schwab.com", 
    "fidelity.com", "paypal.com", "americanexpress.com", "discover.com"
]

KNOWN_PHISHING_PATTERNS = [
    re.compile(r'[0-9]+.*bank', re.IGNORECASE),
    re.compile(r'bank.*[0-9]+', re.IGNORECASE),
    re.compile(r'secure.*[0-9]+', re.IGNORECASE),
    re.compile(r'.*-bank-.*\.com', re.IGNORECASE),
    re.compile(r'.*bank-secure.*\.com', re.IGNORECASE),
    re.compile(r'.*verify-account.*\.com', re.IGNORECASE)
]

# Models
class URLRequest(BaseModel):
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError('Invalid URL format')
            return v
        except:
            raise ValueError('Invalid URL format')

class BulkURLRequest(BaseModel):
    urls: List[str] = Field(..., max_items=50)
    
    @validator('urls', each_item=True)
    def validate_each_url(cls, v):
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError(f'Invalid URL format: {v}')
            return v
        except:
            raise ValueError(f'Invalid URL format: {v}')

class FeatureAnalysis(BaseModel):
    name: str
    detected: bool
    description: str
    weight: float
    details: Optional[List[str]] = None
    riskFactors: Optional[List[str]] = None
    threatType: Optional[str] = None
    source: Optional[str] = None

class BankingAnalysis(BaseModel):
    isSuspicious: bool
    description: str
    details: List[str]
    riskFactors: List[str]

class ThreatIntelligence(BaseModel):
    isKnownThreat: bool
    source: Optional[str] = None
    lastSeen: Optional[datetime] = None
    threatType: Optional[str] = None
    matchedPattern: Optional[str] = None

class AnalysisResult(BaseModel):
    url: str
    status: str
    confidence: float
    riskScore: float
    features: List[FeatureAnalysis]
    bankingAnalysis: BankingAnalysis
    threatIntelligence: ThreatIntelligence
    analysis: Dict[str, Any]

class AnalysisResponse(BaseModel):
    success: bool
    data: AnalysisResult
    timestamp: datetime

class BulkAnalysisResponse(BaseModel):
    success: bool
    data: Dict[str, Any]
    timestamp: datetime

class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    services: Dict[str, str]

class StatsResponse(BaseModel):
    success: bool
    data: Dict[str, Any]

# Database simulation (in-memory for demo)
analysis_logs = []
threat_feeds = {
    "phishTank": [],
    "openPhish": [],
    "malwareDomains": [],
    "bankingThreats": []
}
last_update = None

# Helper functions
async def check_banking_threats(hostname):
    analysis = {
        "isSuspicious": False,
        "description": "Domain appears safe for banking context",
        "details": [],
        "riskFactors": []
    }
    
    domain_lower = hostname.lower()
    
    # Check if it's a legitimate banking domain
    is_legitimate = any(
        domain_lower == domain or domain_lower.endswith("." + domain)
        for domain in LEGITIMATE_BANKING_DOMAINS
    )
    
    if is_legitimate:
        analysis["description"] = "Legitimate banking domain verified"
        analysis["details"].append("Domain verified as legitimate financial institution")
        return analysis
    
    # Check for banking keywords in suspicious contexts
    has_banking_keywords = any(keyword in domain_lower for keyword in BANKING_KEYWORDS)
    
    if has_banking_keywords:
        analysis["riskFactors"].append("Contains banking-related keywords")
        
        # Check for suspicious patterns
        has_suspicious_pattern = any(pattern.search(domain_lower) for pattern in SUSPICIOUS_BANKING_PATTERNS)
        
        if has_suspicious_pattern:
            analysis["isSuspicious"] = True
            analysis["description"] = "CRITICAL: Domain contains banking keywords with suspicious patterns"
            analysis["details"].append("Banking-related domain with phishing indicators")
            analysis["riskFactors"].append("Matches known phishing patterns")
    
    # Check for known phishing patterns
    has_phishing_pattern = any(pattern.search(domain_lower) for pattern in KNOWN_PHISHING_PATTERNS)
    
    if has_phishing_pattern:
        analysis["isSuspicious"] = True
        analysis["description"] = "CRITICAL: Domain matches known banking phishing patterns"
        analysis["details"].append("Domain structure commonly used in banking phishing attacks")
        analysis["riskFactors"].append("Matches banking phishing signature")
    
    # Check for domain spoofing attempts
    spoofing_attempts = [
        legit for legit in LEGITIMATE_BANKING_DOMAINS
        if calculate_similarity(domain_lower, legit) > 0.7 and calculate_similarity(domain_lower, legit) < 1.0
    ]
    
    if spoofing_attempts:
        analysis["isSuspicious"] = True
        analysis["description"] = f"CRITICAL: Potential spoofing of {spoofing_attempts[0]}"
        analysis["details"].append(f"Domain appears to mimic legitimate banking site: {spoofing_attempts[0]}")
        analysis["riskFactors"].append("Domain spoofing detected")
    
    # Check for suspicious TLD with banking keywords
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".pw", ".cc"]
    has_suspicious_tld = any(domain_lower.endswith(tld) for tld in suspicious_tlds)
    
    if has_banking_keywords and has_suspicious_tld:
        analysis["isSuspicious"] = True
        analysis["description"] = "CRITICAL: Banking keywords with suspicious domain extension"
        analysis["details"].append("Banking-related content on suspicious domain extension")
        analysis["riskFactors"].append("Suspicious TLD with banking context")
    
    return analysis

def calculate_similarity(str1, str2):
    longer = str1 if len(str1) > len(str2) else str2
    shorter = str2 if len(str1) > len(str2) else str1
    
    if len(longer) == 0:
        return 1.0
    
    edit_distance = Levenshtein.distance(longer, shorter)
    return (len(longer) - edit_distance) / len(longer)

async def check_ssl_certificate(hostname):
    # Simulate SSL checking
    common_secure_domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
        "github.com", "stackoverflow.com", "wikipedia.org", "bankofamerica.com",
        "chase.com", "wellsfargo.com", "paypal.com"
    ]
    
    domain_lower = hostname.lower()
    is_common_secure = any(
        domain_lower == domain or domain_lower.endswith("." + domain)
        for domain in common_secure_domains
    )
    
    await asyncio.sleep(0.5)  # Simulate async operation
    return is_common_secure

async def check_domain_reputation(domain):
    # Simulate API call delay
    await asyncio.sleep(0.1)
    
    # Known legitimate domains
    legitimate_domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
        "netflix.com", "twitter.com", "instagram.com", "linkedin.com", "github.com",
        "stackoverflow.com", "wikipedia.org", "bankofamerica.com", "chase.com",
        "wellsfargo.com", "paypal.com"
    ]
    
    # Known suspicious domains
    suspicious_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    
    domain_lower = domain.lower()
    
    if any(domain_lower in legit for legit in legitimate_domains):
        return 0.9  # High reputation
    
    if any(domain_lower in sus for sus in suspicious_domains):
        return 0.3  # Low reputation
    
    # Check for suspicious patterns
    if "secure" in domain_lower or "verify" in domain_lower:
        return 0.4
    
    # Default neutral reputation
    return 0.6

async def update_threat_feeds():
    global threat_feeds, last_update
    try:
        # In production, these would be real API calls
        threat_feeds["phishTank"] = [
            "phishing-bank-example.com", "fake-chase-login.tk",
            "secure-banking-update.ml", "verify-account-now.ga"
        ]
        
        threat_feeds["bankingThreats"] = [
            "bank-security-alert.com", "urgent-account-verification.net",
            "suspended-banking-access.org", "confirm-identity-now.info"
        ]
        
        last_update = datetime.now()
        print(f"Threat intelligence updated: {last_update.isoformat()}")
    except Exception as e:
        print(f"Failed to update threat feeds: {e}")

async def check_domain_threat(domain):
    domain_lower = domain.lower()
    
    # Check all threat feeds
    for feed_name, threats in threat_feeds.items():
        if domain_lower in threats:
            return {
                "isKnownThreat": True,
                "source": feed_name,
                "lastSeen": last_update,
                "threatType": "BANKING_PHISHING" if feed_name == "bankingThreats" else "GENERAL_PHISHING"
            }
        
        # Check for partial matches
        for threat in threats:
            if domain_lower in threat or threat in domain_lower:
                return {
                    "isKnownThreat": True,
                    "source": feed_name,
                    "lastSeen": last_update,
                    "threatType": "PARTIAL_MATCH",
                    "matchedPattern": threat
                }
    
    return {
        "isKnownThreat": False,
        "source": None,
        "lastSeen": last_update
    }

async def log_analysis(url, result, client_ip):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "status": result["status"],
        "confidence": result["confidence"],
        "riskScore": result["riskScore"],
        "clientIP": client_ip or "unknown",
        "detectedThreats": len([f for f in result["features"] if f["detected"]]),
        "bankingThreat": result["bankingAnalysis"]["isSuspicious"],
        "knownThreat": result["threatIntelligence"]["isKnownThreat"]
    }
    
    analysis_logs.append(log_entry)
    # Keep only last 100 logs
    if len(analysis_logs) > 100:
        analysis_logs.pop(0)
    
    return log_entry

async def analyze_url(url_string):
    features = []
    risk_score = 0.0
    
    try:
        parsed_url = urlparse(url_string)
        hostname = parsed_url.hostname
        
        # Feature 1: IP Address Detection
        has_ip = re.match(r"(\d{1,3}\.){3}\d{1,3}", hostname) is not None
        features.append({
            "name": "IP Address Usage",
            "detected": has_ip,
            "description": "Uses IP address instead of domain name" if has_ip else "Uses proper domain name",
            "weight": 0.3
        })
        if has_ip:
            risk_score += 0.3
        
        # Feature 2: HTTPS Protocol
        has_https = parsed_url.scheme == "https"
        features.append({
            "name": "HTTPS Security",
            "detected": not has_https,
            "description": "Uses secure HTTPS protocol" if has_https else "Missing HTTPS encryption",
            "weight": 0.25
        })
        if not has_https:
            risk_score += 0.25
        
        # Feature 3: URL Length Analysis
        long_url = len(url_string) > 75
        features.append({
            "name": "URL Length",
            "detected": long_url,
            "description": f"Unusually long URL ({len(url_string)} characters)" if long_url else "Normal URL length",
            "weight": 0.15
        })
        if long_url:
            risk_score += 0.15
        
        # Feature 4: @ Symbol Detection
        has_at_symbol = "@" in url_string
        features.append({
            "name": "@ Symbol",
            "detected": has_at_symbol,
            "description": "Contains @ symbol (often used in phishing)" if has_at_symbol else "No @ symbol detected",
            "weight": 0.25
        })
        if has_at_symbol:
            risk_score += 0.25
        
        # Feature 5: Subdomain Analysis
        subdomains = hostname.split(".")
        subdomain_count = len(subdomains) - 2
        many_subdomains = subdomain_count > 3
        features.append({
            "name": "Subdomain Count",
            "detected": many_subdomains,
            "description": f"Too many subdomains ({subdomain_count})" if many_subdomains else "Normal subdomain structure",
            "weight": 0.1
        })
        if many_subdomains:
            risk_score += 0.1
        
        # Feature 6: Suspicious TLD Check
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".pw", ".cc"]
        has_suspicious_tld = any(hostname.lower().endswith(tld) for tld in suspicious_tlds)
        features.append({
            "name": "Domain Extension",
            "detected": has_suspicious_tld,
            "description": "Uses suspicious domain extension" if has_suspicious_tld else "Common domain extension",
            "weight": 0.2
        })
        if has_suspicious_tld:
            risk_score += 0.2
        
        # Feature 7: SSL Certificate Check
        ssl_valid = False
        if has_https:
            ssl_valid = await check_ssl_certificate(hostname)
        
        features.append({
            "name": "SSL Certificate",
            "detected": not ssl_valid and has_https,
            "description": "Valid SSL certificate" if ssl_valid else "Invalid/expired SSL certificate" if has_https else "No SSL certificate",
            "weight": 0.2
        })
        if not ssl_valid and has_https:
            risk_score += 0.2
        
        # Feature 8: Domain Reputation Check
        reputation_score = await check_domain_reputation(hostname)
        bad_reputation = reputation_score < 0.5
        features.append({
            "name": "Domain Reputation",
            "detected": bad_reputation,
            "description": "Poor domain reputation" if bad_reputation else "Good domain reputation",
            "weight": 0.25
        })
        if bad_reputation:
            risk_score += 0.25
        
        # Feature 9: Banking Threat Detection
        banking_threat = await check_banking_threats(hostname)
        features.append({
            "name": "Banking Threat Analysis",
            "detected": banking_threat["isSuspicious"],
            "description": banking_threat["description"],
            "weight": 0.3,
            "details": banking_threat["details"],
            "riskFactors": banking_threat["riskFactors"]
        })
        if banking_threat["isSuspicious"]:
            risk_score += 0.3
        
        # Feature 10: Threat Intelligence Check
        threat_intel = await check_domain_threat(hostname)
        features.append({
            "name": "Threat Intelligence",
            "detected": threat_intel["isKnownThreat"],
            "description": f"Known threat from {threat_intel['source']}" if threat_intel["isKnownThreat"] else "No known threats detected",
            "weight": 0.4,
            "threatType": threat_intel.get("threatType"),
            "source": threat_intel.get("source")
        })
        if threat_intel["isKnownThreat"]:
            risk_score += 0.4
        
        # Determine final classification
        if risk_score >= 0.8:
            status = "High Risk"
            confidence = min(0.98, 0.8 + (risk_score - 0.8) * 0.5)
        elif risk_score >= 0.6:
            status = "Phishing"
            confidence = min(0.95, 0.7 + (risk_score - 0.6) * 0.5)
        elif risk_score >= 0.4:
            status = "Suspicious"
            confidence = 0.6 + (risk_score - 0.4) * 0.3
        else:
            status = "Legitimate"
            confidence = max(0.8, 1.0 - risk_score)
        
        return {
            "url": url_string,
            "status": status,
            "confidence": round(confidence, 2),
            "riskScore": round(risk_score, 2),
            "features": features,
            "bankingAnalysis": banking_threat,
            "threatIntelligence": threat_intel,
            "analysis": {
                "totalFeatures": len(features),
                "detectedThreats": len([f for f in features if f["detected"]]),
                "analysisTime": datetime.now().isoformat()
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL or analysis failed: {str(e)}")

# Initialize services
@app.on_event("startup")
async def startup_event():
    await update_threat_feeds()
    # Update feeds every hour
    asyncio.create_task(periodic_threat_feed_update())

async def periodic_threat_feed_update():
    while True:
        await asyncio.sleep(3600)  # 1 hour
        await update_threat_feeds()

# Routes
@app.post("/api/analyze-url", response_model=AnalysisResponse)
@limiter.limit("100/15 minutes")
async def analyze_url_endpoint(request: Request, url_request: URLRequest):
    try:
        result = await analyze_url(url_request.url)
        
        client_ip = request.client.host
        await log_analysis(url_request.url, result, client_ip)
        
        return {
            "success": True,
            "data": result,
            "timestamp": datetime.now()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "version": "2.0.0",
        "services": {
            "phishingAnalyzer": "active",
            "threatIntelligence": "active",
            "bankingDetector": "active",
            "sslChecker": "active",
            "reputationChecker": "active",
            "logger": "active"
        }
    }

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    stats = {
        "totalScans": 15420,
        "phishingDetected": 2341,
        "legitimateSites": 11876,
        "suspiciousSites": 1203,
        "bankingThreats": 156,
        "knownThreats": 8,
        "lastUpdated": datetime.now().isoformat(),
        "threatFeeds": {
            "phishTank": len(threat_feeds["phishTank"]),
            "openPhish": len(threat_feeds["openPhish"]),
            "malwareDomains": len(threat_feeds["malwareDomains"]),
            "bankingThreats": len(threat_feeds["bankingThreats"])
        }
    }
    
    return {
        "success": True,
        "data": stats
    }

@app.post("/api/analyze-bulk", response_model=BulkAnalysisResponse)
@limiter.limit("50/15 minutes")
async def analyze_bulk_urls(request: Request, bulk_request: BulkURLRequest):
    try:
        results = []
        client_ip = request.client.host
        
        for url in bulk_request.urls:
            try:
                result = await analyze_url(url)
                await log_analysis(url, result, client_ip)
                results.append({
                    "url": url,
                    "success": True,
                    "data": result
                })
            except Exception as e:
                results.append({
                    "url": url,
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": True,
            "data": {
                "results": results,
                "summary": {
                    "total": len(bulk_request.urls),
                    "successful": len([r for r in results if r["success"]]),
                    "failed": len([r for r in results if not r["success"]])
                }
            },
            "timestamp": datetime.now()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(limit: int = 100, offset: int = 0):
    logs = analysis_logs[-limit-offset:][:limit] if analysis_logs else []
    return {
        "success": True,
        "data": {
            "logs": logs,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": len(analysis_logs)
            }
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
