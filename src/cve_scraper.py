from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
import aiohttp
import asyncio
import logging
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackVector(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"

class Impact(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"

class Complexity(str, Enum):
    HIGH = "HIGH"
    LOW = "LOW"

class Scope(str, Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"

class ExploitMaturity(str, Enum):
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"

class RemediationLevel(str, Enum):
    OFFICIAL_FIX = "OFFICIAL_FIX"
    TEMPORARY_FIX = "TEMPORARY_FIX"
    WORKAROUND = "WORKAROUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_DEFINED = "NOT_DEFINED"

class Requirement(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"

class CVSSMetrics(BaseModel):
    version: str
    vectorString: str
    attackVector: AttackVector = AttackVector.NETWORK
    attackComplexity: Complexity = Complexity.HIGH
    privilegesRequired: Impact = Impact.HIGH
    userInteraction: str = "NONE"
    scope: Scope = Scope.UNCHANGED
    confidentialityImpact: Impact = Impact.NONE
    integrityImpact: Impact = Impact.NONE
    availabilityImpact: Impact = Impact.NONE
    baseScore: float = 0.0
    baseSeverity: str = "NONE"
    exploitCodeMaturity: ExploitMaturity = ExploitMaturity.UNPROVEN
    remediationLevel: RemediationLevel = RemediationLevel.OFFICIAL_FIX
    reportConfidence: str = "UNKNOWN"
    temporalScore: float = 0.0
    temporalSeverity: str = "NONE"
    confidentialityRequirement: Requirement = Requirement.LOW
    integrityRequirement: Requirement = Requirement.LOW
    availabilityRequirement: Requirement = Requirement.LOW
    modifiedAttackVector: AttackVector = AttackVector.NETWORK
    modifiedAttackComplexity: Complexity = Complexity.HIGH
    modifiedPrivilegesRequired: Impact = Impact.HIGH
    modifiedUserInteraction: str = "NONE"
    modifiedScope: Scope = Scope.UNCHANGED
    modifiedConfidentialityImpact: Impact = Impact.NONE
    modifiedIntegrityImpact: Impact = Impact.NONE
    modifiedAvailabilityImpact: Impact = Impact.NONE
    environmentalScore: float = 0.0
    environmentalSeverity: str = "NONE"

class CVEData(BaseModel):
    name: str
    severity: float = 0.0
    api_last_modified: datetime
    api_created: datetime
    references: List[str] = []
    metrics: CVSSMetrics
    weaknesses: List[str] = []
    configurations: List[str] = []
    epss_score: float = 0.0
    epss_percentile: float = 0.0

class CVEScraper:
    def __init__(self):
        """Initialize the CVE scraper."""
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api_url = "https://api.first.org/data/v1/epss"
    
    async def fetch_cve_data(self, cve_id: str) -> CVEData:
        """Fetch CVE data from NVD and EPSS APIs."""
        async with aiohttp.ClientSession() as session:
            try:
                # Fetch NVD data
                async with session.get(f"{self.nvd_api_url}?cveId={cve_id}") as response:
                    if response.status != 200:
                        raise Exception(f"NVD API returned status {response.status}")
                    nvd_data = await response.json()
                
                # Fetch EPSS data
                async with session.get(f"{self.epss_api_url}?cve={cve_id}") as response:
                    if response.status != 200:
                        raise Exception(f"EPSS API returned status {response.status}")
                    epss_data = await response.json()
                
                # Extract vulnerability data
                vuln = nvd_data['vulnerabilities'][0]['cve']
                metrics = vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                
                # Create CVSSMetrics instance
                cvss_metrics = CVSSMetrics(
                    version=metrics.get('version', '3.1'),
                    vectorString=metrics.get('vectorString', 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N'),
                    attackVector=metrics.get('attackVector', AttackVector.NETWORK),
                    attackComplexity=metrics.get('attackComplexity', Complexity.HIGH),
                    privilegesRequired=metrics.get('privilegesRequired', Impact.HIGH),
                    userInteraction=metrics.get('userInteraction', 'NONE'),
                    scope=metrics.get('scope', Scope.UNCHANGED),
                    confidentialityImpact=metrics.get('confidentialityImpact', Impact.NONE),
                    integrityImpact=metrics.get('integrityImpact', Impact.NONE),
                    availabilityImpact=metrics.get('availabilityImpact', Impact.NONE),
                    baseScore=metrics.get('baseScore', 0.0),
                    baseSeverity=metrics.get('baseSeverity', 'NONE'),
                    exploitCodeMaturity=metrics.get('exploitCodeMaturity', ExploitMaturity.UNPROVEN),
                    remediationLevel=metrics.get('remediationLevel', RemediationLevel.OFFICIAL_FIX),
                    reportConfidence=metrics.get('reportConfidence', 'UNKNOWN'),
                    temporalScore=metrics.get('temporalScore', 0.0),
                    temporalSeverity=metrics.get('temporalSeverity', 'NONE'),
                    confidentialityRequirement=metrics.get('confidentialityRequirement', Requirement.LOW),
                    integrityRequirement=metrics.get('integrityRequirement', Requirement.LOW),
                    availabilityRequirement=metrics.get('availabilityRequirement', Requirement.LOW),
                    modifiedAttackVector=metrics.get('modifiedAttackVector', AttackVector.NETWORK),
                    modifiedAttackComplexity=metrics.get('modifiedAttackComplexity', Complexity.HIGH),
                    modifiedPrivilegesRequired=metrics.get('modifiedPrivilegesRequired', Impact.HIGH),
                    modifiedUserInteraction=metrics.get('modifiedUserInteraction', 'NONE'),
                    modifiedScope=metrics.get('modifiedScope', Scope.UNCHANGED),
                    modifiedConfidentialityImpact=metrics.get('modifiedConfidentialityImpact', Impact.NONE),
                    modifiedIntegrityImpact=metrics.get('modifiedIntegrityImpact', Impact.NONE),
                    modifiedAvailabilityImpact=metrics.get('modifiedAvailabilityImpact', Impact.NONE),
                    environmentalScore=metrics.get('environmentalScore', 0.0),
                    environmentalSeverity=metrics.get('environmentalSeverity', 'NONE')
                )
                
                # Get EPSS scores
                epss_scores = epss_data.get('data', [{}])[0]
                
                # Create CVE data instance
                cve_data = CVEData(
                    name=cve_id,
                    severity=cvss_metrics.baseScore,
                    api_last_modified=datetime.fromisoformat(vuln['lastModified']),
                    api_created=datetime.fromisoformat(vuln['published']),
                    references=[ref['url'] for ref in vuln.get('references', [])],
                    metrics=cvss_metrics,
                    weaknesses=[w['description'][0]['value'] for w in vuln.get('weaknesses', [])],
                    configurations=[],  # Add configuration parsing if needed
                    epss_score=float(epss_scores.get('epss', 0)),
                    epss_percentile=float(epss_scores.get('percentile', 0))
                )
                
                return cve_data
                
            except Exception as e:
                logger.error(f"Error fetching CVE data: {str(e)}")
                raise

async def main():
    try:
        # Initialize scraper
        scraper = CVEScraper()
        
        # Get CVE ID from user
        cve_id = input("Enter the CVE ID (e.g., CVE-2024-1234): ").strip()
        if not cve_id:
            raise ValueError("CVE ID cannot be empty")
        
        logger.info(f"Fetching data for {cve_id}")
        
        # Fetch and display CVE data
        cve_data = await scraper.fetch_cve_data(cve_id)
        
        # Print results as JSON
        print("\nCVE Data:")
        print(cve_data.model_dump_json(indent=2))
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        print(f"\nAn error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())