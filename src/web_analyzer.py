from dotenv import load_dotenv
load_dotenv()
from playwright.async_api import async_playwright
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import openai
import json
import asyncio
import os
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebScraperError(Exception):
    """Base exception class for WebScraper errors"""
    pass

class CVSSMetrics(BaseModel):
    version: str = "3.1"
    vectorString: str = ""
    attackVector: str = "NETWORK"
    attackComplexity: str = "HIGH"
    privilegesRequired: str = "HIGH"
    userInteraction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentialityImpact: str = "NONE"
    integrityImpact: str = "NONE"
    availabilityImpact: str = "NONE"
    baseScore: float = 0.0
    baseSeverity: str = "NONE"
    exploitCodeMaturity: str = "UNPROVEN"
    remediationLevel: str = "OFFICIAL_FIX"
    reportConfidence: str = "UNKNOWN"
    temporalScore: float = 0.0
    temporalSeverity: str = "NONE"
    confidentialityRequirement: str = "LOW"
    integrityRequirement: str = "LOW"
    availabilityRequirement: str = "LOW"
    modifiedAttackVector: str = "NETWORK"
    modifiedAttackComplexity: str = "HIGH"
    modifiedPrivilegesRequired: str = "HIGH"
    modifiedUserInteraction: str = "NONE"
    modifiedScope: str = "UNCHANGED"
    modifiedConfidentialityImpact: str = "NONE"
    modifiedIntegrityImpact: str = "NONE"
    modifiedAvailabilityImpact: str = "NONE"
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

class WebScraper:
    def __init__(self, openai_api_key: str):
        """Initialize the scraper with OpenAI API key."""
        if not openai_api_key:
            raise WebScraperError("OpenAI API key is required")
        openai.api_key = openai_api_key
        self.client = openai.Client()
    
    async def extract_text_content(self, url: str) -> str:
        """Visit webpage and extract its text content using Playwright."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            try:
                await page.goto(url, timeout=60000)
                await page.wait_for_load_state('networkidle', timeout=60000)
                
                content = await page.evaluate('''() => {
                    const elementsToRemove = document.querySelectorAll(
                        'nav, footer, header, aside, script, style, iframe, .ad, .advertisement, .social-share'
                    );
                    elementsToRemove.forEach(el => el.remove());
                    
                    const article = document.querySelector('article') || document.querySelector('main') || document.body;
                    return article.innerText;
                }''')
                
                if not content.strip():
                    raise WebScraperError("No content found on the page")
                
                return content
            
            except Exception as e:
                raise WebScraperError(f"Failed to extract content: {str(e)}")
            finally:
                await browser.close()
    
    def analyze_content(self, content: str, url: str) -> List[CVEData]:
        """Use OpenAI's tools API to extract CVE data from content."""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "extract_cve_data",
                    "description": "Extract CVE data from article text",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cves": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "description": "CVE ID (e.g., CVE-2024-1234)"},
                                        "severity": {"type": "number", "description": "Base severity score"},
                                        "api_last_modified": {"type": "string", "description": "Last modified date in ISO format"},
                                        "api_created": {"type": "string", "description": "Creation date in ISO format"},
                                        "references": {"type": "array", "items": {"type": "string"}, "description": "List of reference URLs"},
                                        "metrics": {
                                            "type": "object",
                                            "properties": {
                                                "version": {"type": "string"},
                                                "vectorString": {"type": "string"},
                                                "attackVector": {"type": "string"},
                                                "attackComplexity": {"type": "string"},
                                                "privilegesRequired": {"type": "string"},
                                                "userInteraction": {"type": "string"},
                                                "scope": {"type": "string"},
                                                "confidentialityImpact": {"type": "string"},
                                                "integrityImpact": {"type": "string"},
                                                "availabilityImpact": {"type": "string"},
                                                "baseScore": {"type": "number"},
                                                "baseSeverity": {"type": "string"}
                                            }
                                        },
                                        "weaknesses": {"type": "array", "items": {"type": "string"}},
                                        "configurations": {"type": "array", "items": {"type": "string"}}
                                    },
                                    "required": ["name", "metrics"]
                                }
                            }
                        },
                        "required": ["cves"]
                    }
                }
            }
        ]

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": """You are a security analyst that extracts CVE data from articles.
                    Focus on identifying CVE IDs, CVSS scores, attack vectors, and related security metrics.
                    Important formatting rules:
                    - For any numeric scores (baseScore, temporalScore, etc.), use actual numbers (e.g., 7.5) or 0 if unknown
                    - Do not use 'NA', 'N/A', or text values for numeric fields
                    - When metrics are not explicitly stated, derive them from the context or use defaults
                    - For severity levels, use standardized CVSS terms: NONE, LOW, MEDIUM, HIGH, CRITICAL
                    - For dates, use ISO format (YYYY-MM-DD) if known, otherwise leave empty
                    - When extracting CVE IDs, ensure they match the format CVE-YYYY-XXXXX
                    - When vectorString is not provided, construct it based on the available metrics
                    - Include all relevant URLs in the references field"""},
                    {"role": "user", "content": f"Extract all CVE data from this article text: {content[:4000]}"}
                ],
                tools=tools,
                tool_choice={"type": "function", "function": {"name": "extract_cve_data"}}
            )

            # Parse the function call response
            if not response.choices[0].message.tool_calls:
                return []

            extracted_data = json.loads(
                response.choices[0].message.tool_calls[0].function.arguments
            )
            
            # Convert to list of CVEData models
            cve_list = []
            for cve in extracted_data.get('cves', []):
                # Clean up metrics data before creating the model
                metrics_data = cve.get('metrics', {})
                # Convert 'NA' or invalid values to appropriate defaults
                numeric_fields = ['baseScore', 'temporalScore', 'environmentalScore']
                for field in numeric_fields:
                    if metrics_data.get(field) in ['NA', 'N/A', '', None]:
                        metrics_data[field] = 0.0
                    elif isinstance(metrics_data.get(field), str):
                        try:
                            metrics_data[field] = float(metrics_data[field])
                        except ValueError:
                            metrics_data[field] = 0.0
                
                metrics = CVSSMetrics(**metrics_data)
                # Handle severity value
                severity = cve.get('severity')
                if severity in ['NA', 'N/A', '', None]:
                    severity = metrics.baseScore
                elif isinstance(severity, str):
                    try:
                        severity = float(severity)
                    except ValueError:
                        severity = metrics.baseScore

                # Handle dates
                def parse_date(date_str):
                    if not date_str:
                        return datetime.now()
                    try:
                        return datetime.fromisoformat(date_str)
                    except (ValueError, TypeError):
                        return datetime.now()

                cve_data = CVEData(
                    name=cve['name'],
                    severity=severity,
                    api_last_modified=parse_date(cve.get('api_last_modified')),
                    api_created=parse_date(cve.get('api_created')),
                    references=cve.get('references', []),
                    metrics=metrics,
                    weaknesses=cve.get('weaknesses', []),
                    configurations=cve.get('configurations', []),
                    epss_score=cve.get('epss_score', 0.0),
                    epss_percentile=cve.get('epss_percentile', 0.0)
                )
                cve_list.append(cve_data)
            
            return cve_list
            
        except openai.OpenAIError as e:
            raise WebScraperError(f"OpenAI API error: {str(e)}")
        except Exception as e:
            raise WebScraperError(f"Failed to analyze content: {str(e)}")

    async def scrape_page(self, url: str) -> List[CVEData]:
        """Scrape and analyze a webpage for CVE data."""
        content = await self.extract_text_content(url)
        logger.info("Content extracted successfully")
        return self.analyze_content(content, url)

async def main():
    try:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise WebScraperError("Please set the OPENAI_API_KEY environment variable")
        
        scraper = WebScraper(api_key)
        
        url = input("Enter the URL to analyze: ").strip()
        if not url:
            raise WebScraperError("URL cannot be empty")
        
        logger.info(f"Analyzing URL: {url}")
        
        # Scrape and analyze the page
        cve_data_list = await scraper.scrape_page(url)
        
        # Print results
        print("\nExtracted CVE Data:")
        for cve_data in cve_data_list:
            print("\n" + "="*50)
            print(cve_data.model_dump_json(indent=2))
        
    except WebScraperError as e:
        logger.error(f"Scraping error: {str(e)}")
        print(f"\nError: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        print(f"\nAn unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())