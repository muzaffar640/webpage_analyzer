from dotenv import load_dotenv
load_dotenv()
from playwright.async_api import async_playwright
from pydantic import BaseModel, HttpUrl
from typing import Optional
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

class ArticleData(BaseModel):
    author: Optional[str] = None
    date_published: Optional[datetime] = None
    summary: str
    url: HttpUrl

class WebScraper:
    def __init__(self, openai_api_key: str):
        """Initialize the scraper with OpenAI API key."""
        if not openai_api_key:
            raise WebScraperError("OpenAI API key is required")
        self.client = openai.AsyncOpenAI(api_key=openai_api_key) 
    
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
    
    async def analyze_content(self, content: str, url: str) -> ArticleData:
        """Use OpenAI's tools API to extract structured data."""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "extract_article_data",
                    "description": "Extract structured data from article text",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "author": {
                                "type": "string",
                                "description": "The author of the article"
                            },
                            "date_published": {
                                "type": "string",
                                "description": "The publication date in ISO format (YYYY-MM-DD)"
                            },
                            "summary": {
                                "type": "string",
                                "description": "A concise summary of the article (max 200 words)"
                            }
                        },
                        "required": ["summary"]
                    }
                }
            }
        ]

        try:
            response = await self.client.chat.completions.create( 
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that extracts structured data from web articles."},
                    {"role": "user", "content": f"Extract the author, publication date, and a summary from this article text: {content[:4000]}"}
                ],
                tools=tools,
                tool_choice={"type": "function", "function": {"name": "extract_article_data"}}
            )

            # Parse the function call response
            function_args = json.loads(
                response.choices[0].message.tool_calls[0].function.arguments
            )
            
            # Convert to Pydantic model
            return ArticleData(
                author=function_args.get('author'),
                date_published=datetime.fromisoformat(function_args['date_published']) if function_args.get('date_published') else None,
                summary=function_args['summary'],
                url=url
            )
            
        except openai.OpenAIError as e:
            raise WebScraperError(f"OpenAI API error: {str(e)}")
        except Exception as e:
            raise WebScraperError(f"Failed to analyze content: {str(e)}")

    async def scrape_page(self, url: str) -> ArticleData:
        """Scrape and analyze a webpage."""
        content = await self.extract_text_content(url)
        logger.info("Content extracted successfully")
        return await self.analyze_content(content, url)

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
        article_data = await scraper.scrape_page(url)
        
        print("\nExtracted Data:")
        print(article_data.model_dump_json(indent=2))
        
    except WebScraperError as e:
        logger.error(f"Scraping error: {str(e)}")
        print(f"\nError: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        print(f"\nAn unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())