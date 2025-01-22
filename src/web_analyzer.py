from dotenv import load_dotenv
load_dotenv() 
from playwright.sync_api import sync_playwright
from pydantic import BaseModel
from typing import Optional
import openai
import os
from datetime import datetime

# Define our data structure using Pydantic
class ArticleData(BaseModel):
    author: Optional[str] = None
    date_published: Optional[datetime] = None
    summary: str
    url: str

class WebScraper:
    def __init__(self, openai_api_key: str):
        """Initialize the scraper with OpenAI API key."""
        self.client = openai.OpenAI(api_key=openai_api_key)
    
    def extract_text_content(self, url: str) -> str:
        """Visit webpage and extract its text content using Playwright."""
        with sync_playwright() as p:
            # Launch browser in headless mode
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            try:
                # Navigate to the URL
                page.goto(url)
                
                # Wait for the content to load
                page.wait_for_load_state('networkidle')
                
                # Extract the main content (you might need to adjust these selectors)
                content = page.evaluate('''() => {
                    // Remove unwanted elements
                    const elementsToRemove = document.querySelectorAll('nav, footer, header, aside, script, style');
                    elementsToRemove.forEach(el => el.remove());
                    
                    // Get the main content
                    return document.body.innerText;
                }''')
                
                return content
            
            finally:
                browser.close()
    
    def analyze_content(self, content: str, url: str) -> ArticleData:
        """Use OpenAI's function calling to extract structured data."""
        # Define the function that OpenAI will call
        functions = [
            {
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
                            "description": "A concise summary of the article"
                        }
                    },
                    "required": ["summary"]
                }
            }
        ]

        # Call OpenAI API
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that extracts structured data from web articles."},
                {"role": "user", "content": f"Extract the author, publication date, and a summary from this article text: {content}"}
            ],
            functions=functions,
            function_call={"name": "extract_article_data"}
        )

        # Parse the response
        extracted_data = eval(response.choices[0].message.function_call.arguments)
        
        # Convert to our Pydantic model
        return ArticleData(
            author=extracted_data.get('author'),
            date_published=datetime.fromisoformat(extracted_data['date_published']) if extracted_data.get('date_published') else None,
            summary=extracted_data['summary'],
            url=url
        )

def main():
    # Get OpenAI API key from environment variable
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("Please set the OPENAI_API_KEY environment variable")
    
    # Initialize scraper
    scraper = WebScraper(api_key)
    
    # Example usage
    url = input("Enter the URL to analyze: ")
    
    try:
        # Extract content from webpage
        content = scraper.extract_text_content(url)
        
        # Analyze content using OpenAI
        article_data = scraper.analyze_content(content, url)
        
        # Print results
        print("\nExtracted Data:")
        print(f"URL: {article_data.url}")
        print(f"Author: {article_data.author or 'Not found'}")
        print(f"Date Published: {article_data.date_published or 'Not found'}")
        print(f"Summary: {article_data.summary}")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()