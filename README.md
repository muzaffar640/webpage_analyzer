# CVE Scraper and Web Analyzer

This project contains two main components:

## CVE Scraper

The CVE Scraper is a Python script that fetches and processes CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) and EPSS (Exploit Prediction Scoring System) APIs.

### Usage

To use the CVE Scraper, run the `cve_scraper.py` script and enter a CVE ID when prompted. For example:

The script will fetch the CVE data from the NVD and EPSS APIs, process it, and print the results as JSON.

### Features

- Fetches CVE data from the NVD and EPSS APIs
- Processes the data and creates a `CVEData` model instance
- Includes CVSS metrics, weaknesses, references, and EPSS scores
- Handles various data formats and edge cases

## Web Analyzer

The Web Analyzer is a Python script that scrapes the content of a given webpage and uses OpenAI's GPT-4 model to extract CVE data from the text.

### Usage

To use the Web Analyzer, run the `run.py` script and enter a URL when prompted. For example:

The script will scrape the webpage, extract the text content, and use OpenAI's GPT-4 model to analyze the text and extract any CVE data. The extracted data will be printed as JSON.

### Features

- Scrapes webpages using Playwright
- Extracts text content from the webpage
- Uses OpenAI's GPT-4 model to analyze the text and extract CVE data
- Handles various data formats and edge cases
- Requires an OpenAI API key (set as an environment variable)

Both scripts are designed to be run from the command line and provide a convenient way to fetch and analyze CVE data from different sources.
