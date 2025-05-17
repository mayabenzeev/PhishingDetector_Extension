import pandas as pd
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import random
import os

# Config
TRANCOPATH = os.path.join(os.getcwd(), "datasets/benign.csv")  # Path to Tranco file
MAX_URLS = 5000
MAX_LINKS_PER_DOMAIN = 5
DELAY = 0.3
TIMEOUT = 5

# Helper to strip scheme and keep clean domain
def strip_scheme(domain):
    parsed = urlparse(domain)
    return parsed.netloc or parsed.path  # path fallback for bare domains

# Load Tranco list and select ranks 1001–10,000
tranco_df = pd.read_csv(TRANCOPATH, header=None)
top_sites = tranco_df[1].dropna().iloc[10000:20000].apply(strip_scheme).tolist()

# Extract internal links from domain
def extract_internal_urls(domain, max_links=10):
    urls = set()
    try:
        try:
            response = requests.get("https://" + domain, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            response = requests.get("http://" + domain, timeout=TIMEOUT)

        if response.status_code != 200:
            return []

        base_url = response.url
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all("a", href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            if domain in urlparse(full_url).netloc and full_url.startswith("http"):
                urls.add(full_url)
            if len(urls) >= max_links:
                break
    except Exception as e:
        print(f"[!] Error fetching {domain}: {e}")
    return list(urls)

# Crawl loop
benign_urls = []
for domain in top_sites:
    print(f"[+] Crawling {domain}...")
    links = extract_internal_urls(domain, max_links=MAX_LINKS_PER_DOMAIN)
    benign_urls.extend(links)
    print(f"    → {len(links)} links found. Total: {len(benign_urls)}")
    if len(benign_urls) >= MAX_URLS:
        break
    time.sleep(DELAY)

# Save result
benign_df = pd.DataFrame(benign_urls[:MAX_URLS], columns=["url"])
output_path = "benign_urls_5000.csv"
benign_df.to_csv(output_path, index=False)
print(f"✅ Saved {output_path} with {len(benign_df)} entries.")
