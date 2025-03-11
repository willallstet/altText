import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin
from collections import deque
import random

class WebCrawler:
    def __init__(self, start_url, max_visited=1000):
        self.start_url = start_url
        self.max_visited = max_visited
        self.url_queue = deque([start_url])
        self.visited_urls = set()
        self.known_domains = set()

    def is_broken_image(self, url):
        try:
            response = requests.get(url, timeout=5)
            return response.status_code != 200
        except requests.RequestException:
            return True

    def extract_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
            # Only add URLs that start with http/https
            if absolute_url.startswith(('http://', 'https://')):
                links.append(absolute_url)
        return links

    def crawl_page_for_broken_images(self, url):
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract new links and add them to the queue
            new_links = self.extract_links(soup, url)
            for link in new_links:
                if link not in self.visited_urls:
                    self.url_queue.append(link)

            img_tags = soup.find_all('img')
            broken_images_alt_texts = []

            for img in img_tags:
                img_url = img.get('src')
                alt_text = img.get('alt', '')

                if img_url:
                    img_url = urljoin(url, img_url)
                    if self.is_broken_image(img_url):
                        print(f"Broken image found: {img_url}")
                        if alt_text:
                            broken_images_alt_texts.append(alt_text)
                            print(f"Alt text saved: {alt_text}")

            return broken_images_alt_texts

        except requests.RequestException as e:
            print(f"Error crawling page {url}: {e}")
            return []

    def get_next_url(self):
        while self.url_queue:
            url = self.url_queue.popleft()
            if url not in self.visited_urls:
                return url
        
        # If queue is empty, restart from a known domain or the start URL
        if self.known_domains:
            return random.choice(list(self.known_domains))
        return self.start_url

    def continuous_crawl(self, interval=60):
        while True:
            current_url = self.get_next_url()
            print(f"\nCrawling page: {current_url}")
            
            broken_images = self.crawl_page_for_broken_images(current_url)
            self.visited_urls.add(current_url)
            self.known_domains.add(current_url)

            print(f"Queue size: {len(self.url_queue)}")
            print(f"Visited URLs: {len(self.visited_urls)}")

            if broken_images:
                print(f"Alt texts of broken images: {broken_images}")
            else:
                print("No broken images found.")

            # Reset visited URLs if we've reached the maximum
            if len(self.visited_urls) >= self.max_visited:
                print("Resetting visited URLs list...")
                self.visited_urls.clear()

            print(f"Waiting for {interval} seconds before the next crawl.")
            time.sleep(interval)

# Starting point of the script
if __name__ == "__main__":
    start_url = 'https://example.com'  # Replace with your preferred starting point
    crawler = WebCrawler(start_url)
    crawler.continuous_crawl()
