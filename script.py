import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin
from collections import deque
import random
import http.server
import socketserver
import webbrowser
from urllib.parse import parse_qs, urlparse
import threading
import json
import ssl
import os
from OpenSSL import crypto
from dotenv import load_dotenv
from datetime import datetime
import signal
import atexit

load_dotenv()

class OAuthCallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            self.server.oauth_code = query_components['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Authorization successful! You can close this window.")
            threading.Thread(target=self.server.shutdown).start()
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authorization failed! Please try again.")

def create_self_signed_cert():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    cert_path = "localhost.crt"
    key_path = "localhost.key"
    
    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    return cert_path, key_path

class ArenaAPI:
    def __init__(self, client_id=None, client_secret=None, redirect_uri=None, access_token=None):
        self.client_id = client_id or os.getenv('ARENA_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('ARENA_CLIENT_SECRET')
        self.redirect_uri = redirect_uri or "https://localhost:8000/callback"
        self.access_token = access_token or os.getenv('ARENA_ACCESS_TOKEN')
        
        if not self.access_token and not (self.client_id and self.client_secret):
            raise ValueError("Either access_token or both client_id and client_secret must be provided")

    def get_authorization(self):
        if self.access_token:
            print("Using existing access token")
            return

        if not (os.path.exists("localhost.crt") and os.path.exists("localhost.key")):
            cert_path, key_path = create_self_signed_cert()
        else:
            cert_path, key_path = "localhost.crt", "localhost.key"

        httpd = socketserver.TCPServer(('localhost', 8000), OAuthCallbackHandler)
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            certfile=cert_path,
            keyfile=key_path,
            server_side=True
        )
        
        auth_url = f"https://dev.are.na/oauth/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"
        webbrowser.open(auth_url)
        
        httpd.serve_forever()
        auth_code = httpd.oauth_code
        
        token_url = "https://dev.are.na/oauth/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code'
        }
        response = requests.post(token_url, data=data)
        self.access_token = response.json()['access_token']
    
    def post_to_channel(self, channel_slug, content):
        if not self.access_token:
            raise Exception("Not authenticated. Call get_authorization() first.")
            
        url = f"https://api.are.na/v2/channels/{channel_slug}/blocks"  
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=content)
        return response.json()

class WebCrawler:
    def __init__(self, start_url, arena_api, channel_slug, max_visited=10000):
        self.start_url = start_url
        self.max_visited = max_visited
        self.arena_api = arena_api
        self.channel_slug = channel_slug
        
        self.state_file = 'crawler_state.json'
        if os.path.exists(self.state_file):
            self.load_state()
        else:
            self.url_queue = deque([start_url])
            self.visited_urls = set()
            self.known_domains = set()
            self.broken_images_count = 0
        
        atexit.register(self.save_state)
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

        self.recent_posts = []
        self.max_recent_posts = 10

    def save_state(self):
        state = {
            'url_queue': list(self.url_queue),
            'visited_urls': list(self.visited_urls),
            'known_domains': list(self.known_domains),
            'start_url': self.start_url,
            'broken_images_count': self.broken_images_count
        }
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f)
        print(f"\nCrawler state saved to {self.state_file}")
        print(f"Queue size: {len(self.url_queue)}")
        print(f"Visited URLs: {len(self.visited_urls)}")
        print(f"Known domains: {len(self.known_domains)}")
        print(f"Total broken images found: {self.broken_images_count}")

    def load_state(self):
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            self.url_queue = deque(state['url_queue'])
            self.visited_urls = set(state['visited_urls'])
            self.known_domains = set(state['known_domains'])
            self.broken_images_count = state.get('broken_images_count', 0)
            
            if state.get('start_url') != self.start_url:
                self.url_queue.append(self.start_url)
            
            print(f"\nResuming previous crawl:")
            print(f"Queue size: {len(self.url_queue)}")
            print(f"Visited URLs: {len(self.visited_urls)}")
            print(f"Known domains: {len(self.known_domains)}")
            print(f"Total broken images found so far: {self.broken_images_count}")
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error loading state: {e}")
            self.url_queue = deque([self.start_url])
            self.visited_urls = set()
            self.known_domains = set()
            self.broken_images_count = 0

    def handle_exit(self, signum, frame):
        print("\nSaving state before exit...")
        self.save_state()
        exit(0)

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
            if absolute_url.startswith(('http://', 'https://')):
                links.append(absolute_url)
        return links

    def check_and_reorder_queue(self, base_url):
        domain_count = sum(1 for url in self.recent_posts if urlparse(url).netloc == urlparse(base_url).netloc)
        
        if domain_count == self.max_recent_posts:
            print(f"\nToo many recent posts from {urlparse(base_url).netloc}, reordering queue...")
            same_domain = []
            different_domain = deque()
            
            while self.url_queue:
                url = self.url_queue.popleft()
                if urlparse(url).netloc == urlparse(base_url).netloc:
                    same_domain.append(url)
                else:
                    different_domain.append(url)
            
            self.url_queue = different_domain
            self.url_queue.extend(same_domain)
            print(f"Moved {len(same_domain)} URLs to back of queue")

    def crawl_page_for_broken_images(self, url):
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')

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
                            self.broken_images_count += 1
                            
                            self.recent_posts.append(url)
                            if len(self.recent_posts) > self.max_recent_posts:
                                self.recent_posts.pop(0)
                            
                            self.check_and_reorder_queue(url)
                            
                            current_time = datetime.now().strftime("%m/%d/%Y, %H:%M")
                            
                            img_filename = img_url.split('/')[-1]
                            
                            content = {
                                'content': f'*{alt_text}*\n\n{url}',
                                'title': img_filename
                            }
                            try:
                                self.arena_api.post_to_channel(self.channel_slug, content)
                                print(f"Posted to Are.na channel: {self.channel_slug}")
                                print(f"Total broken images found: {self.broken_images_count}")
                            except Exception as e:
                                print(f"Failed to post to Are.na: {e}")
                                self.broken_images_count -= 1

            return broken_images_alt_texts

        except requests.RequestException as e:
            print(f"Error crawling page {url}: {e}")
            return []

    def get_next_url(self):
        while self.url_queue:
            url = self.url_queue.popleft()
            if url not in self.visited_urls:
                return url
        
        if self.known_domains:
            return random.choice(list(self.known_domains))
        return self.start_url

    def continuous_crawl(self, interval=60):
        print("\nPress Ctrl+C to save and exit.")
        print(f"Total broken images found so far: {self.broken_images_count}")
        try:
            while True:
                current_url = self.get_next_url()
                print(f"\nCrawling page: {current_url}")
                
                broken_images = self.crawl_page_for_broken_images(current_url)
                self.visited_urls.add(current_url)
                self.known_domains.add(current_url)

                print(f"Queue size: {len(self.url_queue)}")
                print(f"Visited URLs: {len(self.visited_urls)}")
                print(f"Total broken images: {self.broken_images_count}")

                if broken_images:
                    print(f"Alt texts of broken images: {broken_images}")
                else:
                    print("No broken images found.")

                if len(self.visited_urls) >= self.max_visited:
                    print("Saving state before resetting visited URLs...")
                    self.save_state()
                    print("Resetting visited URLs list...")
                    self.visited_urls.clear()

                print(f"Waiting for {interval} seconds before the next crawl.")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nReceived keyboard interrupt...")
            self.save_state()
            print("Exiting gracefully.")
            exit(0)

if __name__ == "__main__":
    arena_api = ArenaAPI()
    
    print("Checking authorization...")
    arena_api.get_authorization()
    print("Authorization successful!")
    
    start_url = 'https://geocities.restorativland.org/Area51/Shadowlands/' 
    CHANNEL_SLUG = "broken-images-and-the-alt-text-that-remains"
    
    if not os.path.exists('.gitignore'):
        with open('.gitignore', 'w') as f:
            f.write('crawler_state.json\n')
    elif 'crawler_state.json' not in open('.gitignore').read():
        with open('.gitignore', 'a') as f:
            f.write('\ncrawler_state.json\n')
    
    crawler = WebCrawler(start_url, arena_api, CHANNEL_SLUG)
    crawler.continuous_crawl()
