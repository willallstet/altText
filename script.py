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
from PIL import Image
import io

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

        self.last_published_alt_text = None
        self.recent_posts = []
        self.max_recent_posts = 10

        self.broken_images_file = 'broken_images.json'
        self.broken_images_data = self.load_broken_images()

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
        print(f"State saved. Total broken images: {self.broken_images_count}")

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
            
            print(f"Resuming crawl - Queue: {len(self.url_queue)}, Visited: {len(self.visited_urls)}, Total found: {self.broken_images_count}")
            
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
            # For relative paths, try both the base URL and the full directory path
            if not url.startswith(('http://', 'https://')):
                # Get the directory of the current page by removing everything after the last slash
                base_dir = '/'.join(self.current_url.split('/')[:-1]) + '/'
                
                # Try the full directory path first
                img_url = urljoin(base_dir, url)
                
                try:
                    response = requests.get(img_url, timeout=10, headers={
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'image/*',
                        'Referer': self.current_url
                    })
                    if self._validate_image_response(response, img_url):
                        return False
                except requests.RequestException:
                    pass
                
                # If that fails, try the base URL
                img_url = urljoin(self.current_url, url)
            else:
                img_url = url
            
            response = requests.get(img_url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'image/*',
                'Referer': self.current_url
            })
            
            if self._validate_image_response(response, img_url):
                return False
            else:
                return True
        
        except requests.RequestException:
            return True

    def _validate_image_response(self, response, img_url):
        """
        Comprehensive image validation using multiple checks:
        1. HTTP status code
        2. Content-Type header
        3. Content-Length (file size)
        4. PIL image verification
        5. Image format detection
        """
        try:
            # Check HTTP status
            if response.status_code != 200:
                return False
            
            # Check Content-Type header
            content_type = response.headers.get('Content-Type', '').lower()
            if not content_type.startswith('image/'):
                # Sometimes images are served with generic content types
                if 'text/html' in content_type:
                    return False
                if 'application/json' in content_type:
                    return False
                # Allow some generic types but be cautious
                if not content_type.startswith(('application/octet-stream', 'binary/')):
                    return False
            
            # Check Content-Length (file size)
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    size = int(content_length)
                    if size < 50:  # Suspiciously small files are likely error pages
                        return False
                    if size > 10 * 1024 * 1024:  # Skip very large files (>10MB)
                        return False
                except ValueError:
                    pass
            
            # Get image content
            image_data = response.content
            
            # Check if content is suspiciously small
            if len(image_data) < 50:
                return False
            
            # Check for HTML content (common for broken image URLs)
            if b'<html' in image_data.lower()[:200] or b'<!doctype' in image_data.lower()[:200]:
                return False
            
            # Check for JSON content
            if image_data.strip().startswith(b'{') or image_data.strip().startswith(b'['):
                return False
            
            # Use PIL to verify image integrity and detect format
            try:
                with Image.open(io.BytesIO(image_data)) as img:
                    img_format = img.format
                    img.verify()  # This will raise an exception if the image is corrupted
                    return True
            except Exception:
                # Try to detect HEIC format manually (not supported by PIL)
                if len(image_data) >= 12:
                    heic_signatures = [b'ftypheic', b'ftypheix', b'ftyphevc', b'ftyphevx']
                    if image_data[4:12] in heic_signatures:
                        return True
                
                # Try to detect other formats by file signature
                if self._detect_image_format_by_signature(image_data):
                    return True
                
                return False
                
        except Exception:
            return False

    def _detect_image_format_by_signature(self, image_data):
        """
        Detect image format by file signature (magic numbers)
        """
        if len(image_data) < 4:
            return False
        
        # Common image format signatures
        signatures = {
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF87a': 'GIF',
            b'GIF89a': 'GIF',
            b'BM': 'BMP',
            b'II*\x00': 'TIFF',
            b'MM\x00*': 'TIFF',
            b'\x00\x00\x01\x00': 'ICO',
            b'\x00\x00\x02\x00': 'CUR',
        }
        
        for signature, format_name in signatures.items():
            if image_data.startswith(signature):
                return True
        
        # Special check for WebP (needs more bytes to verify)
        if len(image_data) >= 12 and image_data.startswith(b'RIFF') and image_data[8:12] == b'WEBP':
            return True
        
        return False

    def extract_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
            if absolute_url.startswith(('http://', 'https://')):
                links.append(absolute_url)
        return links

    def check_and_reorder_queue(self, base_url):
        base_domain = '/'.join(base_url.split('/')[:3])
        domain_count = sum(1 for url in self.recent_posts if '/'.join(url.split('/')[:3]) == base_domain)
        
        if domain_count == self.max_recent_posts:
            same_domain = []
            different_domain = deque()
            
            while self.url_queue:
                url = self.url_queue.popleft()
                if '/'.join(url.split('/')[:3]) == base_domain:
                    same_domain.append(url)
                else:
                    different_domain.append(url)
            
            self.url_queue = different_domain
            self.url_queue.extend(same_domain)

    def load_broken_images(self):
        try:
            if os.path.exists(self.broken_images_file):
                with open(self.broken_images_file, 'r') as f:
                    return json.load(f)
            return []
        except json.JSONDecodeError:
            return []

    def save_broken_image(self, img_url, alt_text, page_url):
        broken_image = {
            'img_url': img_url,
            'alt_text': alt_text,
            'page_url': page_url,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M"),
            'arena_post_success': False
        }
        self.broken_images_data.append(broken_image)
        
        try:
            with open(self.broken_images_file, 'w') as f:
                json.dump(self.broken_images_data, f, indent=2)
        except Exception:
            pass

    def is_duplicate_broken_image(self, img_url, alt_text, page_url):
        for entry in self.broken_images_data:
            if (entry['img_url'] == img_url and 
                entry['alt_text'] == alt_text and 
                entry['page_url'] == page_url):
                return True
        return False

    def crawl_page_for_broken_images(self, url):
        try:
            # Set the current URL at the start of crawling
            self.current_url = url
            
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract and sort links
            links = self.extract_links(soup, url)
            current_domain = '/'.join(url.split('/')[:3])
            
            # Separate links by domain
            external_links = [link for link in links if '/'.join(link.split('/')[:3]) != current_domain]
            internal_links = [link for link in links if '/'.join(link.split('/')[:3]) == current_domain]
            random.shuffle(external_links)
            random.shuffle(internal_links)
            
            # Add up to 10 links, prioritizing external ones
            links_added = 0
            
            # Try external links first (up to 6)
            links_added += self._add_links_to_queue(external_links, "external", links_added, 6)
            
            # Add internal links if we haven't reached 10 yet
            links_added += self._add_links_to_queue(internal_links, "internal", links_added, 10 - links_added)

            img_tags = soup.find_all('img')
            broken_images_alt_texts = []

            for img in img_tags:
                img_url = img.get('src')
                if not img_url:
                    continue
                
                img_url = urljoin(url, img_url)
                if not img_url.startswith(('http://', 'https://')):
                    continue
                
                if self.is_broken_image(img_url):
                    alt_text = img.get('alt', '')

                    # Only process alt text with more than one word
                    if alt_text and len(alt_text.split()) > 1:
                        # Check if this exact combination was already saved
                        if self.is_duplicate_broken_image(img_url, alt_text, url):
                            continue
                        
                        # Save the broken image data and continue with posting
                        self.save_broken_image(img_url, alt_text, url)
                        
                        if alt_text == self.last_published_alt_text:
                            continue
                        
                        broken_images_alt_texts.append(alt_text)
                        print(f"Broken image found: {alt_text}")
                        self.broken_images_count += 1
                        
                        self.recent_posts.append(url)
                        if len(self.recent_posts) > self.max_recent_posts:
                            self.recent_posts.pop(0)
                        self.check_and_reorder_queue(url)
                        
                        img_filename = img_url.split('/')[-1]
                        
                        content = {
                            'content': f'#*{alt_text}*\n\n{url}',
                            'title': img_filename
                        }

                        # Add retry logic for Are.na posting
                        max_retries = 3
                        retry_delay = 5  # Start with 5 seconds
                        for attempt in range(max_retries):
                            try:
                                self.arena_api.post_to_channel(self.channel_slug, content)
                                print(f"Posted to Are.na: {alt_text}")
                                self.last_published_alt_text = alt_text
                                # Update the last entry's arena_post_success status
                                if self.broken_images_data:
                                    self.broken_images_data[-1]['arena_post_success'] = True
                                    with open(self.broken_images_file, 'w') as f:
                                        json.dump(self.broken_images_data, f, indent=2)
                                break
                            except Exception as e:
                                if attempt < max_retries - 1:  # Don't sleep on last attempt
                                    time.sleep(retry_delay)
                                    retry_delay *= 2  # Exponential backoff
                                else:
                                    print(f"Failed to post to Are.na: {e}")
                                    self.broken_images_count -= 1

            return broken_images_alt_texts

        except requests.RequestException as e:
            print(f"Error crawling page {url}: {e}")
            return []

    def _add_links_to_queue(self, links, link_type, current_count, max_to_add):
        """Helper method to add links to the queue with validation"""
        added = 0
        for link in links:
            if added >= max_to_add:
                break
            if link not in self.visited_urls and link not in self.url_queue:
                try:
                    response = requests.get(link, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                    if response.status_code == 200:
                        self.url_queue.append(link)
                        added += 1
                except requests.RequestException:
                    continue
        return added

    def get_next_url(self):
        while self.url_queue:
            url = self.url_queue.popleft()
            if url not in self.visited_urls:
                return url
        
        if self.known_domains:
            return random.choice(list(self.known_domains))
        return self.start_url

    def continuous_crawl(self, interval=20):
        print("\nPress Ctrl+C to save and exit.")
        print(f"Total broken images found so far: {self.broken_images_count}")
        scrape_count = 0
        try:
            while True:
                current_url = self.get_next_url()
                print(f"\nCrawling: {current_url}")
                
                broken_images = self.crawl_page_for_broken_images(current_url)
                self.visited_urls.add(current_url)
                self.known_domains.add(current_url)
                
                scrape_count += 1
                if scrape_count >= 10:
                    queue_list = list(self.url_queue)
                    random.shuffle(queue_list)
                    self.url_queue = deque(queue_list)
                    scrape_count = 0

                print(f"Queue: {len(self.url_queue)}, Visited: {len(self.visited_urls)}, Total found: {self.broken_images_count}")
                
                if len(self.visited_urls) >= self.max_visited:
                    print("Resetting visited URLs list...")
                    self.save_state()
                    self.visited_urls.clear()

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
    
    start_url = 'https://www.forumancientcoins.com/dougsmith/photo.html?srsltid=AfmBOooDh8XWrk5e34oyUy58lDdNCN18NxBprVDZXOlmSqZuAZXiV0TZ' 
    CHANNEL_SLUG = "broken-images-and-the-alt-text-that-remains"
    
    # Ensure crawler_state.json is in .gitignore
    gitignore_path = '.gitignore'
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, 'w') as f:
            f.write('crawler_state.json\n')
    else:
        with open(gitignore_path, 'r') as f:
            content = f.read()
        if 'crawler_state.json' not in content:
            with open(gitignore_path, 'a') as f:
                f.write('\ncrawler_state.json\n')
    
    crawler = WebCrawler(start_url, arena_api, CHANNEL_SLUG)
    crawler.continuous_crawl()
