import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin
from collections import deque
import random
import http.server
import socketserver
import webbrowser
from urllib.parse import parse_qs, urlparse, urlunparse
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
import sys

# Platform-specific sound imports
try:
    import winsound  # Windows
except ImportError:
    winsound = None

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
        
        # Allow multiple redirect URI options - users can set ARENA_REDIRECT_URI env var to test different ones
        if redirect_uri:
            self.redirect_uri = redirect_uri
        elif os.getenv('ARENA_REDIRECT_URI'):
            self.redirect_uri = os.getenv('ARENA_REDIRECT_URI')
        else:
            self.redirect_uri = "https://localhost:8000/callback"
            
        self.access_token = access_token or os.getenv('ARENA_ACCESS_TOKEN')
        
        # Create a session to maintain cookies and connection pooling
        self.session = requests.Session()
        
        if not self.access_token and not (self.client_id and self.client_secret):
            raise ValueError("Either access_token or both client_id and client_secret must be provided")

    def get_authorization(self):
        if self.access_token:
            print("Using existing access token")
            # Test the token to make sure it's valid
            if self.test_access_token():
                print("Access token is valid")
                return
            else:
                print("Access token is invalid, getting new authorization...")
                self.access_token = None

        print(f"\n{'='*60}")
        print("ARE.NA OAUTH SETUP INSTRUCTIONS")
        print(f"{'='*60}")
        print(f"🔗 Your redirect URI should be set to: {self.redirect_uri}")
        print(f"📝 Go to your Are.na app settings and configure this EXACTLY")
        print(f"🌐 If this doesn't work, try these alternatives:")
        print(f"   - http://localhost:8000/callback (HTTP instead of HTTPS)")
        print(f"   - http://127.0.0.1:8000/callback (IP instead of localhost)")
        print(f"   - https://127.0.0.1:8000/callback (HTTPS + IP)")
        print(f"💡 To test different URIs, set: ARENA_REDIRECT_URI=http://localhost:8000/callback")
        print(f"{'='*60}\n")

        # Determine if we need SSL based on redirect URI
        use_ssl = self.redirect_uri.startswith('https://')
        
        if use_ssl:
            if not (os.path.exists("localhost.crt") and os.path.exists("localhost.key")):
                print("🔑 Creating self-signed SSL certificate...")
                cert_path, key_path = create_self_signed_cert()
                print(f"✅ Certificate created: {cert_path}, {key_path}")
            else:
                cert_path, key_path = "localhost.crt", "localhost.key"
                print(f"🔑 Using existing SSL certificate: {cert_path}, {key_path}")

        try:
            httpd = socketserver.TCPServer(('localhost', 8000), OAuthCallbackHandler)
            
            if use_ssl:
                try:
                    # Use modern SSL context instead of deprecated ssl.wrap_socket
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert_path, key_path)
                    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
                    print(f"🔒 Starting HTTPS server on port 8000...")
                except Exception as ssl_error:
                    print(f"❌ SSL setup failed: {ssl_error}")
                    print("💡 Falling back to HTTP server...")
                    # Update redirect URI to HTTP and recreate server
                    self.redirect_uri = self.redirect_uri.replace('https://', 'http://')
                    httpd = socketserver.TCPServer(('localhost', 8000), OAuthCallbackHandler)
                    use_ssl = False
            
            if not use_ssl:
                print(f"🌐 Starting HTTP server on port 8000...")
            
            print(f"✅ Server started successfully on {self.redirect_uri}")
            
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            print("💡 Possible solutions:")
            print("   - Port 8000 might be in use - try closing other applications")
            print("   - Try running as administrator")
            print("   - Check if antivirus/firewall is blocking the connection")
            raise Exception(f"Could not start callback server: {e}")
        
        auth_url = f"https://dev.are.na/oauth/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"
        print(f"🚀 Opening browser for authorization...")
        print(f"🔗 Auth URL: {auth_url}")
        print(f"🔗 Redirect URI: {self.redirect_uri}")
        webbrowser.open(auth_url)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n❌ Authorization cancelled by user")
            httpd.shutdown()
            return
        except Exception as e:
            print(f"❌ Server error: {e}")
            httpd.shutdown()
            raise
            
        auth_code = httpd.oauth_code
        
        token_url = "https://dev.are.na/oauth/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        print(f"🔄 Exchanging authorization code for access token...")
        print(f"📡 Token URL: {token_url}")
        print(f"📝 Request data: {data}")
        
        # Add browser-like headers to bypass Cloudflare blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://dev.are.na',
            'Referer': 'https://dev.are.na/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        try:
            response = self.session.post(token_url, data=data, headers=headers)
            print(f"📊 Response status: {response.status_code}")
            print(f"📄 Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                try:
                    token_data = response.json()
                    print(f"✅ Token response: {token_data}")
                    
                    if 'access_token' in token_data:
                        self.access_token = token_data['access_token']
                        print(f"🎉 Access token obtained successfully!")
                    else:
                        print(f"❌ No access_token in response: {token_data}")
                        raise Exception("No access_token in response")
                        
                except ValueError as e:
                    print(f"❌ Invalid JSON response: {e}")
                    print(f"🔍 Raw response: {response.text}")
                    raise Exception(f"Invalid JSON response from Are.na token endpoint: {e}")
            else:
                print(f"❌ Token exchange failed with status {response.status_code}")
                print(f"🔍 Error response: {response.text}")
                raise Exception(f"Token exchange failed: {response.status_code} - {response.text}")
                
        except requests.RequestException as e:
            print(f"❌ Request failed: {e}")
            raise Exception(f"Failed to exchange authorization code: {e}")
    
    def test_access_token(self):
        """Test if the current access token is valid by making a simple API call"""
        if not self.access_token:
            return False
        
        try:
            # Test the token with a simple API call (get user info)
            url = "https://api.are.na/v2/me"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
                'Referer': 'https://are.na/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            }
            response = self.session.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Error testing access token: {e}")
            return False
    
    def test_channel_access(self, channel_slug):
        """Test if the channel exists and is accessible"""
        if not self.access_token:
            return False
            
        try:
            url = f"https://api.are.na/v2/channels/{channel_slug}"
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
                'Referer': 'https://are.na/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            }
            
            print(f"🔍 Testing channel access: {url}")
            print(f"🔑 Using access token: {self.access_token[:10]}...")
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            print(f"📊 Response status: {response.status_code}")
            print(f"📄 Response encoding: {response.encoding}")
            print(f"🔍 Response content preview: {response.text[:200]}...")
            
            if response.status_code == 200:
                try:
                    channel_data = response.json()
                    print(f"✅ Channel found: '{channel_data.get('title', 'Unknown')}' (ID: {channel_data.get('id', 'Unknown')})")
                    print(f"📊 Channel status: {channel_data.get('status', 'Unknown')}")
                    print(f"👥 Channel collaboration: {channel_data.get('collaboration', 'Unknown')}")
                    return True
                except ValueError as e:
                    print(f"❌ JSON parsing failed: {e}")
                    print(f"🔍 Raw response: {response.text}")
                    return False
            else:
                print(f"❌ Channel access failed: Status {response.status_code}")
                print(f"🔍 Error response: {response.text}")
                if response.status_code == 404:
                    print("Channel not found. Please check the channel slug.")
                elif response.status_code == 403:
                    print("Access denied. You might not have permission to access this channel.")
                return False
        except Exception as e:
            print(f"❌ Error testing channel access: {e}")
            return False
    
    def post_to_channel(self, channel_slug, content):
        if not self.access_token:
            raise Exception("Not authenticated. Call get_authorization() first.")
            
        url = f"https://api.are.na/v2/channels/{channel_slug}/blocks"  
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://are.na',
            'Referer': 'https://are.na/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        print(f"📡 Posting to Are.na: {url}")
        print(f"📝 Content: {content}")
        
        response = self.session.post(url, headers=headers, json=content)
        
        print(f"📊 Response status: {response.status_code}")
        print(f"📄 Response encoding: {response.encoding}")
        print(f"🔍 Response content preview: {response.text[:200]}...")
        
        # Check if the request was successful
        if response.status_code == 200 or response.status_code == 201:
            try:
                result = response.json()
                print(f"✅ Block created successfully: {result.get('id', 'Unknown ID')}")
                return result
            except ValueError as e:
                print(f"❌ Invalid JSON response: {e}")
                print(f"🔍 Raw response: {response.text}")
                raise Exception(f"Invalid JSON response from Are.na: {e}")
        else:
            # Handle different error status codes
            print(f"❌ API request failed with status {response.status_code}")
            print(f"🔍 Error response: {response.text}")
            
            error_msg = f"Are.na API error (status {response.status_code})"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg += f": {error_data['error']}"
                elif 'message' in error_data:
                    error_msg += f": {error_data['message']}"
                else:
                    error_msg += f": {error_data}"
            except ValueError:
                # Response isn't JSON, use the raw text
                error_msg += f": {response.text[:200]}"
            
            raise Exception(error_msg)

class WebCrawler:
    def __init__(self, start_url, arena_api, channel_slug, max_visited=10000, sound_notifications=True):
        self.start_url = start_url
        self.max_visited = max_visited
        self.arena_api = arena_api
        self.channel_slug = channel_slug
        self.sound_notifications = sound_notifications
        
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
            # Resolve relative URLs against current page
            if not url.startswith(('http://', 'https://')):
                base_dir = self._get_base_directory_url(self.current_url)
                primary_url = urljoin(base_dir, url)
                fallback_url = urljoin(self.current_url, url)
            else:
                primary_url = url
                fallback_url = url

            # First probe: with Referer
            if self._probe_image_valid(primary_url, referer=self.current_url):
                return False

            # If relative and first probe failed, try fallback resolved URL
            if fallback_url != primary_url and self._probe_image_valid(fallback_url, referer=self.current_url):
                return False

            # Second probe: without Referer (some CDNs block hotlinking)
            if self._probe_image_valid(primary_url, referer=None, user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15'):
                return False

            return True

        except requests.RequestException:
            return True

    def _probe_image_valid(self, img_url, referer=None, user_agent=None):
        """Lightweight probe to determine if an image URL is valid without downloading the whole body."""
        headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'image/*',
            'Accept-Encoding': 'identity',  # avoid compressed HTML error pages
        }
        if referer:
            headers['Referer'] = referer

        try:
            with requests.get(img_url, headers=headers, timeout=10, stream=True, allow_redirects=True) as resp:
                # HTTP status must be OK
                if resp.status_code < 200 or resp.status_code >= 300:
                    return False

                content_type = (resp.headers.get('Content-Type') or '').lower()
                content_length = resp.headers.get('Content-Length')

                # Read a small chunk to sniff content (do not download full file)
                chunk = b''
                for data in resp.iter_content(chunk_size=4096):
                    chunk = data or b''
                    break

                # Empty body → likely invalid
                if not chunk:
                    return False

                # If we inadvertently received HTML/JSON, it's not an image
                head_lower = chunk[:256].lower()
                if b'<html' in head_lower or b'<!doctype' in head_lower or head_lower.strip().startswith((b'{', b'[')):
                    return False

                # If server claims an image type and gave us bytes, consider valid
                if content_type.startswith('image/'):
                    return True

                # Otherwise, try magic-byte sniffing for common image formats
                if self._detect_image_format_by_signature(chunk):
                    return True

                # As a final heuristic: if content-length header exists and is sensible (> 50 bytes), accept
                try:
                    if content_length is not None and int(content_length) > 50:
                        return True
                except Exception:
                    pass

                return False
        except requests.RequestException:
            return False

    def _get_base_directory_url(self, page_url):
        """Return the proper base directory URL for resolving relative resources."""
        p = urlparse(page_url)
        path = p.path or '/'
        if path.endswith('/'):
            dir_path = path
        else:
            last_segment = path.rsplit('/', 1)[-1]
            if '.' in last_segment:
                # Looks like a file: drop filename
                dir_path = path.rsplit('/', 1)[0] + '/'
                if dir_path == '//':
                    dir_path = '/'
            else:
                # Looks like a directory without trailing '/'
                dir_path = path + '/'
        return urlunparse((p.scheme, p.netloc, dir_path, '', '', ''))

    def _validate_image_response(self, response, img_url):
        """
        Comprehensive image validation using multiple checks:
        1. HTTP status code
        2. Content-Type header
        3. Content-Length (file size)
        4. PIL image verification (for raster images)
        5. SVG validation (for vector graphics)
        6. Image format detection
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
                # Allow SVG files which might be served as text/xml or application/xml
                if 'xml' in content_type and img_url.lower().endswith('.svg'):
                    pass  # Continue with SVG validation
                elif not content_type.startswith(('application/octet-stream', 'binary/')):
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
            
            # Special handling for SVG files
            if img_url.lower().endswith('.svg') or 'image/svg' in content_type:
                return self._validate_svg_content(image_data)
            
            # Use PIL to verify raster image integrity and detect format
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

    def _validate_svg_content(self, svg_data):
        """
        Validate SVG content by checking for SVG-specific elements
        """
        try:
            # Convert to string for text-based validation
            svg_text = svg_data.decode('utf-8', errors='ignore').lower()
            
            # Check for SVG signature and basic structure
            if '<svg' in svg_text and ('xmlns' in svg_text or 'viewbox' in svg_text):
                # Make sure it's not an error page disguised as SVG
                if 'error' in svg_text or 'not found' in svg_text or '404' in svg_text:
                    return False
                return True
            
            # Also check for XML declaration with SVG
            if '<?xml' in svg_text and '<svg' in svg_text:
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
        
        # Special check for SVG files (XML-based)
        if len(image_data) >= 5:
            # Check for XML declaration or direct SVG tag
            text_start = image_data[:100].decode('utf-8', errors='ignore').lower()
            if '<?xml' in text_start or '<svg' in text_start:
                return True
        
        return False

	def _is_shortener_url(self, url):
		"""Return True if the URL belongs to a known shortener that should be skipped."""
		try:
			netloc = urlparse(url).netloc.lower()
			blocked_domains = ('bit.ly', 'tinyurl.com')
			for domain in blocked_domains:
				if netloc == domain or netloc.endswith('.' + domain):
					return True
			return False
		except Exception:
			return False

    def extract_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
			if absolute_url.startswith(('http://', 'https://')) and not self._is_shortener_url(absolute_url):
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
                
                # Skip certain file types entirely
                if img_url.lower().endswith(('.svg', '.avif')):
                    continue
                
                # Skip tiny tracking pixels and spacer images
                img_filename = img_url.split('/')[-1].lower()
                skip_patterns = ['1px.gif', 'blank.gif', 'spacer.gif', 'pixel.gif', 'clear.gif', 
                               'transparent.gif', 'empty.gif', 'invisible.gif', '1x1.gif', 
                               'dot.gif', 'space.gif', 'tracker.gif', '0x0.gif']
                if any(pattern in img_filename for pattern in skip_patterns):
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
                        
                        # Play notification sound for broken image
                        self.play_notification_sound()
                        
                        print(f"🚨 BROKEN IMAGE FOUND: {alt_text} 🚨")
                        
                        self.broken_images_count += 1
                        
                        self.recent_posts.append(url)
                        if len(self.recent_posts) > self.max_recent_posts:
                            self.recent_posts.pop(0)
                        self.check_and_reorder_queue(url)
                        
                        img_filename = img_url.split('/')[-1]
                        
                        content = {
                            'content': f'{alt_text}',
                            'title': alt_text,
                            'description': f'page url: *{url}*\nimage url: *{img_url}*',
                        }

                        # Add retry logic for Are.na posting
                        max_retries = 3
                        retry_delay = 5  # Start with 5 seconds
                        for attempt in range(max_retries):
                            try:
                                print(f"Attempting to post to Are.na (attempt {attempt + 1}/{max_retries})")
                                print(f"Channel: {self.channel_slug}")
                                print(f"Content: {content}")
                                
                                # Add a small delay to avoid rate limiting
                                if attempt > 0:
                                    time.sleep(2)  # Wait 2 seconds between retries
                                
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
                                print(f"Are.na posting failed on attempt {attempt + 1}: {e}")
                                if attempt < max_retries - 1:  # Don't sleep on last attempt
                                    print(f"Retrying in {retry_delay} seconds...")
                                    time.sleep(retry_delay)
                                    retry_delay *= 2  # Exponential backoff
                                else:
                                    print(f"Failed to post to Are.na after {max_retries} attempts: {e}")
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
				# Skip known URL shorteners
				if self._is_shortener_url(link):
					continue
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
        if self.sound_notifications:
            print("🔊 Sound notifications enabled - you'll hear a beep when broken images are found!")
        else:
            print("🔇 Sound notifications disabled")
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

    def test_image_url(self, url):
        """Test a specific image URL to see if it's correctly identified as broken or valid"""
        print(f"\n=== Testing URL: {url} ===")
        
        # Set current_url for context
        self.current_url = "http://www.missouribotanicalgarden.org/plant-science/plant-science/resources/raven-library.aspx"
        
        try:
            # Test the URL directly
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'image/*',
                'Referer': self.current_url
            })
            
            print(f"HTTP Status: {response.status_code}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
            print(f"Content-Length: {response.headers.get('Content-Length', 'Unknown')}")
            
            if response.status_code == 200:
                is_broken = self.is_broken_image(url)
                print(f"Is broken: {is_broken}")
                
                # Show some content for debugging
                content_preview = response.content[:200]
                try:
                    text_preview = content_preview.decode('utf-8', errors='ignore')
                    print(f"Content preview: {text_preview[:100]}...")
                except:
                    print(f"Content preview (binary): {content_preview}")
                
                return not is_broken
            else:
                print(f"HTTP request failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error testing URL: {e}")
            return False

    def play_notification_sound(self):
        """Play a notification sound when a broken image is found"""
        if not self.sound_notifications:
            return
            
        try:
            if winsound:
                # Windows - play a pleasant notification sound
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            else:
                # Other platforms - try system bell
                print("\a", end="", flush=True)  # ASCII bell character
        except Exception as e:
            # Fallback - just print a visual indicator
            print("🔔 BROKEN IMAGE FOUND! 🔔")

if __name__ == "__main__":
    arena_api = ArenaAPI()
    
    print("Checking authorization...")
    arena_api.get_authorization()
    print("Authorization successful!")
    
    start_url = 'https://www.forumancientcoins.com/dougsmith/photo.html?srsltid=AfmBOooDh8XWrk5e34oyUy58lDdNCN18NxBprVDZXOlmSqZuAZXiV0TZ' 
    CHANNEL_SLUG = "broken-images-and-the-alt-text-that-remains"
    
    print(f"Testing channel access for '{CHANNEL_SLUG}'...")
    if not arena_api.test_channel_access(CHANNEL_SLUG):
        print("Channel access failed. Please check your permissions and channel slug.")
        exit(1)
    print("Channel access successful!")
    
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
    
    # Create crawler with sound notifications enabled
    # To disable sound notifications, change sound_notifications=False
    crawler = WebCrawler(start_url, arena_api, CHANNEL_SLUG, sound_notifications=True)
    
    # Test the specific URLs that were incorrectly identified as broken
    print("\n" + "="*50)
    print("TESTING SVG URLS FROM BROKEN IMAGES")
    print("="*50)
    
    test_urls = [
        "http://www.missouribotanicalgarden.org/Portals/0/2022redesignassets/bh-logo-horiz.svg",
        "http://www.missouribotanicalgarden.org/Portals/0/2022redesignassets/snr-logo-horiz.svg", 
        "http://www.missouribotanicalgarden.org/Portals/0/2022redesignassets/mobot-logo.svg",
        "http://www.missouribotanicalgarden.org/Portals/0/2022redesignassets/bh-logo.svg",
        "http://www.missouribotanicalgarden.org/Portals/0/2022redesignassets/snr-logo.svg"
    ]
    
    valid_count = 0
    for url in test_urls:
        if crawler.test_image_url(url):
            valid_count += 1
    
    print(f"\nTest Results: {valid_count}/{len(test_urls)} URLs are now correctly identified as valid")
    print("="*50)
    
    # Ask user if they want to continue with crawling
    user_input = input("\nDo you want to continue with crawling? (y/n): ")
    if user_input.lower() != 'y':
        print("Exiting...")
        exit(0)
    
    crawler.continuous_crawl()
