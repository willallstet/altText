import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin
from collections import deque
import random
import http.server
import socketserver
import webbrowser
from urllib.parse import parse_qs, urlparse, urlunparse, quote
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
from playwright.sync_api import sync_playwright
from requests.exceptions import ConnectionError, Timeout, RequestException

# Try to import Playwright TimeoutError, fallback to checking by name if not available
try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
except ImportError:
    # If direct import fails, we'll check by exception type name instead
    PlaywrightTimeoutError = None

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
        # Set default headers for the session to look more like a real browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })
        
        if not self.access_token and not (self.client_id and self.client_secret):
            raise ValueError("Either access_token or both client_id and client_secret must be provided")

    def _establish_session(self):
        """Establish a session with Are.na to get Cloudflare cookies"""
        try:
            # Visit the main site first to establish a session and get Cloudflare cookies
            print("Establishing session with Are.na...")
            response = self.session.get('https://are.na/', timeout=10)
            if response.status_code == 200:
                print("✅ Session established successfully")
                return True
            else:
                print(f"⚠️ Session establishment returned status {response.status_code}")
                return False
        except Exception as e:
            print(f"⚠️ Could not establish session: {e}")
            return False
    
    def get_authorization(self):
        if self.access_token:
            print("Using existing access token")
            # Establish session before testing token
            self._establish_session()
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
            'Accept-Encoding': 'gzip, deflate',
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
            # Use simpler headers to avoid Cloudflare blocking
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            }
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    user_data = response.json()
                    print(f"✅ Token is valid! Authenticated as: {user_data.get('username', 'Unknown')}")
                    return True
                except:
                    print("✅ Token is valid (got 200 response)")
                    return True
            elif response.status_code == 401:
                print("❌ Token is INVALID or EXPIRED (401 Unauthorized)")
                print("   You need to get a new access token.")
                return False
            elif response.status_code == 403:
                print("⚠️  Got 403 - could be Cloudflare blocking OR invalid token")
                # Try to see if we can decode the response
                try:
                    error_text = response.text[:200]
                    if 'cloudflare' in error_text.lower() or 'cf-ray' in error_text.lower():
                        print("   This looks like Cloudflare blocking, not an auth issue")
                    else:
                        print(f"   Response: {error_text}")
                except:
                    pass
                return False
            else:
                print(f"⚠️  Unexpected status code: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error testing access token: {e}")
            return False
    
    def test_channel_access(self, channel_slug):
        """Test if the channel exists and is accessible"""
        if not self.access_token:
            return False
        
        # Establish session first to get Cloudflare cookies
        self._establish_session()

        try:
            url = f"https://api.are.na/v2/channels/{channel_slug}"
            # Use simpler headers for API calls - Cloudflare might be blocking complex headers
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            }
            
            print(f"🔍 Testing channel access: {url}")
            print(f"🔑 Using access token: {self.access_token[:10]}...")
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            print(f"📊 Response status: {response.status_code}")
            print(f"📄 Response encoding: {response.encoding}")
            
            # Try to decode the response properly
            try:
                # Check if response is compressed
                content_encoding = response.headers.get('Content-Encoding', '')
                if content_encoding:
                    print(f"📦 Content-Encoding: {content_encoding}")
                
                # Try to get text (requests should auto-decompress)
                response_text = response.text
                print(f"🔍 Response content preview: {response_text[:200]}...")
            except Exception as e:
                print(f"⚠️ Error decoding response: {e}")
                # Try to decode as UTF-8 with error handling
                try:
                    response_text = response.content.decode('utf-8', errors='ignore')
                    print(f"🔍 Response content (fallback): {response_text[:200]}...")
                except:
                    response_text = str(response.content[:200])
                    print(f"🔍 Response content (raw): {response_text}...")
            
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
                try:
                    error_text = response.text
                except:
                    try:
                        error_text = response.content.decode('utf-8', errors='ignore')
                    except:
                        error_text = str(response.content[:500])
                print(f"🔍 Error response: {error_text[:500]}")
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
        # Use simpler headers for API calls - Cloudflare might be blocking complex headers
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
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
            self.last_arena_post_time = None
        
        atexit.register(self.save_state)
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

        self.last_published_alt_text = None
        self.recent_posts = []
        self.max_recent_posts = 10
        
        # Rate limiting: track last time an image was posted to are.na
        # Ensure it's initialized (load_state may have set it, or it's None for new crawls)
        if not hasattr(self, 'last_arena_post_time'):
            self.last_arena_post_time = None
        self.arena_post_interval = 600  # 10 minutes in seconds

        # Queue for images waiting to be posted to are.na (persists between sessions)
        self.post_queue_file = 'post_queue.json'
        self.post_queue = self.load_post_queue()

        self.broken_images_file = 'broken_images.json'
        self.broken_images_data = self.load_broken_images()

        # Launch a persistent headless browser for accurate broken-image detection
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._browser_context = self._browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            ignore_https_errors=True,
        )
        
        # Network connectivity tracking
        self.network_paused = False
        # Track retry attempts for URLs to prevent infinite loops
        self.url_retry_count = {}

    def _close_browser(self):
        try:
            self._browser_context.close()
        except Exception:
            pass
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw.stop()
        except Exception:
            pass
    
    def check_network_connectivity(self):
        """Check if network connectivity is available by trying to reach a reliable server"""
        test_urls = [
            'https://www.google.com',
            'http://8.8.8.8',  # Google DNS (HTTP for IP addresses)
            'http://1.1.1.1',  # Cloudflare DNS (HTTP for IP addresses)
        ]
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                # Accept any response status as long as we got a response (means network is up)
                return True
            except (ConnectionError, Timeout, RequestException) as e:
                # These are expected network errors - continue to next URL
                continue
            except Exception as e:
                # Unexpected errors - log but continue checking
                continue
        return False
    
    def wait_for_network_recovery(self, check_interval=10):
        """Wait for network connectivity to be restored"""
        if not self.network_paused:
            return
        
        print(f"\n⏸️  Network connectivity lost. Pausing queue processing...")
        print(f"📡 Waiting for network to recover (checking every {check_interval} seconds)...")
        print(f"Press Ctrl+C to exit (will save state)")
        
        while self.network_paused:
            try:
                if self.check_network_connectivity():
                    print(f"✅ Network connectivity restored! Resuming queue processing...")
                    self.network_paused = False
                    return
                else:
                    print(f"⏳ Still waiting for network... (Queue: {len(self.url_queue)} URLs pending)")
                    # Sleep in smaller increments to allow KeyboardInterrupt to be caught
                    for _ in range(check_interval):
                        time.sleep(1)
            except KeyboardInterrupt:
                # Re-raise to be handled by the main loop
                raise
    
    def _is_network_error(self, exception):
        """Check if an exception is a network connectivity error"""
        error_str = str(exception).lower()
        
        # Exclude non-network errors first
        non_network_indicators = [
            'download is starting',
            'download',
            'navigation was interrupted',
            'target closed',
            'page closed',
            'context closed',
            'browser closed',
            'page.goto: timeout',
            'navigation timeout',
            'waiting for',
            'err_http2_protocol_error',
            'err_http2',
            'protocol error',
            'http2',
            'http/2',
            'server error',
            '502',
            '503',
            '504',
            '500',
        ]
        
        # If error contains non-network indicators, it's not a network error
        if any(indicator in error_str for indicator in non_network_indicators):
            return False
        
        network_error_types = [
            ConnectionError,
            Timeout,
            RequestException,
        ]
        
        # Add PlaywrightTimeoutError if available
        if PlaywrightTimeoutError is not None:
            network_error_types.append(PlaywrightTimeoutError)
        
        # Check exception type
        if isinstance(exception, tuple(network_error_types)):
            # Double-check it's not a download-related timeout
            if 'download' in error_str:
                return False
            return True
        
        # Also check by exception type name (for Playwright timeout errors)
        exception_type_name = type(exception).__name__
        if 'TimeoutError' in exception_type_name or 'Timeout' in exception_type_name:
            # Exclude download-related timeouts
            if 'download' in error_str:
                return False
            return True
        
        # Check exception message for network-related keywords
        network_keywords = [
            'connection',
            'network',
            'dns',
            'resolve',
            'unreachable',
            'refused',
            'reset',
            'no internet',
            'offline',
            'connection refused',
            'connection reset',
            'name resolution',
        ]
        
        return any(keyword in error_str for keyword in network_keywords)

    def save_state(self):
        state = {
            'url_queue': list(self.url_queue),
            'visited_urls': list(self.visited_urls),
            'known_domains': list(self.known_domains),
            'start_url': self.start_url,
            'broken_images_count': self.broken_images_count,
            'last_arena_post_time': self.last_arena_post_time
        }
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f)
        # Also save post queue
        self.save_post_queue()
        print(f"State saved. Total broken images: {self.broken_images_count}, Post queue: {len(self.post_queue)}")

    def load_state(self):
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            self.url_queue = deque(state['url_queue'])
            self.visited_urls = set(state['visited_urls'])
            self.known_domains = set(state['known_domains'])
            self.broken_images_count = state.get('broken_images_count', 0)
            self.last_arena_post_time = state.get('last_arena_post_time', None)
            
            if state.get('start_url') != self.start_url:
                self.url_queue.append(self.start_url)
            
            print(f"Resuming crawl - Queue: {len(self.url_queue)}, Visited: {len(self.visited_urls)}, Total found: {self.broken_images_count}")
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error loading state: {e}")
            self.url_queue = deque([self.start_url])
            self.visited_urls = set()
            self.known_domains = set()
            self.broken_images_count = 0
            self.last_arena_post_time = None

    def handle_exit(self, signum, frame):
        print("\nSaving state before exit...")
        try:
            self.save_state()
            print("State saved.")
        except Exception as e:
            print(f"Warning: Error saving state: {e}")
        
        # Skip browser cleanup - os._exit will kill all processes anyway
        # Trying to close browser might hang if it's stuck in a blocking operation
        print("Exiting...")
        os._exit(0)

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
    
    def _is_amazon_url(self, url):
        """Return True if the URL belongs to Amazon and should be skipped."""
        try:
            netloc = urlparse(url).netloc.lower()
            # Remove 'www.' prefix if present for easier matching
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            
            amazon_domains = ('amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 
                            'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp',
                            'amazon.in', 'amazon.com.au', 'amazon.com.mx', 'amazon.nl',
                            'amazon.se', 'amazon.pl', 'amazon.com.br', 'amazon.sg',
                            'amazon.ae', 'amazon.sa', 'amazon.tr', 'amazon.eg')
            for domain in amazon_domains:
                if netloc == domain or netloc.endswith('.' + domain):
                    return True
            return False
        except Exception:
            return False
    
    def _is_google_url(self, url):
        """Return True if the URL belongs to Google and should be skipped."""
        try:
            netloc = urlparse(url).netloc.lower()
            # Remove 'www.' prefix if present for easier matching
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            
            google_domains = ('google.com', 'google.co.uk', 'google.ca', 'google.de',
                            'google.fr', 'google.it', 'google.es', 'google.co.jp',
                            'google.com.au', 'google.com.mx', 'google.nl', 'google.se',
                            'google.pl', 'google.com.br', 'google.sg', 'google.ae',
                            'google.sa', 'google.tr', 'google.eg', 'google.in',
                            'google.ru', 'google.cn', 'google.co.za', 'google.co.nz',
                            'google.com.ar', 'google.cl', 'google.co.kr', 'google.com.tw',
                            'google.com.hk', 'google.com.sg', 'google.co.id', 'google.com.ph',
                            'google.com.vn', 'google.com.my', 'google.com.th', 'youtube.com',
                            'youtu.be', 'gmail.com', 'googlemail.com', 'googletagmanager.com',
                            'googleapis.com', 'googleusercontent.com', 'gstatic.com',
                            'googleadservices.com', 'doubleclick.net', 'googlesyndication.com')
            for domain in google_domains:
                if netloc == domain or netloc.endswith('.' + domain):
                    return True
            return False
        except Exception:
            return False
    
    def _is_pdf_url(self, url):
        """Return True if the URL points to a PDF file."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            # Check if URL ends with .pdf or has pdf in the path
            if path.endswith('.pdf') or '/pdf' in path:
                return True
            return False
        except Exception:
            return False

    def extract_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urljoin(base_url, href)
            if (absolute_url.startswith(('http://', 'https://')) and 
                not self._is_shortener_url(absolute_url) and 
                not self._is_amazon_url(absolute_url) and
                not self._is_google_url(absolute_url) and
                not self._is_pdf_url(absolute_url)):
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
    
    def load_post_queue(self):
        """Load the queue of images waiting to be posted to are.na"""
        try:
            if os.path.exists(self.post_queue_file):
                with open(self.post_queue_file, 'r') as f:
                    queue_data = json.load(f)
                    print(f"📋 Loaded {len(queue_data)} items from post queue")
                    return deque(queue_data)
            return deque()
        except (json.JSONDecodeError, KeyError) as e:
            print(f"⚠️  Error loading post queue: {e}, starting with empty queue")
            return deque()
    
    def save_post_queue(self):
        """Save the queue of images waiting to be posted to are.na"""
        try:
            with open(self.post_queue_file, 'w') as f:
                json.dump(list(self.post_queue), f, indent=2)
        except Exception as e:
            print(f"⚠️  Error saving post queue: {e}")
    
    def add_to_post_queue(self, content, img_url, alt_text, page_url):
        """Add an item to the post queue"""
        # Never queue logo-related entries for posting.
        if 'logo' in (alt_text or '').lower():
            print(f"⏭️  Skipping Are.na post (contains 'logo'): {alt_text}")
            return

        queue_item = {
            'content': content,
            'img_url': img_url,
            'alt_text': alt_text,
            'page_url': page_url,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M")
        }
        self.post_queue.append(queue_item)
        self.save_post_queue()
        print(f"📝 Added to post queue: {alt_text} (Queue size: {len(self.post_queue)})")
    
    def process_post_queue(self):
        """Process items from the post queue with rate limiting"""
        if not self.post_queue:
            return
        
        # Enforce logo-filter for any legacy items already in queue.
        while self.post_queue:
            queued_alt = (self.post_queue[0].get('alt_text') or '').lower()
            if 'logo' not in queued_alt:
                break
            skipped_item = self.post_queue.popleft()
            self.save_post_queue()
            print(f"⏭️  Removed queued logo item (not posting): {skipped_item.get('alt_text', '')}")
        
        if not self.post_queue:
            return
        
        # Check if we can post (rate limiting)
        current_time = time.time()
        if self.last_arena_post_time is not None:
            time_since_last_post = current_time - self.last_arena_post_time
            if time_since_last_post < self.arena_post_interval:
                # Not enough time has passed, skip for now
                return
        
        # Get the next item from the queue
        queue_item = self.post_queue[0]  # Peek at first item without removing
        
        content = queue_item['content']
        alt_text = queue_item['alt_text']
        
        max_retries = 3
        retry_delay = 1
        for attempt in range(max_retries):
            try:
                print(f"📤 Processing post queue: Attempting to post '{alt_text}' (attempt {attempt + 1}/{max_retries})")
                print(f"   Queue size: {len(self.post_queue)}")
                
                self.arena_api.post_to_channel(self.channel_slug, content)
                print(f"✅ Posted to Are.na: {alt_text}")
                
                # Success! Remove from queue and update state
                self.post_queue.popleft()  # Remove the item we just posted
                self.save_post_queue()
                self.last_published_alt_text = alt_text
                self.last_arena_post_time = time.time()
                
                # Update broken_images_data if this item matches
                for broken_img in self.broken_images_data:
                    if (broken_img.get('alt_text') == alt_text and 
                        broken_img.get('img_url') == queue_item['img_url'] and
                        broken_img.get('page_url') == queue_item['page_url']):
                        broken_img['arena_post_success'] = True
                        with open(self.broken_images_file, 'w') as f:
                            json.dump(self.broken_images_data, f, indent=2)
                        break
                
                break  # Success, exit retry loop
                
            except Exception as e:
                # Check if this is a network connectivity error
                if self._is_network_error(e):
                    print(f"⚠️  Network error detected while posting to Are.na: {e}")
                    self.network_paused = True
                    # Don't remove from queue, we'll retry when network is back
                    break
                else:
                    print(f"❌ Are.na posting failed on attempt {attempt + 1}: {e}")
                    if attempt < max_retries - 1:
                        print(f"   Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2
                    else:
                        print(f"❌ Failed to post to Are.na after {max_retries} attempts: {e}")
                        # Remove from queue after max retries to prevent infinite retries
                        self.post_queue.popleft()
                        self.save_post_queue()
                        print(f"   Removed from queue after max retries")

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
    
    def _confirm_broken_image_url(self, img_url):
        """Return True only when the image URL appears truly broken via direct fetch + decode."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': self.current_url if hasattr(self, 'current_url') else self.start_url,
        }
        try:
            response = requests.get(img_url, headers=headers, timeout=12, allow_redirects=True)
            if response.status_code >= 400:
                return True
            content_type = (response.headers.get('Content-Type') or '').lower()
            if content_type and 'image' not in content_type:
                return True
            if not response.content:
                return True
            try:
                # Verify that bytes decode as a real image; invalid/HTML placeholders fail here.
                image = Image.open(io.BytesIO(response.content))
                image.verify()
                return False
            except Exception:
                return True
        except (ConnectionError, Timeout, RequestException):
            # Uncertain due transient network conditions; avoid false positives.
            return False
        except Exception:
            return False

    def crawl_page_for_broken_images(self, url):
        page = self._browser_context.new_page()
        try:
            # Load the page in a real browser and wait for network to settle
            # Timeout set to 20 seconds - if page takes longer, skip to next
            page.goto(url, wait_until='networkidle', timeout=20000)
            effective_url = page.url
            self.current_url = effective_url

            # Ask the browser which images show the broken-image icon.
            # img.complete==true && img.naturalWidth==0 is the standard browser check.
            broken_imgs = page.evaluate("""() =>
                Array.from(document.querySelectorAll('img'))
                    .filter(img => {
                        if (!(img.complete && img.naturalWidth === 0 && img.src)) return false;
                        
                        // Skip hidden carousel/lazy elements that are often temporarily unresolved.
                        const hiddenAncestor = img.closest('[aria-hidden="true"], [hidden]');
                        if (hiddenAncestor) return false;
                        
                        const style = window.getComputedStyle(img);
                        if (!style || style.display === 'none' || style.visibility === 'hidden') return false;
                        
                        const rect = img.getBoundingClientRect();
                        if (rect.width === 0 || rect.height === 0) return false;
                        
                        return true;
                    })
                    .map(img => ({ src: img.src, alt: img.getAttribute('alt') || '' }))
            """)

            # Extract links for the crawl queue from the live page HTML
            html = page.content()
            soup = BeautifulSoup(html, 'html.parser')
            links = self.extract_links(soup, effective_url)

        except Exception as e:
            error_str = str(e).lower()
            # Check if this is a timeout (page took too long)
            is_timeout = 'timeout' in error_str or 'timed out' in error_str
            
            if is_timeout:
                print(f"⏱️  Page timeout (>20s) - skipping {url}")
                # Mark as visited so we don't retry
                self.visited_urls.add(url)
                return []
            
            # Check if this is a network connectivity error
            if self._is_network_error(e):
                # Track retry count for this URL
                retry_count = self.url_retry_count.get(url, 0) + 1
                self.url_retry_count[url] = retry_count
                
                # If we've retried this URL 3 times, give up and mark as visited
                if retry_count >= 3:
                    print(f"⚠️  Network error on {url} (retried {retry_count} times) - giving up")
                    self.visited_urls.add(url)
                    # Remove from retry tracking
                    if url in self.url_retry_count:
                        del self.url_retry_count[url]
                else:
                    print(f"⚠️  Network error detected while crawling {url}: {e} (retry {retry_count}/3)")
                    self.network_paused = True
                    # Put the URL back at the front of the queue so we can retry it
                    self.url_queue.appendleft(url)
            else:
                # Not a network error - server error, protocol error, etc.
                # Mark as visited so we don't retry infinitely
                print(f"⚠️  Page error (not network) - skipping {url}: {e}")
                self.visited_urls.add(url)
                # Clear retry count if it exists
                if url in self.url_retry_count:
                    del self.url_retry_count[url]
            return []
        finally:
            try:
                page.close()
            except Exception:
                pass

        # Successful crawl - clear retry count if it exists
        if url in self.url_retry_count:
            del self.url_retry_count[url]

        # Queue discovered links
        current_domain = '/'.join(url.split('/')[:3])
        external_links = [l for l in links if '/'.join(l.split('/')[:3]) != current_domain]
        internal_links = [l for l in links if '/'.join(l.split('/')[:3]) == current_domain]
        random.shuffle(external_links)
        random.shuffle(internal_links)
        links_added = 0
        links_added += self._add_links_to_queue(external_links, "external", links_added, 6)
        links_added += self._add_links_to_queue(internal_links, "internal", links_added, 10 - links_added)

        skip_patterns = ['1px.gif', 'blank.gif', 'spacer.gif', 'pixel.gif', 'clear.gif',
                         'transparent.gif', 'empty.gif', 'invisible.gif', '1x1.gif',
                         'dot.gif', 'space.gif', 'tracker.gif', '0x0.gif']

        broken_images_alt_texts = []

        for img_data in broken_imgs:
            img_url = img_data['src']
            alt_text = img_data['alt']

            if not img_url.startswith(('http://', 'https://')):
                continue

            # Skip SVG/AVIF (browsers handle these differently)
            if img_url.lower().endswith(('.svg', '.avif')):
                continue

            # Skip tracking pixels and spacer images
            img_filename = img_url.split('/')[-1].lower()
            if any(pattern in img_filename for pattern in skip_patterns):
                continue

            # Only process alt text with more than one word
            if not alt_text or len(alt_text.split()) <= 1:
                continue

            # Skip duplicates
            if self.is_duplicate_broken_image(img_url, alt_text, effective_url):
                continue
            
            # Confirm with a direct fetch/decode check to reduce browser-render false positives.
            if not self._confirm_broken_image_url(img_url):
                continue

            self.save_broken_image(img_url, alt_text, effective_url)

            if alt_text == self.last_published_alt_text:
                continue

            broken_images_alt_texts.append(alt_text)
            self.play_notification_sound()
            print(f"🚨 BROKEN IMAGE FOUND: {alt_text} 🚨")
            self.broken_images_count += 1

            self.recent_posts.append(url)
            if len(self.recent_posts) > self.max_recent_posts:
                self.recent_posts.pop(0)
            self.check_and_reorder_queue(url)

            content = {
                'content': f'{alt_text}',
                'title': alt_text,
                'description': f'page url: *{effective_url}*\nimage url: *{img_url}*',
            }

            # Add to post queue instead of posting immediately
            # The queue will be processed with rate limiting in the main loop
            self.add_to_post_queue(content, img_url, alt_text, effective_url)

        return broken_images_alt_texts

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
                
                # Skip Amazon links
                if self._is_amazon_url(link):
                    continue
                
                # Skip Google links
                if self._is_google_url(link):
                    continue
                
                # Skip PDF files
                if self._is_pdf_url(link):
                    continue

                # Validate that the link is a well-formed HTTP(S) URL before enqueueing.
                # We avoid doing a network request here; any connection issues will be
                # handled when we actually crawl the page.
                try:
                    parsed = urlparse(link)
                    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                        continue
                except Exception:
                    continue

                self.url_queue.append(link)
                added += 1
        return added

    def get_next_url(self):
        while self.url_queue:
            url = self.url_queue.popleft()
            # Skip Amazon links even if they're in the queue
            if self._is_amazon_url(url):
                self.visited_urls.add(url)  # Mark as visited so we don't try again
                continue
            # Skip Google links even if they're in the queue
            if self._is_google_url(url):
                self.visited_urls.add(url)  # Mark as visited so we don't try again
                continue
            # Skip PDF files even if they're in the queue
            if self._is_pdf_url(url):
                self.visited_urls.add(url)  # Mark as visited so we don't try again
                continue
            if url not in self.visited_urls:
                return url

        # Queue is empty — clear visited history and restart from start_url
        # so the crawler keeps finding new pages indefinitely.
        print("Queue empty — clearing visited history and restarting from start URL.")
        self.visited_urls.clear()
        return self.start_url

    def continuous_crawl(self):
        print("\nPress Ctrl+C to save and exit.")
        print(f"Total broken images found so far: {self.broken_images_count}")
        if len(self.post_queue) > 0:
            print(f"📋 Post queue: {len(self.post_queue)} items waiting to be posted")
        if self.sound_notifications:
            print("🔊 Sound notifications enabled - you'll hear a beep when broken images are found!")
        else:
            print("🔇 Sound notifications disabled")
        scrape_count = 0
        try:
            while True:
                # Check network connectivity before processing
                if self.network_paused or not self.check_network_connectivity():
                    if not self.network_paused:
                        self.network_paused = True
                    self.wait_for_network_recovery()
                    continue
                
                # Process post queue (with rate limiting) before crawling new pages
                # This ensures queued items are posted even if we're not finding new broken images
                self.process_post_queue()
                
                current_url = self.get_next_url()
                
                # Skip Amazon URLs (double-check in case one slipped through)
                if self._is_amazon_url(current_url):
                    print(f"\n⏭️  Skipping Amazon URL: {current_url}")
                    self.visited_urls.add(current_url)
                    continue
                
                # Skip Google URLs (double-check in case one slipped through)
                if self._is_google_url(current_url):
                    print(f"\n⏭️  Skipping Google URL: {current_url}")
                    self.visited_urls.add(current_url)
                    continue
                
                # Skip PDF files (double-check in case one slipped through)
                if self._is_pdf_url(current_url):
                    print(f"\n⏭️  Skipping PDF file: {current_url}")
                    self.visited_urls.add(current_url)
                    continue
                
                print(f"\nCrawling: {current_url}")
                
                broken_images = self.crawl_page_for_broken_images(current_url)
                
                # If network error occurred during crawling, wait for recovery
                # Don't mark URL as visited since we put it back in the queue
                if self.network_paused:
                    self.wait_for_network_recovery()
                    continue
                
                # Only mark as visited if crawl was successful (no network error)
                self.visited_urls.add(current_url)
                self.known_domains.add(current_url)
                
                scrape_count += 1
                if scrape_count >= 10:
                    queue_list = list(self.url_queue)
                    random.shuffle(queue_list)
                    self.url_queue = deque(queue_list)
                    scrape_count = 0

                print(f"Queue: {len(self.url_queue)}, Visited: {len(self.visited_urls)}, Total found: {self.broken_images_count}, Post queue: {len(self.post_queue)}")
                
                # Process post queue again after crawling (in case we added new items)
                self.process_post_queue()
                
                if len(self.visited_urls) >= self.max_visited:
                    print("Resetting visited URLs list...")
                    self.save_state()
                    self.visited_urls.clear()

        except KeyboardInterrupt:
            print("\nReceived keyboard interrupt...")
            try:
                self.save_state()
                print("State saved.")
            except Exception as e:
                print(f"Warning: Error saving state: {e}")
            
            # Skip browser cleanup - os._exit will kill all processes anyway
            # Trying to close browser might hang if it's stuck in a blocking operation
            print("Exiting...")
            os._exit(0)

    def test_image_url(self, url):
        """Test a specific image URL to see if it's correctly identified as broken or valid"""
        print(f"\n=== Testing URL: {url} ===")
        page = self._browser_context.new_page()
        try:
            # Build a minimal page that contains only this image so the browser
            # can tell us whether it renders or shows the broken icon.
            page.set_content(f'<html><body><img id="img" src="{url}"></body></html>',
                             wait_until='networkidle')
            result = page.evaluate("""() => {
                const img = document.getElementById('img');
                return { complete: img.complete, naturalWidth: img.naturalWidth };
            }""")
            is_broken = result['complete'] and result['naturalWidth'] == 0
            print(f"complete={result['complete']}  naturalWidth={result['naturalWidth']}  broken={is_broken}")
            return not is_broken
        except Exception as e:
            print(f"Error testing URL: {e}")
            return False
        finally:
            page.close()

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
    
    start_url = 'https://tregeagle.com/' 
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
