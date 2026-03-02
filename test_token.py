#!/usr/bin/env python3
"""Simple script to test if your Are.na access token is valid"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

access_token = os.getenv('ARENA_ACCESS_TOKEN')

if not access_token:
    print("[ERROR] No ARENA_ACCESS_TOKEN found in .env file")
    exit(1)

print(f"Testing token: {access_token[:10]}...")
print()

# Test 1: Simple API call to /v2/me
print("Test 1: Checking token validity with /v2/me endpoint...")
try:
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    response = requests.get('https://api.are.na/v2/me', headers=headers, timeout=10)
    
    print(f"   Status Code: {response.status_code}")
    
    if response.status_code == 200:
        try:
            user_data = response.json()
            print(f"   [OK] TOKEN IS VALID!")
            print(f"   Username: {user_data.get('username', 'Unknown')}")
            print(f"   Full Name: {user_data.get('full_name', 'Unknown')}")
        except:
            print(f"   [OK] TOKEN IS VALID (got 200, but couldn't parse JSON)")
    elif response.status_code == 401:
        print(f"   [ERROR] TOKEN IS INVALID OR EXPIRED")
        print(f"   You need to get a new access token.")
    elif response.status_code == 403:
        print(f"   [WARNING] Got 403 Forbidden")
        print(f"   This could be:")
        print(f"   - Cloudflare blocking your IP")
        print(f"   - Invalid token (but Cloudflare blocked before auth check)")
        try:
            error_text = response.text[:300]
            if 'cloudflare' in error_text.lower():
                print(f"   Response contains 'cloudflare' - likely IP blocking")
            print(f"   Response preview: {error_text}")
        except:
            pass
    else:
        print(f"   [WARNING] Unexpected status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
        
except Exception as e:
    print(f"   ❌ Error: {e}")

print()
print("Test 2: Testing channel access...")
try:
    channel_slug = "broken-images-and-the-alt-text-that-remains"
    url = f"https://api.are.na/v2/channels/{channel_slug}"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    response = requests.get(url, headers=headers, timeout=10)
    
    print(f"   Status Code: {response.status_code}")
    
    if response.status_code == 200:
        try:
            channel_data = response.json()
            print(f"   [OK] Channel access successful!")
            print(f"   Channel: {channel_data.get('title', 'Unknown')}")
        except:
            print(f"   [OK] Channel access successful (got 200)")
    elif response.status_code == 403:
        print(f"   [ERROR] 403 Forbidden - Cloudflare blocking or no permission")
    elif response.status_code == 404:
        print(f"   [ERROR] Channel not found")
    else:
        print(f"   [WARNING] Status: {response.status_code}")
        
except Exception as e:
    print(f"   [ERROR] Error: {e}")

print()
print("=" * 60)
print("SUMMARY:")
print("=" * 60)
print("If you see 401 errors, your token is expired/invalid.")
print("If you see 403 errors, it's likely Cloudflare blocking.")
print("If you see 200, everything is working!")

