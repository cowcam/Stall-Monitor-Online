
import requests
import os

ZONE_ID = "5aeca7f6e29e5f6a4c3f22a45e9fc155"
API_TOKEN = "YTeTMaJ6MjJFHQJKgjo4whYn1lPpRe_PWU1btpR9"

url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

data = {
    "content": "stallmonitor.com",
    "name": "*",
    "proxied": True,
    "type": "CNAME",
    "comment": "Wildcard for Worker"
}

try:
    response = requests.post(url, json=data, headers=headers)
    print(f"Status Code: {response.status_code}")
    print(response.json())
except Exception as e:
    print(f"Error: {e}")
