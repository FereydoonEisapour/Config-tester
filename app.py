import re
import geoip2.database
import os
import sys
import platform
import subprocess
import tempfile
import time
import json
import argparse
import logging
import threading
import queue
import requests
import shutil
import re
import base64
from urllib.parse import urlparse, parse_qs, unquote
from base64 import urlsafe_b64decode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')

# Organized directory structure for data storage
PROTOCOLS_DIR = os.path.join("Servers", "Protocols")      # Protocol-specific server configurations
REGIONS_DIR = os.path.join("Servers", "Regions")          # Country-based server groupings
REPORTS_DIR = os.path.join("logs")                        # Logs and extraction analytics
MERGED_DIR = os.path.join("Servers", "Merged")            # Consolidated server list
CHANNELS_DIR = os.path.join("Servers", "Channels")        # Per-channel configuration storage

CHANNELS_FILE = "data/telegram_sources.txt"                           # Input file
LOG_FILE = os.path.join(REPORTS_DIR, "extraction_report.log")         # Master log file
GEOIP_DATABASE_PATH = Path("data/db/GeoLite2-Country.mmdb")           # MaxMind GeoLite2 database
MERGED_SERVERS_FILE = os.path.join(MERGED_DIR, "merged_servers.txt")  # Unified server list

SLEEP_TIME = 3                   # Anti-rate-limiting delay between batches (seconds)
BATCH_SIZE = 10                  # Channels processed before sleep interval
FETCH_CONFIG_LINKS_TIMEOUT = 15  # HTTP request timeout for Telegram scraping (seconds)

V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
V2RAY_DIR = os.path.join("data", 'v2ray')
TESTED_SERVERS_DIR = os.path.join(BASE_DIR, 'Tested_Servers')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
CHANNELS_DIR = os.path.join(BASE_DIR, 'Servers/Channels')

# Maximum entries per file
MAX_CHANNEL_SERVERS = 50          # Max entries per channel file
MAX_PROTOCOL_SERVERS = 500        # Max entries per protocol file
MAX_REGION_SERVERS = 500          # Max entries per region file
MAX_MERGED_SERVERS = 1000         # Max entries in merged file

# Test
TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 20
START_PORT = 10000
REQUEST_TIMEOUT = 10
PROCESS_START_WAIT = 20
MAX_RETRIES = 1

def clean_directory(dir_path):
    if os.path.exists(dir_path):
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        logging.info(f"Cleaned directory: {dir_path}")
    else:
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")

clean_directory("Servers")

# Create directories if they don't exist
for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR]:
    os.makedirs(directory, exist_ok=True)

# ========================
# Protocol Detection Patterns
# ========================
# Regex patterns for exact protocol matching (negative lookbehind prevents partial matches)
PATTERNS = {
    'vmess': r'(?<![a-zA-Z0-9_])vmess://[^\s<>]+',           # VMess  
    'vless': r'(?<![a-zA-Z0-9_])vless://[^\s<>]+',           # VLESS 
    'trojan': r'(?<![a-zA-Z0-9_])trojan://[^\s<>]+',         # Trojan 
    'hysteria': r'(?<![a-zA-Z0-9_])hysteria://[^\s<>]+',     # Hysteria v1  
    'hysteria2': r'(?<![a-zA-Z0-9_])hysteria2://[^\s<>]+',   # Hysteria v2 
    'tuic': r'(?<![a-zA-Z0-9_])tuic://[^\s<>]+',             # TUIC  
    'ss': r'(?<![a-zA-Z0-9_])ss://[^\s<>]+',                 # Shadowsocks  
    'wireguard': r'(?<![a-zA-Z0-9_])wireguard://[^\s<>]+',   # Wireguard  
    'warp': r'(?<![a-zA-Z0-9_])warp://[^\s<>]+'              # Warp  
}


# Protocol enable/disable configuration
ENABLED_PROTOCOLS = {
    'vless': True,
    'vmess': True,
    'trojan': True,
    'ss': True
}

def normalize_telegram_url(url):
    """
    Normalizes a Telegram channel name or URL to the standard format with '/s/'.
    
    - Converts 'example' to 'https://t.me/s/example'.
    - Converts 'https://t.me/example' to 'https://t.me/s/example'.
    - Leaves URLs already in 'https://t.me/s/...' format unchanged.
    
    Args:
        url (str): The input channel name or URL.
        
    Returns:
        str: The normalized Telegram channel URL.
    """
    # Strip leading/trailing whitespace
    url = url.strip()
    
    # Check if the input is already a valid Telegram URL
    if url.startswith("https://t.me/"):
        parts = url.split('/')
        if len(parts) >= 4 and parts[3] != 's':
            # Convert to https://t.me/s/... format
            return f"https://t.me/s/{'/'.join(parts[3:])}"
        return url  # Already normalized
    
    # Handle cases where only the channel name is provided (e.g., 'example')
    elif url:
        # Prepend 'https://t.me/s/' to the channel name
        return f"https://t.me/s/{url}"
    
    # Return empty string if input is invalid
    return ""


def extract_channel_name(url):
    """Extracts normalized channel name from Telegram URL."""
    return url.split('/')[-1].replace('s/', '')

def count_servers_in_file(file_path):
    """Counts valid server entries in a text file."""
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip()])
    except Exception as e:
        print(f"❌ Error counting servers in {file_path}: {e}")
        return 0

def get_current_counts():
    """Generates comprehensive server statistics."""
    counts = {}
    
    # Protocol-specific counts
    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        counts[proto] = count_servers_in_file(proto_file)
    
    # Consolidated server count
    counts['total'] = count_servers_in_file(MERGED_SERVERS_FILE)
    
    # Regional distribution analysis
    regional_servers = 0
    country_data = {}
    for region_file in Path(REGIONS_DIR).glob("*.txt"):
        country = region_file.stem
        count = count_servers_in_file(region_file)
        country_data[country] = count
        regional_servers += count
    
    # Geo-IP resolution metrics
    counts['successful'] = regional_servers
    counts['failed'] = counts['total'] - regional_servers
    
    return counts, country_data

def get_channel_stats():
    """Compiles contribution metrics per Telegram channel."""
    channel_stats = {}
    for channel_file in Path(CHANNELS_DIR).glob("*.txt"):
        channel_name = channel_file.stem
        count = count_servers_in_file(channel_file)
        channel_stats[channel_name] = count
    return channel_stats

def save_extraction_data(channel_stats, country_data):

    """Persists extraction metrics to log file."""
    current_counts, country_stats = get_current_counts()
    
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            # Regional statistics
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers: {current_counts['total']}\n")
            log.write(f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")
            
            # Protocol distribution
            log.write("\n=== Server Type Summary ===\n")
            sorted_protocols = sorted(PATTERNS.keys(), key=lambda x: current_counts[x], reverse=True)
            for proto in sorted_protocols:
                log.write(f"{proto.upper():<20} : {current_counts[proto]}\n")
            
            # Channel contributions
            log.write("\n=== Channel Statistics ===\n")
            for channel, total in sorted(channel_stats.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{channel:<20}: {total}\n")
                
    except Exception as e:
        print(f"❌ Error writing to log file: {e}")
     
def fetch_config_links(url):
    """Scrapes Telegram channel content for proxy configuration links."""
    try:
        response = requests.get(url, timeout=FETCH_CONFIG_LINKS_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        
        
        message_tags = soup.find_all(['div', 'span'], class_='tgme_widget_message_text')
        code_blocks = soup.find_all(['code', 'pre'])
        
        configs = {proto: set() for proto in PATTERNS}
        configs["all"] = set()
        
        
        for code_tag in code_blocks:
            code_text = code_tag.get_text().strip()
           
            clean_text = re.sub(r'^(`{1,3})|(`{1,3})$', '', code_text, flags=re.MULTILINE)
            
            for proto, pattern in PATTERNS.items():
                matches = re.findall(pattern, clean_text)
                if matches:
                    configs[proto].update(matches)
                    configs["all"].update(matches)
        
        
        for tag in message_tags:
            general_text = tag.get_text().strip()
            
            for proto, pattern in PATTERNS.items():
                matches = re.findall(pattern, general_text)
                if matches:
                    configs[proto].update(matches)
                    configs["all"].update(matches)
        
        return {k: list(v) for k, v in configs.items()}
    
    except requests.exceptions.RequestException as e:
        print(f"🛜❌ Connection error for {url}: {e}")
        return None

def load_existing_configs():
    """Loads previously extracted configurations to prevent duplicates."""
    existing = {proto: set() for proto in PATTERNS}
    existing["merged"] = set()
    
    # Protocol-specific entries
    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        if os.path.exists(proto_file):
            try:
                with open(proto_file, 'r', encoding='utf-8') as f:
                    existing[proto] = set(f.read().splitlines())
            except Exception as e:
                print(f"Error reading {proto} configs: {e}")
    
    # Merged entries
    if os.path.exists(MERGED_SERVERS_FILE):
        try:
            with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                existing['merged'] = set(f.read().splitlines())
        except Exception as e:
            print(f"Error reading merged configs: {e}")
    
    return existing

def trim_file(file_path, max_lines):
    """Trim file to keep only the latest entries up to max_lines."""
    if not os.path.exists(file_path):
        return
    try:
        with open(file_path, 'r+', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                f.seek(0)
                f.truncate()
                f.writelines(lines[:max_lines])
    except Exception as e:
        print(f"Error trimming {file_path}: {e}")

def process_channel(url):
    """Executes full processing pipeline for a Telegram channel."""
    existing_configs = load_existing_configs()
    channel_name = extract_channel_name(url)
    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    
    configs = fetch_config_links(url)
    if not configs:
        return 0, 0  # Early exit on failure

    all_channel_configs = set()
    for proto_links in configs.values():
        all_channel_configs.update(proto_links)

    # Channel-specific deduplication
    existing_channel_configs = set()
    if os.path.exists(channel_file):
        with open(channel_file, 'r', encoding='utf-8') as f:
            existing_channel_configs = set(f.read().splitlines())
    
    new_channel_configs = all_channel_configs - existing_channel_configs
    if new_channel_configs:
        updated_channel_configs = list(new_channel_configs) + list(existing_channel_configs)
        with open(channel_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(updated_channel_configs[:MAX_CHANNEL_SERVERS]) + '\n')

    # Protocol processing
    for proto, links in configs.items():
        if proto == "all":
            continue
        new_links = set(links) - existing_configs[proto]
        if not new_links:
            continue

        unique_new = [link for link in new_links if link not in existing_configs[proto]]
        
        # Update protocol file
        proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        try:
            existing_lines = []
            if os.path.exists(proto_path):
                with open(proto_path, 'r', encoding='utf-8') as f:
                    existing_lines = f.read().splitlines()
            
            updated_lines = unique_new + existing_lines
            with open(proto_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_lines[:MAX_PROTOCOL_SERVERS]) + '\n')
        
        except Exception as e:
            print(f"Error writing to {proto} file: {e}")
        
        # Update merged list
        try:
            merged_lines = []
            if os.path.exists(MERGED_SERVERS_FILE):
                with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                    merged_lines = f.read().splitlines()
            
            new_merged = [link for link in unique_new if link not in merged_lines]
            updated_merged = new_merged + merged_lines
            with open(MERGED_SERVERS_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_merged[:MAX_MERGED_SERVERS]) + '\n')
        
        except Exception as e:
            print(f"Error updating merged configs: {e}")
        
        existing_configs[proto].update(unique_new)

    return 1, len(new_channel_configs)

def download_geoip_database():
    """Downloads GeoLite2-Country database from GitHub."""
    GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb"
    GEOIP_DIR = Path("data/db")
    
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        
        response = requests.get(GEOIP_URL, timeout=30)
        response.raise_for_status()
        
        with open(GEOIP_DATABASE_PATH, 'wb') as f:
            f.write(response.content)
            
        print("✅ GeoLite2 database downloaded successfully")
        return True
    
    except Exception as e:
        print(f"❌ Failed to download GeoIP database: {e}")
        return False

def process_geo_data():
    """Performs geographical analysis using GeoIP database."""
    if not GEOIP_DATABASE_PATH.exists():
        print("⚠️ GeoIP database missing. Attempting download...")
        success = download_geoip_database()
        if not success:
            return {}
    
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except Exception as e:
        print(f"❌ GeoIP database error: {e}")
        return {}

    country_counter = {}  
    
    # Clear existing region files
    for region_file in Path(REGIONS_DIR).glob("*.txt"):
        region_file.unlink()

    # Process merged configurations
    configs = []
    if os.path.exists(MERGED_SERVERS_FILE):
        with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]

    for config in configs:
        try:
            # Extract IP from common proxy URI formats
            ip = config.split('@')[1].split(':')[0]  
            country_response = geo_reader.country(ip)
            country = country_response.country.name or "Unknown"
            
            country_counter[country] = country_counter.get(country, 0) + 1
            
            region_file = os.path.join(REGIONS_DIR, f"{country}.txt")
            existing_region = []
            if os.path.exists(region_file):
                with open(region_file, 'r', encoding='utf-8') as f:
                    existing_region = f.read().splitlines()
            
            updated_region = [config] + existing_region
            with open(region_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_region[:MAX_REGION_SERVERS]) + '\n')
                
        except (IndexError, geoip2.errors.AddressNotFoundError, ValueError):
            pass  # Silent fail for invalid formats
        except Exception as e:
            print(f"❌ Geo processing error: {e}")
    
    geo_reader.close()
    return country_counter

# Create required directories
required_dirs = [
    TESTED_SERVERS_DIR,
    os.path.join(TESTED_SERVERS_DIR, 'Protocols'),
    os.path.join(TESTED_SERVERS_DIR, 'Channels'),
    LOGS_DIR,
    V2RAY_DIR,
    CHANNELS_DIR
]

for dir_path in required_dirs:
    os.makedirs(dir_path, exist_ok=True)

# Configure logging
class CleanFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            return f"{record.msg}"
        elif record.levelno == logging.ERROR:
            return f"ERROR: {record.msg}"
        return super().format(record)

# Set up logger with UTF-8 encoding
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Console handler (clean output)
console_handler = logging.StreamHandler()
console_handler.setFormatter(CleanFormatter())
logger.addHandler(console_handler)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Thread-safe port counter
current_port = START_PORT
port_lock = threading.Lock()

def get_next_port():
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
    return port

def read_links_from_file(file_path):
    try:  
        with open(file_path, "r", encoding="utf-8") as file:
            links = file.readlines()
        return [link.strip() for link in links if link.strip()]
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return []

def parse_vless_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vless':
        raise ValueError("Invalid VLESS link")
    uuid = parsed.username
    uuid_pattern = (
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    if not re.match(uuid_pattern, uuid, re.I):
        raise ValueError(f"Invalid UUID format: {uuid}")
    query = parse_qs(parsed.query)
    return {
        'original_link': link,
        'protocol': 'vless',
        'uuid': uuid,
        'host': parsed.hostname,
        'port': parsed.port,
        'security': query.get('security', [''])[0] or 'none',
        'encryption': query.get('encryption', ['none'])[0],
        'network': query.get('type', ['tcp'])[0],
        'ws_path': query.get('path', [''])[0],
        'ws_host': query.get('host', [parsed.hostname])[0],
        'sni': query.get('sni', [parsed.hostname])[0] or parsed.hostname,
        'pbk': query.get('pbk', [''])[0],
        'sid': query.get('sid', [''])[0],
        'fp': query.get('fp', [''])[0],
        'alpn': query.get('alpn', [''])[0].split(',') if 'alpn' in query else [],
        'flow': query.get('flow', [''])[0]
    }

def parse_vmess_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vmess':
        raise ValueError("Invalid VMESS link")
    base64_data = parsed.netloc + parsed.path
    json_str = urlsafe_b64decode(base64_data + '==').decode('utf-8')
    data = json.loads(json_str)
    return {
        'original_link': link,
        'protocol': 'vmess',
        'uuid': data.get('id'),
        'host': data.get('add'),
        'port': int(data.get('port', 80)),
        'network': data.get('net', 'tcp'),
        'security': data.get('tls', 'none'),
        'ws_path': data.get('path', ''),
        'ws_host': data.get('host', ''),
        'sni': data.get('sni', ''),
        'alter_id': int(data.get('aid', 0)),
        'encryption': 'none'
    }

def parse_trojan_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'trojan':
        raise ValueError("Invalid Trojan link")
    query = parse_qs(parsed.query)
    return {
        'original_link': link,
        'protocol': 'trojan',
        'password': parsed.username,
        'host': parsed.hostname,
        'port': parsed.port,
        'security': query.get('security', ['tls'])[0],
        'sni': query.get('sni', [parsed.hostname])[0],
        'alpn': query.get('alpn', ['h2,http/1.1'])[0].split(','),
        'network': query.get('type', ['tcp'])[0],
        'ws_path': query.get('path', [''])[0],
        'ws_host': query.get('host', [parsed.hostname])[0]
    }

def parse_ss_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'ss':
        raise ValueError("Invalid Shadowsocks link")
    try:
        userinfo = unquote(parsed.netloc)
        if '@' in userinfo:
            base64_part, _ = userinfo.split('@', 1)
            try:
                padding = '=' * ((4 - len(base64_part) % 4) % 4)
                decoded = urlsafe_b64decode(base64_part + padding).decode('utf-8')
                if ':' not in decoded:
                    raise ValueError("Decoded Shadowsocks info missing ':' separator")
                method, password = decoded.split(':', 1)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 method:password — {str(e)}")
        elif ':' in userinfo:
            method, password = userinfo.split(':', 1)
        else:
            raise ValueError("Shadowsocks link missing proper format (no @ or :)")
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            raise ValueError("Missing host or port in Shadowsocks link")
        return {
            'original_link': link,
            'protocol': 'shadowsocks',
            'method': method,
            'password': password,
            'host': host,
            'port': int(port),
            'network': 'tcp'
        }
    except Exception as e:
        raise ValueError(f"Invalid Shadowsocks link format: {str(e)}")

def generate_config(server_info, local_port):
    config = {
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": server_info['protocol'],
            "settings": {},
            "streamSettings": {}
        }]
    }
    if server_info['protocol'] == 'vless':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "encryption": server_info['encryption'],
                    "flow": server_info.get('flow', '')
                }]
            }]
        }
    elif server_info['protocol'] == 'vmess':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "alterId": server_info['alter_id'],
                    "security": server_info['encryption']
                }]
            }]
        }
    elif server_info['protocol'] == 'trojan':
        config['outbounds'][0]['settings'] = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "password": server_info['password']
            }]
        }
    elif server_info['protocol'] == 'shadowsocks':
        config['outbounds'][0]['settings'] = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "method": server_info['method'],
                "password": server_info['password'],
                "ota": False
            }]
        }
    stream = {
        "network": server_info.get('network', 'tcp'),
        "security": server_info.get('security', 'none'),
        "tlsSettings": None,
        "realitySettings": None,
        "wsSettings": None
    }
    if server_info.get('security') == 'tls':
        stream['tlsSettings'] = {
            "allowInsecure": True,
            "serverName": server_info.get('sni'),
            "alpn": server_info.get('alpn', [])
        }
    elif server_info.get('security') == 'reality':
        stream['realitySettings'] = {
            "show": False,
            "fingerprint": server_info.get('fp', ''),
            "serverName": server_info.get('sni'),
            "publicKey": server_info.get('pbk', ''),
            "shortId": server_info.get('sid', ''),
            "spiderX": ""
        }
    if server_info.get('network') == 'ws':
        stream['wsSettings'] = {
            "path": server_info.get('ws_path', ''),
            "headers": {
                "Host": server_info.get('ws_host', '')
            }
        }
    config['outbounds'][0]['streamSettings'] = {k: v for k, v in stream.items() if v is not None}
    return config

def test_server(server_info, config, local_port, log_queue):
    for attempt in range(MAX_RETRIES):
        process = None
        config_path = None
        try:
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
                json.dump(config, f)
                config_path = f.name
            v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
            process = subprocess.Popen(
                [v2ray_path, 'run', '--config', config_path],
                cwd=V2RAY_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(PROCESS_START_WAIT)
            if process.poll() is not None:
                raise RuntimeError("V2Ray failed to start")
            proxies = {
                'http': f'socks5h://127.0.0.1:{local_port}',
                'https': f'socks5h://127.0.0.1:{local_port}'
            }
            start_time = time.time()
            response = requests.get(
                TEST_LINK,
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            elapsed = time.time() - start_time
            if response.status_code == 200:
                log_queue.put(('success', server_info, f"{elapsed:.2f}s (Attempt {attempt+1})"))
                break
            else:
                if attempt == MAX_RETRIES - 1:
                    log_queue.put(('failure', server_info, f"HTTP {response.status_code}"))
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                log_queue.put(('failure', server_info, f"Test error: {str(e)}"))
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            if config_path and os.path.exists(config_path):
                try:
                    os.remove(config_path)
                except Exception:
                    pass

def check_v2ray_installed():
    try:
        result = subprocess.run(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), 'version'],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            check=True
        )
        output = result.stdout.decode('utf-8')
        version = output.split()[1]
        return version
    except Exception:
        return None

def get_latest_version():
    try:
        response = requests.get(
            'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
            timeout=5
        )
        response.raise_for_status()
        return response.json()['tag_name'].lstrip('v')
    except requests.exceptions.RequestException:
        return None

def install_v2ray():
    try:
        os_type = platform.system().lower()
        base_url = 'https://github.com/v2fly/v2ray-core/releases/latest/download'
        if os_type == 'linux':
            machine = platform.machine().lower()
            if 'aarch64' in machine or 'arm64' in machine:
                url = f'{base_url}/v2ray-linux-arm64.zip'
            else:
                url = f'{base_url}/v2ray-linux-64.zip'
        elif os_type == 'windows':
            url = f'{base_url}/v2ray-windows-64.zip'
        else:
            raise OSError(f"Unsupported OS: {os_type}")
        if os.path.exists(V2RAY_DIR):
            shutil.rmtree(V2RAY_DIR, ignore_errors=True)
        os.makedirs(V2RAY_DIR, exist_ok=True)
        try:
            import zipfile
            import urllib.request
            zip_path, _ = urllib.request.urlretrieve(url)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(V2RAY_DIR)
            v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
            os.chmod(v2ray_path, 0o755)
            result = subprocess.run(
                [v2ray_path, 'version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                raise RuntimeError(f"V2Ray install failed: {result.stderr.decode()}")
        except Exception as e:
            sys.exit(f"Installation failed: {e}")
    except Exception as e:
        logging.critical(f"V2Ray installation failed: {e}")
        sys.exit(1)

def logger_thread(log_queue):
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    channels_dir = os.path.join(TESTED_SERVERS_DIR, 'Channels')
    main_dir = TESTED_SERVERS_DIR
    report_file = os.path.join(LOGS_DIR, 'channel_stats.log')
    
    os.makedirs(protocols_dir, exist_ok=True)
    os.makedirs(channels_dir, exist_ok=True)
    os.makedirs(main_dir, exist_ok=True)

    # Initialize tracking structures
    channel_stats = defaultdict(lambda: {
        'total': 0,
        'active': 0,
        'skipped': 0,
        'failed': 0,
        'working_links': []
    })
    completed_files = set()

    try:
        # Open report file
        with open(report_file, 'w', encoding='utf-8') as report_fd:
            report_fd.write("Channel Statistics Report\n")
            report_fd.write("="*50 + "\n")
            report_fd.write("Real-time Updates:\n\n")

            while True:
                record = log_queue.get()
                if record is None:
                    # Generate final ranking
                    sorted_channels = sorted(
                        channel_stats.items(),
                        key=lambda x: (x[1]['active']/x[1]['total'])*100 if x[1]['total'] > 0 else 0,
                        reverse=True
                    )
                    
                    # Write final report
                    report_fd.write("\n\nFinal Ranking by Success Rate:\n")
                    report_fd.write(f"{'Channel':<45} | {'Total':<6} | {'Active':<6} | {'Failed':<6} | {'Success%':<8}\n")
                    report_fd.write("-"*80 + "\n")
                    
                    for channel, stats in sorted_channels:
                        if stats['total'] > 0:
                            telegram_channel = f"https://t.me/s/{channel}"
                            percent = (stats['active'] / stats['total']) * 100
                            report_fd.write(
                                f"{telegram_channel:<45} | {stats['total']:<6} | "
                                f"{stats['active']:<6} | {stats['failed']:<6} | {percent:.1f}%\n"
                            )
                    break

                status, server_info, message = record
                source_file = server_info['source_file']
                proto = server_info.get('protocol', 'unknown').lower()

                # Update statistics
                if status == 'received':
                    channel_stats[source_file]['total'] += 1
                    continue
                
                if status == 'success':
                    channel_stats[source_file]['active'] += 1
                    channel_stats[source_file]['working_links'].append(server_info['original_link'])
                    
                    # Save to protocol-specific file
                    protocol_file = os.path.join(protocols_dir, f"{proto}.txt")
                    with open(protocol_file, 'a', encoding='utf-8') as pf:
                        pf.write(f"{server_info['original_link']}\n")
                    
                    # Save to main working servers file
                    main_file = os.path.join(main_dir, 'all_working_servers.txt')
                    with open(main_file, 'a', encoding='utf-8') as mf:
                        mf.write(f"{server_info['original_link']}\n")
                        
                elif status == 'skip':
                    channel_stats[source_file]['skipped'] += 1
                elif status == 'failure':
                    channel_stats[source_file]['failed'] += 1

                # Write channel file when complete
                if (channel_stats[source_file]['active'] + 
                    channel_stats[source_file]['skipped'] + 
                    channel_stats[source_file]['failed']) == channel_stats[source_file]['total']:
                    
                    total = channel_stats[source_file]['total']
                    active = channel_stats[source_file]['active']
                    skipped = channel_stats[source_file]['skipped']
                    failed = channel_stats[source_file]['failed']
                    percent = (active / total) * 100 if total > 0 else 0
                    telegram_channel = f"https://t.me/s/{source_file}"
                    
                    # Write to report
                    report_fd.write(
                        f"{telegram_channel:<45} | Total: {total:<4} | "
                        f"Active: {active:<6} | Failed: {failed:<4} | Percent: {percent:.1f}%\n"
                    )
                    report_fd.flush()
                    
                    # Write to channel file
                    output_path = os.path.join(channels_dir, source_file)
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(f"# Statistics: Total={total} Active={active} Failed={failed} Percent={percent:.1f}%\n")
                        for link in channel_stats[source_file]['working_links']:
                            f.write(f"{link}\n")
                    
                    completed_files.add(source_file)

    except Exception as e:
        logging.error(f"Error in logger thread: {str(e)}")



if __name__ == "__main__":
   
    channels_file = CHANNELS_FILE
    try:
        # Read and normalize URLs
        with open(channels_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip()]
        
        # Normalize URLs and remove duplicates
        normalized_urls = list({normalize_telegram_url(url) for url in raw_urls})
        
        # Sort and save back to file
        normalized_urls.sort()
        with open(channels_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(normalized_urls))
        
        print(f"✅ Found {len(normalized_urls)} unique channels (standardized)")
        
    except Exception as e:
        print(f"❌ Channel list error: {e}")
        sys.exit(1)

    # Batch processing with rate limiting
    for idx, channel in enumerate(normalized_urls, 1):
        success, _ = process_channel(channel)
        print(f"⌛ Processed {idx}/{len(normalized_urls)} {channel} ")
        if idx % BATCH_SIZE == 0:
            print(f"⏳ Processed {idx}/{len(normalized_urls)} channels, pausing for {SLEEP_TIME} s 🕐")
            time.sleep(SLEEP_TIME)

    print("🌍 Starting geographical analysis...")
    country_data = process_geo_data()
    
    # Generate final reports
    channel_stats = get_channel_stats()
    save_extraction_data(channel_stats, country_data)

    current_counts, _ = get_current_counts()
    print("\n✅ Extraction Complete")
    print(f"📁 Protocols: {PROTOCOLS_DIR}")
    print(f"🗺 Regions: {REGIONS_DIR}")
    print(f"📄 Merged : {MERGED_DIR}")
    print(f"📂 Channels: {CHANNELS_DIR}")
    print(f"\n📊 Final Statistics:")
    print(f"🎉 Total Servers: {current_counts['total']}")

    print(f"✅ Successful Geo-IP Resolutions: {current_counts['successful']}")
    print(f"❌ Failed Geo-IP Resolutions: {current_counts['failed']}")

    
    logging.info("Cleaning previous data... 📂❌")
    clean_directory(TESTED_SERVERS_DIR)
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Channels'), exist_ok=True)
    sys.stdout.reconfigure(encoding='utf-8')
    logging.info("Starting server tester")

    # Load servers from channel files
    channel_files = [f for f in os.listdir(CHANNELS_DIR) if f.endswith('.txt')]
    if not channel_files:
        logging.error("😐 No channel files found in Channels directory")
        sys.exit(1)

    all_servers = []
    for channel_file in channel_files:
        file_path = os.path.join(CHANNELS_DIR, channel_file)
        servers = read_links_from_file(file_path)
        for link in servers:
            try:
                parsed = urlparse(link)
                proto = parsed.scheme.lower()
                if proto not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[proto]:
                    continue
                try:
                    if proto == 'vless':
                        server_info = parse_vless_link(link)
                    elif proto == 'vmess':
                        server_info = parse_vmess_link(link)
                    elif proto == 'trojan':
                        server_info = parse_trojan_link(link)
                    elif proto == 'ss':
                        server_info = parse_ss_link(link)
                    server_info['source_file'] = channel_file
                    all_servers.append(server_info)
                except Exception as e:
                    logging.error(f"Invalid {proto.upper()} link in {channel_file}: {link[:60]}... Error: {str(e)}")
            except Exception as e:
                logging.error(f"General error processing link: {str(e)}")

    if not all_servers:
        logging.error("No valid servers to test")
        sys.exit(1)

    logging.info(f"Loaded {len(all_servers)} servers from {len(channel_files)} channel files")

    # Test servers
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS)
    args = parser.parse_args()

    logging.info("Protocol configuration:")
    for proto, enabled in ENABLED_PROTOCOLS.items():
        logging.info(f"  {proto.upper():<10}: {'Enabled' if enabled else 'Disabled'}")

    # Check V2Ray installation
    installed_version = check_v2ray_installed()
    latest_version = get_latest_version()
    if not installed_version or (latest_version and installed_version != latest_version):
        logging.info("⏳ Installing V2Ray...")
        install_v2ray()
    else:
        logging.info(f" Using V2Ray {installed_version}")

    # Start testing
    log_queue = queue.Queue()
    logger = threading.Thread(target=logger_thread, args=(log_queue,))
    logger.start()

    # First send all server info to initialize tracking
    for server_info in all_servers:
        log_queue.put(('received', server_info, None))

    with ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        futures = []
        for server_info in all_servers:
            try:
                proto = server_info['protocol']
                if proto not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[proto]:
                    log_queue.put(('skip', server_info, "Protocol disabled"))
                    continue
                local_port = get_next_port()
                config = generate_config(server_info, local_port)
                futures.append(executor.submit(test_server, server_info, config, local_port, log_queue))
            except Exception as e:
                log_queue.put(('failure', server_info, f"Config error: {str(e)}"))

        for future in futures:
            future.result()

    log_queue.put(None)
    logger.join()
    logging.info("Testing completed")
