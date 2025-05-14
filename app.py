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
import base64
import binascii
from urllib.parse import urlparse, parse_qs, unquote
from base64 import urlsafe_b64decode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')
# Organized directory structure for data storage
PROTOCOLS_DIR = os.path.join("Servers", "Protocols")
REGIONS_DIR = os.path.join("Servers", "Regions")
REPORTS_DIR = os.path.join("logs")
MERGED_DIR = os.path.join("Servers", "Merged")
CHANNELS_DIR = os.path.join("Servers", "Channels")
CHANNELS_FILE = "data/telegram_sources.txt"
LOG_FILE = os.path.join(REPORTS_DIR, "extraction_report.log")
GEOIP_DATABASE_PATH = Path("data/db/GeoLite2-Country.mmdb")
MERGED_SERVERS_FILE = os.path.join(MERGED_DIR, "merged_servers.txt")


SLEEP_TIME = 3
BATCH_SIZE = 10
FETCH_CONFIG_LINKS_TIMEOUT = 15
MAX_CHANNEL_SERVERS = 1000
MAX_PROTOCOL_SERVERS = 10000
MAX_REGION_SERVERS = 10000
MAX_MERGED_SERVERS = 100000

V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
V2RAY_DIR = os.path.join(BASE_DIR, 'data', 'v2ray')
TESTED_SERVERS_DIR = os.path.join(BASE_DIR, 'Tested_Servers')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 20
START_PORT = 10000
REQUEST_TIMEOUT = 30
PROCESS_START_WAIT = 15
REALTIME_UPDATE_INTERVAL = 25  
ENABLED_PROTOCOLS = {
    'vless': True,
    'vmess': False,
    'trojan': False,
    'ss': False,
    'hysteria': False,
    'hysteria2': False,
    'tuic': False,
    'wireguard': False,
    'warp': False,
}

channel_test_stats = defaultdict(
    lambda: {'total_prepared': 0, 'active': 0, 'failed': 0, 'skip': 0})


def clean_directory(dir_path):
    if os.path.exists(dir_path):
        is_v2ray_dir = os.path.abspath(dir_path) == os.path.abspath(V2RAY_DIR)
        if is_v2ray_dir:  
            logging.info(f"Selectively cleaning V2Ray directory: {dir_path}")
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                if filename == V2RAY_BIN or filename.lower().endswith(('.dat', '.db', 'geoip.dat', 'geosite.dat')):
                    logging.debug(
                        f"Skipping deletion of essential V2Ray file: {file_path}")
                    continue
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    logging.error(
                        f"Failed to delete {file_path} during V2Ray dir selective clean: {str(e)}")
            os.makedirs(dir_path, exist_ok=True)
            return
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
        
logging.info("Cleaning extraction directories (Servers folder)...")
if os.path.exists(os.path.join(BASE_DIR, "Servers")):
    shutil.rmtree(os.path.join(BASE_DIR, "Servers"))
    logging.info(
        f"Removed existing directory: {os.path.join(BASE_DIR, 'Servers')}")
for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR,
                  V2RAY_DIR, TESTED_SERVERS_DIR, LOGS_DIR,
                  os.path.join(TESTED_SERVERS_DIR, 'Protocols'),
                  os.path.join(TESTED_SERVERS_DIR, 'Channels')]:
    os.makedirs(directory, exist_ok=True)

PATTERNS = {
    'vmess': r'(?<![a-zA-Z0-9_])vmess://[^\s<>]+',
    'vless': r'(?<![a-zA-Z0-9_])vless://[^\s<>]+',
    'trojan': r'(?<![a-zA-Z0-9_])trojan://[^\s<>]+',
    'hysteria': r'(?<![a-zA-Z0-9_])hysteria://[^\s<>]+',
    'hysteria2': r'(?<![a-zA-Z0-9_])hysteria2://[^\s<>]+',
    'tuic': r'(?<![a-zA-Z0-9_])tuic://[^\s<>]+',
    'ss': r'(?<![a-zA-Z0-9_])ss://[^\s<>]+',
    'wireguard': r'(?<![a-zA-Z0-9_])wireguard://[^\s<>]+',
    'warp': r'(?<![a-zA-Z0-9_])warp://[^\s<>]+'
}


def normalize_telegram_url(url):
    """Normalize various Telegram URL formats to https://t.me/s/ format.
    
    Args:
        url: Input URL string to normalize
        
    Returns:
        Normalized URL in https://t.me/s/ format or empty string for invalid URLs
    """
    if not url:
        return ""
    
    url = url.strip()
    
    # Handle bare username cases (e.g., "Free_HTTPCustom")
    if not any(url.startswith(prefix) for prefix in ["http://", "https://", "t.me/", "@"]):
        if "/" not in url:  # Confirm it's just a channel name without paths
            return f"https://t.me/s/{url}"
    
    # Convert t.me/ links to https://t.me/s/
    if url.startswith("t.me/"):
        url = f"https://{url}"
    
    # Convert @username format to https://t.me/s/username
    if url.startswith("@"):
        return f"https://t.me/s/{url[1:]}"
    
    # Process full https://t.me/ URLs
    if url.startswith("https://t.me/"):
        parts = url.split('/')
        if len(parts) >= 4:
            channel_candidate = parts[3]
            if channel_candidate == 's':
                if len(parts) > 4 and parts[4]:  # Valid /s/ link
                    return url
                return ""  # Invalid /s/ link like https://t.me/s/
            else:  # Convert to /s/ format
                return f"https://t.me/s/{'/'.join(parts[3:])}"
        return ""  # Invalid URL structure
    
    return url  # Return as-is if already in /s/ format or other valid format 

def extract_channel_name(url):
    try:
        parsed_url = urlparse(url)
        path_parts = [part for part in parsed_url.path.split('/') if part]
        if path_parts:
            if path_parts[0] == 's' and len(path_parts) > 1:
                return path_parts[1]
            return path_parts[0]
    except Exception:
        pass
    name = url.split('/')[-1] if '/' in url else url
    return name if name else "unknown_channel"


def count_servers_in_file(file_path):
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip() and not line.strip().startswith('#')])
    except Exception as e:
        logging.error(f"❌ Error counting servers in {file_path}: {e}")
        return 0


def get_current_counts():
    counts = {}
    for proto in PATTERNS:
        counts[proto] = count_servers_in_file(
            os.path.join(PROTOCOLS_DIR, f"{proto}.txt"))
    counts['total'] = count_servers_in_file(MERGED_SERVERS_FILE)
    regional_servers = 0
    country_data = {}
    if os.path.exists(REGIONS_DIR):
        for region_file in Path(REGIONS_DIR).glob("*.txt"):
            country = region_file.stem
            count = count_servers_in_file(region_file)
            country_data[country] = count
            regional_servers += count
    counts['successful'] = regional_servers
    counts['failed'] = max(0, counts['total'] - regional_servers)
    return counts, country_data


def get_channel_stats():
    channel_stats = {}
    if os.path.exists(CHANNELS_DIR):
        for channel_file in Path(CHANNELS_DIR).glob("*.txt"):
            channel_stats[channel_file.stem] = count_servers_in_file(
                channel_file)
    return channel_stats


def save_extraction_data(channel_stats_data, country_data_map):
    current_counts, country_stats_map_local = get_current_counts()
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers (Merged): {current_counts['total']}\n")
            log.write(
                f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(
                f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats_map_local.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")
            log.write("\n=== Server Type Summary ===\n")
            valid_protocols = {p: current_counts.get(p, 0) for p in PATTERNS}
            for proto, count in sorted(valid_protocols.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{proto.upper():<20} : {count}\n")
            log.write("\n=== Channel Statistics (Extraction) ===\n")
            if not channel_stats_data:
                log.write("No channel data available.\n")
            else:
                for channel, total in sorted(channel_stats_data.items(), key=lambda x: x[1], reverse=True):
                    log.write(f"{channel:<30}: {total}\n")
    except Exception as e:
        logging.error(f"❌ Error writing extraction report to {LOG_FILE}: {e}")


def fetch_config_links(url):
    logging.info(f"Fetching configs from: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(
            url, timeout=FETCH_CONFIG_LINKS_TIMEOUT, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        message_containers = soup.select(
            'div.tgme_widget_message_bubble, div.tgme_widget_message_text')
        code_blocks = soup.find_all(['code', 'pre'])
        configs = {proto: set() for proto in PATTERNS}
        configs["all"] = set()
        for code_tag in code_blocks:
            clean_text = re.sub(r'(^`{1,3}|`{1,3}$)', '', code_tag.get_text(
                '\n').strip(), flags=re.MULTILINE).strip()
            for line in clean_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                for proto, pattern in PATTERNS.items():
                    valid_matches = set()
                    matches = re.findall(pattern, line)
                    if matches:
                        valid_matches = {
                            m for m in matches if urlparse(m).scheme == proto}
                    if valid_matches:
                        configs[proto].update(valid_matches)
                        configs["all"].update(valid_matches)
        for container in message_containers:
            for line in container.get_text(separator='\n', strip=True).splitlines():
                line = line.strip()
                if not line:
                    continue
                for proto, pattern in PATTERNS.items():
                    valid_matches = set()
                    matches = re.findall(pattern, line)
                    if matches:
                        valid_matches = {
                            m for m in matches if urlparse(m).scheme == proto}
                    if valid_matches:
                        configs[proto].update(valid_matches)
                        configs["all"].update(valid_matches)
        final_configs = {k: list(v) for k, v in configs.items() if v}
        logging.info(
            f"Found {len(final_configs.get('all', []))} potential configs in {url}")
        return final_configs
    except requests.exceptions.Timeout:
        logging.error(f"Timeout fetching {url}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Connection error for {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Scraping error for {url}: {e}")
        return None


def load_existing_configs():
    existing = {proto: set() for proto in PATTERNS}
    existing["merged"] = set()
    for proto in PATTERNS:
        p_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        if os.path.exists(p_file):
            try:
                with open(p_file, 'r', encoding='utf-8') as f:
                    existing[proto] = {l.strip() for l in f if l.strip()}
            except Exception as e:
                logging.error(f"Error reading {p_file}: {e}")
    m_file = MERGED_SERVERS_FILE
    if os.path.exists(m_file):
        try:
            with open(m_file, 'r', encoding='utf-8') as f:
                existing['merged'] = {l.strip() for l in f if l.strip()}
        except Exception as e:
            logging.error(f"Error reading {m_file}: {e}")
    return existing


def trim_file(file_path, max_lines):
    if not os.path.exists(file_path) or max_lines <= 0:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        valid_lines = [line for line in lines if line.strip()]
        if len(valid_lines) > max_lines:
            logging.info(
                f"Trimming {file_path} from {len(valid_lines)} to {max_lines} lines.")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(l if l.endswith('\n') else l +
                             '\n' for l in valid_lines[:max_lines])
    except Exception as e:
        logging.error(f"Error trimming {file_path}: {e}")


def process_channel(url):
    channel_name = extract_channel_name(url)
    if not channel_name or channel_name == "unknown_channel":
        return 0, 0
    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    logging.info(f"Processing channel: {channel_name} ({url})")
    existing_configs = load_existing_configs()
    configs = fetch_config_links(url)
    if configs is None or not configs.get("all"):
        logging.info(f"No new links or fetch failed for {channel_name}.")
        Path(channel_file).touch(exist_ok=True)
        return 1 if configs is not None else 0, 0
    all_fetched = set(configs["all"])
    existing_channel_cfgs = set()
    if os.path.exists(channel_file):
        try:
            with open(channel_file, 'r', encoding='utf-8') as f:
                existing_channel_cfgs = {l.strip() for l in f if l.strip()}
        except Exception as e:
            logging.error(f"Error reading {channel_file}: {e}")
    new_for_channel = all_fetched - existing_channel_cfgs
    if new_for_channel:
        updated_ch_cfgs = list(new_for_channel) + list(existing_channel_cfgs)
        try:
            with open(channel_file, 'w', encoding='utf-8') as f:
                seen = set()
                unique_lines = [l for l in updated_ch_cfgs if not (
                    l in seen or seen.add(l))]
                f.write('\n'.join(unique_lines[:MAX_CHANNEL_SERVERS]) + '\n')
            trim_file(channel_file, MAX_CHANNEL_SERVERS)
        except Exception as e:
            logging.error(f"Error writing {channel_file}: {e}")
    elif not os.path.exists(channel_file):
        Path(channel_file).touch(exist_ok=True)
    new_global_total = 0
    for proto, links in configs.items():
        if proto == "all" or not links:
            continue
        new_global_proto = set(links) - existing_configs.get(proto, set())
        if not new_global_proto:
            continue
        proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        try:
            updated_proto_lns = list(new_global_proto) + \
                list(existing_configs.get(proto, set()))
            with open(proto_path, 'w', encoding='utf-8') as f:
                seen = set()
                unique_lines = [l for l in updated_proto_lns if not (
                    l in seen or seen.add(l))]
                f.write('\n'.join(unique_lines[:MAX_PROTOCOL_SERVERS]) + '\n')
            trim_file(proto_path, MAX_PROTOCOL_SERVERS)
            existing_configs[proto].update(new_global_proto)
        except Exception as e:
            logging.error(f"Error writing {proto_path}: {e}")
        new_for_merged = new_global_proto - \
            existing_configs.get('merged', set())
        if new_for_merged:
            try:
                updated_merged_lns = list(
                    new_for_merged) + list(existing_configs.get('merged', set()))
                with open(MERGED_SERVERS_FILE, 'w', encoding='utf-8') as f:
                    seen = set()
                    unique_lines = [l for l in updated_merged_lns if not (
                        l in seen or seen.add(l))]
                    f.write(
                        '\n'.join(unique_lines[:MAX_MERGED_SERVERS]) + '\n')
                trim_file(MERGED_SERVERS_FILE, MAX_MERGED_SERVERS)
                existing_configs['merged'].update(new_for_merged)
                new_global_total += len(new_for_merged)
            except Exception as e:
                logging.error(f"Error updating {MERGED_SERVERS_FILE}: {e}")
    logging.info(
        f"Channel {channel_name}: {len(new_for_channel)} new for channel file, {new_global_total} new globally.")
    return 1, new_global_total


def download_geoip_database():
    """Downloads GeoLite2-Country database from a reliable source."""
    # Using the direct MaxMind link if possible, otherwise fallback or manual download needed.
    # Official registration might be required for direct downloads now.
    # This example uses a common community mirror URL. Replace if needed.
    GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb" # Check if this URL is still active
    GEOIP_DIR = GEOIP_DATABASE_PATH.parent # Get the parent directory "data/db"

    logging.info(f"Attempting to download GeoIP database from {GEOIP_URL}...")
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)

        # Use stream=True for potentially large files and timeout
        with requests.get(GEOIP_URL, timeout=60, stream=True) as response:
            response.raise_for_status()
            # Check content length if available
            total_size = int(response.headers.get('content-length', 0))
            block_size = 8192 # 8KB chunks
            wrote = 0
            with open(GEOIP_DATABASE_PATH, 'wb') as f:
                for chunk in response.iter_content(chunk_size=block_size):
                    f.write(chunk)
                    wrote += len(chunk)
                    if total_size > 0:
                        # Optional: Print progress
                        # progress = (wrote / total_size) * 100
                        # print(f"Downloading GeoIP DB: {progress:.1f}%", end='\r')
                        pass
            # print() # Newline after progress

            # Basic validation: check if file size is reasonable (e.g., > 1MB)
            if GEOIP_DATABASE_PATH.stat().st_size > 1024 * 1024:
                logging.info("✅ GeoLite2 database downloaded successfully.")
                return True
            else:
                logging.error("❌ Downloaded GeoIP database seems too small. Deleting.")
                GEOIP_DATABASE_PATH.unlink(missing_ok=True)
                return False

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Failed to download GeoIP database: {e}")
        # Clean up potentially incomplete file
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False
    except Exception as e:
        logging.error(f"❌ An unexpected error occurred during GeoIP download: {e}")
        GEOIP_DATABASE_PATH.unlink(missing_ok=True)
        return False


def process_geo_data():
    if not GEOIP_DATABASE_PATH.exists() or GEOIP_DATABASE_PATH.stat().st_size < 1024 * 1024:
        if not download_geoip_database():
            logging.error("❌ Cannot perform GeoIP.")
            return {}
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except Exception as e:
        logging.error(f"❌ Error opening GeoIP DB: {e}")
        return {}
    country_configs = defaultdict(list)
    failed_lookups = 0
    processed = 0
    if os.path.exists(REGIONS_DIR):
        for rf in Path(REGIONS_DIR).glob("*.txt"):
            try:
                rf.unlink()
            except OSError as e:
                logging.error(f"Error deleting {rf}: {e}")
    else:
        os.makedirs(REGIONS_DIR)
    configs = []
    if os.path.exists(MERGED_SERVERS_FILE):
        try:
            with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                configs = [l.strip() for l in f if l.strip()]
        except Exception as e:
            logging.error(f"Error reading merged for GeoIP: {e}")
    if not configs:
        logging.warning("No merged configs for GeoIP.")
        if geo_reader:
            geo_reader.close()
        return {}
    for config in configs:
        processed += 1
        ip = None
        country = "Unknown"
        try:
            parsed = urlparse(config)
            if parsed.scheme in ['vless', 'trojan', 'hysteria', 'hysteria2', 'tuic']:
                ip = parsed.hostname
            elif parsed.scheme == 'vmess':
                try:
                    vmess_json_str = urlsafe_b64decode(
                        parsed.netloc + parsed.path + '==').decode('utf-8')
                    vmess_data = json.loads(vmess_json_str)
                    ip = vmess_data.get('add')
                except:
                    pass
            elif parsed.scheme == 'ss':
                ip = parsed.hostname
            if ip:
                try:
                    resp = geo_reader.country(ip)
                    country = resp.country.iso_code or resp.country.name or "Unknown"
                except geoip2.errors.AddressNotFoundError:
                    failed_lookups += 1
                    country = "Unknown"
                except Exception:
                    failed_lookups += 1
                    country = "Unknown"
            else:
                failed_lookups += 1
        except:
            failed_lookups += 1
        country_configs[country].append(config)
    if geo_reader:
        geo_reader.close()
    country_counts = {}
    for country, c_list in country_configs.items():
        country_counts[country] = len(c_list)
        try:
            with open(os.path.join(REGIONS_DIR, f"{country.replace(' ', '_')}.txt"), 'w', encoding='utf-8') as f:
                f.write('\n'.join(c_list[:MAX_REGION_SERVERS]) + '\n')
        except Exception as e:
            logging.error(f"Error writing region file for {country}: {e}")
    logging.info(
        f"GeoIP done. Processed: {processed}, Successful: {processed - failed_lookups}, Failed: {failed_lookups}")
    return dict(country_counts)


class CleanFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, 'clean_output'):
            if record.levelno == logging.INFO:
                return f"{record.msg}"
            elif record.levelno >= logging.WARNING:
                return f"{record.levelname}: {record.msg}"
        return super().format(record)


if not logging.getLogger().hasHandlers():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    cf = CleanFormatter()
    ch.addFilter(lambda r: setattr(r, 'clean_output', True) or True)
    ch.setFormatter(cf)
    logger.addHandler(ch)
    fh = logging.FileHandler(os.path.join(
        LOGS_DIR, 'testing_debug.log'), encoding='utf-8')
    ff = logging.Formatter(
        '%(asctime)s-%(levelname)s-%(threadName)s- %(message)s')
    fh.setFormatter(ff)
    logger.addHandler(fh)

try:
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests.packages.urllib3.disable_verify()

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
        with open(file_path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
    except FileNotFoundError:
        logging.debug(f"File not found during read: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading links from {file_path}: {e}")
        return []


def parse_vless_link(link):
    parsed = urlparse(link)
    uuid = parsed.username
    query = parse_qs(parsed.query)
    hostname = parsed.hostname
    if not (parsed.scheme == 'vless' and hostname and uuid and
            re.match(r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$', uuid, re.I)):
        raise ValueError(f"Invalid VLESS link structure: {link}")
    port = parsed.port or (443 if query.get('security', [''])[
                           0] in ['tls', 'reality'] else 80)
    sec = query.get('security', ['none'])[0] or 'none'
    net = query.get('type', ['tcp'])[0] or 'tcp'
    sni = query.get('sni', [hostname])[0] or hostname
    return {'original_link': link, 'protocol': 'vless', 'uuid': uuid.replace('-', ''), 'host': hostname, 'port': int(port),
            'security': sec, 'encryption': query.get('encryption', ['none'])[0] or 'none', 'network': net,
            'ws_path': query.get('path', ['/'])[0] if net == 'ws' else '/',
            'ws_host': query.get('host', [sni])[0] if net == 'ws' else sni,
            'sni': sni, 'pbk': query.get('pbk', [''])[0] if sec == 'reality' else '',
            'sid': query.get('sid', [''])[0] if sec == 'reality' else '',
            'fp': query.get('fp', [''])[0] if sec == 'reality' else '',
            'alpn': [v.strip() for v in query.get('alpn', [''])[0].split(',') if v.strip()],
            'flow': query.get('flow', [''])[0]}


def parse_vmess_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vmess':
        raise ValueError(f"Invalid VMESS scheme: {link}")
    try:
        base64_part = parsed.netloc + parsed.path
        json_str = urlsafe_b64decode(
            base64_part + '=' * ((4 - len(base64_part) % 4) % 4)).decode('utf-8')
        data = json.loads(json_str)
    except Exception as e:
        raise ValueError(f"VMess JSON decode error for {link}: {e}")
    host = data.get('add')
    port = int(data.get('port', 0))
    uuid = data.get('id')
    if not (host and port and uuid):
        raise ValueError(f"VMess missing host/port/id in {link}")
    net = data.get('net', 'tcp') or 'tcp'
    tls = data.get('tls', 'none') or 'none'
    return {'original_link': link, 'protocol': 'vmess', 'uuid': uuid, 'host': host, 'port': port, 'network': net,
            'security': tls, 'ws_path': data.get('path', '/') if net == 'ws' else '/',
            'ws_host': data.get('host', host) if net == 'ws' else host,
            'sni': data.get('sni', data.get('host', host) if tls == 'tls' else ''),
            'alter_id': int(data.get('aid', 0)), 'encryption': data.get('scy', 'auto') or 'auto'}


def parse_trojan_link(link):
    parsed = urlparse(link)
    passwd = parsed.username
    host = parsed.hostname
    port = parsed.port
    query = parse_qs(parsed.query)
    if not (parsed.scheme == 'trojan' and passwd and host and port):
        raise ValueError(f"Invalid Trojan link structure: {link}")
    sec = query.get('security', ['tls'])[0] or 'tls'
    sni = query.get('sni', [host])[0] or host
    net = query.get('type', ['tcp'])[0] or 'tcp'
    alpn_str = query.get('alpn', ['h2,http/1.1'])[0]
    alpn = [v.strip() for v in alpn_str.split(',') if v.strip()]
    return {'original_link': link, 'protocol': 'trojan', 'password': passwd, 'host': host, 'port': int(port),
            'security': sec, 'sni': sni, 'alpn': alpn, 'network': net,
            'ws_path': query.get('path', ['/'])[0] if net == 'ws' else '/',
            'ws_host': query.get('host', [sni])[0] if net == 'ws' else sni}


def parse_ss_link(link):
    parsed = urlparse(link)
    host = parsed.hostname
    port = parsed.port
    if not (parsed.scheme == 'ss' and host and port):
        raise ValueError(f"Invalid SS host/port in link: {link}")
    name = parsed.fragment or f"ss_{host}"
    userinfo_raw = parsed.username
    method, password = None, None
    if not userinfo_raw and '@' in parsed.netloc:
        userinfo_raw = parsed.netloc.split('@')[0]
    if not userinfo_raw:
        try:
            b64_part = parsed.netloc.split('#')[0]
            b64_part_padded = b64_part + '=' * ((4 - len(b64_part) % 4) % 4)
            decoded = urlsafe_b64decode(b64_part_padded).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                raise ValueError(
                    "SS base64 netloc part does not contain 'method:password'")
        except (binascii.Error, UnicodeDecodeError, ValueError) as e:
            raise ValueError(f"SS netloc base64 parse error for '{link}': {e}")
    else:
        userinfo_decoded_str = unquote(userinfo_raw)
        try:
            userinfo_padded = userinfo_decoded_str + '=' * \
                ((4 - len(userinfo_decoded_str) % 4) % 4)
            decoded = urlsafe_b64decode(userinfo_padded).decode('utf-8')
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                if ':' in userinfo_decoded_str:
                    method, password = userinfo_decoded_str.split(':', 1)
                else:
                    raise ValueError(
                        "SS userinfo b64 decoded but no colon, and plain also no colon")
        except (binascii.Error, UnicodeDecodeError):
            if ':' in userinfo_decoded_str:
                method, password = userinfo_decoded_str.split(':', 1)
            else:
                raise ValueError(
                    "Could not extract method/password for SS link")
        except Exception as e_inner:
            raise ValueError(
                f"Unexpected SS userinfo processing error for '{link}': {e_inner}")
    if method is None or password is None:
        raise ValueError(
            f"Could not extract method/password for SS link: {link}")
    return {'original_link': link, 'protocol': 'shadowsocks', 'method': method, 'password': password,
            'host': host, 'port': int(port), 'network': 'tcp', 'name': name}


def generate_config(s_info, l_port):
    cfg = {
        "log": {"access": None, "error": None},
        "inbounds": [{
            "port": l_port, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{
            "protocol": s_info['protocol'], "settings": {},
            "streamSettings": {
                "network": s_info.get('network', 'tcp'),
                "security": s_info.get('security', 'none')
            },
            "mux": {"enabled": True, "concurrency": 8}
        }]
    }
    out_s = cfg['outbounds'][0]['settings']
    stream_s = cfg['outbounds'][0]['streamSettings']
    if s_info['protocol'] == 'vless':
        out_s["vnext"] = [{"address": s_info['host'], "port": s_info['port'], "users": [
            {"id": s_info['uuid'], "encryption": s_info['encryption'], "flow": s_info.get('flow', '')}]}]
    elif s_info['protocol'] == 'vmess':
        out_s["vnext"] = [{"address": s_info['host'], "port": s_info['port'], "users": [
            {"id": s_info['uuid'], "alterId": s_info['alter_id'], "security": s_info['encryption']}]}]
    elif s_info['protocol'] == 'trojan':
        out_s["servers"] = [{"address": s_info['host'],
                             "port": s_info['port'], "password": s_info['password']}]
    elif s_info['protocol'] == 'shadowsocks':
        out_s["servers"] = [{"address": s_info['host'], "port": s_info['port'],
                             "method": s_info['method'], "password": s_info['password'], "ota": False}]
    if stream_s['security'] == 'tls':
        tls_settings = {"serverName": s_info.get(
            'sni', s_info['host']), "allowInsecure": True}
        if s_info.get('alpn'):
            tls_settings["alpn"] = s_info['alpn']
        if s_info.get('fp') and s_info.get('fp') != 'none':
            tls_settings["fingerprint"] = s_info['fp']
        stream_s['tlsSettings'] = tls_settings
    elif stream_s['security'] == 'reality':
        if not s_info.get('pbk') or not s_info.get('fp'):
            raise ValueError(
                "REALITY config missing 'pbk' (publicKey) or 'fp' (fingerprint)")
        stream_s['realitySettings'] = {
            "show": False, "fingerprint": s_info['fp'],
            "serverName": s_info.get('sni', s_info['host']),
            "publicKey": s_info['pbk'], "shortId": s_info.get('sid', ''),
            "spiderX": s_info.get('spx', '/')
        }
    if stream_s['network'] == 'ws':
        stream_s['wsSettings'] = {
            "path": s_info.get('ws_path', '/'),
            "headers": {"Host": s_info.get('ws_host', s_info.get('sni', s_info['host']))}
        }
    cfg['outbounds'][0]['streamSettings'] = {
        k: v for k, v in stream_s.items() if v is not None or k in ('network', 'security')
    }
    return cfg


def test_server(s_info, cfg, l_port, log_q):
    proc = None
    cfg_path = None
    success = False
    err_msg = "Test incomplete"
    r_time = -1.0
    try:
        os.makedirs(V2RAY_DIR, exist_ok=True)
        v2_exec = os.path.join(V2RAY_DIR, V2RAY_BIN)
        if not os.path.exists(v2_exec):
            raise FileNotFoundError(f"V2Ray executable not found: {v2_exec}")
        if platform.system() != "Windows" and not os.access(v2_exec, os.X_OK):
            try:
                os.chmod(v2_exec, 0o755)
            except Exception as e:
                raise PermissionError(f"V2Ray chmod failed: {e}")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2)
            cfg_path = f.name
        cmd = [v2_exec, 'run', '--config', cfg_path]
        proc = subprocess.Popen(cmd, cwd=V2RAY_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding='utf-8', close_fds=(platform.system() != 'Windows'))
        try:
            proc.wait(timeout=PROCESS_START_WAIT)
            stderr_output = proc.stderr.read(500)
            raise RuntimeError(
                f"V2Ray process exited prematurely (code {proc.returncode}). Stderr: {stderr_output}...")
        except subprocess.TimeoutExpired:
            pass
        if proc.poll() is not None:
            stderr_output = proc.stderr.read(500)
            raise RuntimeError(
                f"V2Ray process exited unexpectedly after wait (code {proc.returncode}). Stderr: {stderr_output}...")
        proxies = {'http': f'socks5h://127.0.0.1:{l_port}',
                   'https': f'socks5h://127.0.0.1:{l_port}'}
        start_t = time.monotonic()
        try:
            resp = requests.get(TEST_LINK, proxies=proxies, timeout=REQUEST_TIMEOUT,
                                verify=False, headers={'User-Agent': 'ProxyTester/1.0'})
            r_time = time.monotonic() - start_t
            if resp.status_code == 200:
                success = True
                err_msg = f"{resp.status_code} OK"
            else:
                err_msg = f"HTTP Status {resp.status_code}"
        except requests.exceptions.Timeout:
            r_time = time.monotonic() - start_t
            err_msg = f"Request Timeout ({r_time:.1f}s > {REQUEST_TIMEOUT}s)"
        except requests.exceptions.ProxyError as pe:
            err_msg = f"Proxy Error: {str(pe)[:100]}"
        except requests.exceptions.RequestException as e:
            err_msg = f"Request Exception: {str(e)[:100]}"
        log_level = logging.INFO if success else logging.WARNING
        log_symbol = "✅" if success else "⚠️"
        logging.log(log_level, f"{log_symbol} Test {'Success' if success else 'Failed'} ({r_time:.2f}s) - "
                    f"{s_info.get('protocol')} {s_info.get('host')}:{s_info.get('port')} | {err_msg}")
    except Exception as e:
        err_msg = f"Test Setup/Runtime Error: {str(e)[:150]}"
        logging.error(f"❌ Error testing {s_info.get('host', 'N/A')}: {e}",
                      exc_info=True if logger.isEnabledFor(logging.DEBUG) else False)
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.remove(cfg_path)
            except Exception:
                pass
        log_q.put(('success' if success else 'failure', s_info,
                  f"{r_time:.2f}s" if success else err_msg))

def check_v2ray_installed():
    """Checks if V2Ray is installed and returns the version."""
    v2ray_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
    if not os.path.exists(v2ray_path):
        logging.debug("V2Ray executable not found.")
        return None
    try:
         # Ensure executable permission before running
         if platform.system() != "Windows" and not os.access(v2ray_path, os.X_OK):
              logging.warning(f"V2Ray found but not executable, attempting chmod: {v2ray_path}")
              try:
                   os.chmod(v2ray_path, 0o755)
              except Exception as chmod_err:
                   logging.error(f"Failed to make V2Ray executable: {chmod_err}")
                   return None # Cannot run version check

         logging.debug(f"Checking V2Ray version using: {v2ray_path}")
         result = subprocess.run(
             [v2ray_path, 'version'],
             stdout=subprocess.PIPE,
             stderr=subprocess.PIPE,
             encoding='utf-8',
             check=True, # Raise exception on non-zero exit code
             cwd=V2RAY_DIR # Run from V2Ray directory
         )
         output = result.stdout.strip()
         # Example output: "V2Ray 5.8.0 (V2Fly, a community-driven edition) (go1.20.4 linux/amd64)"
         match = re.search(r'V2Ray\s+([\d.]+)', output) # Extract version number
         if match:
             version = match.group(1)
             logging.debug(f"Found V2Ray version: {version}")
             return version
         else:
              logging.warning(f"Could not parse V2Ray version from output: {output}")
              return "unknown" # Indicate installed but version unknown

    except FileNotFoundError:
        logging.debug("V2Ray command failed: File not found (check path and permissions).")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"V2Ray version check failed with error code {e.returncode}. Stderr: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during V2Ray version check: {e}")
        return None


def get_latest_version():
    """Gets the latest V2Ray release tag from GitHub API."""
    try:
        logging.debug("Fetching latest V2Ray version from GitHub API...")
        response = requests.get(
            'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
            timeout=10 # Increased timeout for API call
        )
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        tag_name = data.get('tag_name')
        if tag_name and tag_name.startswith('v'):
            version = tag_name.lstrip('v')
            logging.debug(f"Latest GitHub release tag: {tag_name} -> Version: {version}")
            return version
        else:
             logging.warning(f"Could not find valid tag_name in GitHub API response: {data.get('tag_name')}")
             return None
    except requests.exceptions.Timeout:
         logging.error("Timeout fetching latest V2Ray version from GitHub.")
         return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching latest V2Ray version from GitHub: {e}")
        return None
    except Exception as e:
         logging.error(f"Unexpected error parsing GitHub API response: {e}")
         return None


_latest_release_data_cache = None


def get_github_latest_release_data():
     """Fetches the full data for the latest release."""
     try:
          response = requests.get(
               'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
               timeout=10
          )
          response.raise_for_status()
          return response.json()
     except requests.exceptions.RequestException as e:
          logging.error(f"Failed to fetch latest release data from GitHub: {e}")
          return None


def asset_name_exists(asset_name):
    data = get_github_latest_release_data()
    return any(a.get('name') == asset_name for a in data.get('assets', []))


def get_asset_download_url(asset_name):
    data = get_github_latest_release_data()
    for asset in data.get('assets', []):
        if asset.get('name') == asset_name:
            return asset.get('browser_download_url')
    return None


def install_v2ray():
    """Downloads and extracts the latest V2Ray release."""
    try:
        os_type = platform.system().lower()
        machine = platform.machine().lower()
        logging.info(f"Detected OS: {os_type}, Machine: {machine}")

        # Determine asset filename based on OS and architecture
        asset_name = None
        if os_type == 'linux':
            if 'aarch64' in machine or 'arm64' in machine:
                asset_name = 'v2ray-linux-arm64-v8a.zip' # Check exact name on GitHub releases
                # Fallback if v8a not available
                if not asset_name_exists(asset_name): asset_name = 'v2ray-linux-arm64.zip'
            elif 'armv7' in machine: # 32-bit ARM
                 asset_name = 'v2ray-linux-arm32-v7a.zip' # Check name
                 if not asset_name_exists(asset_name): asset_name = 'v2ray-linux-arm.zip'
            elif '64' in machine: # Assume x86_64
                asset_name = 'v2ray-linux-64.zip'
            else: # Assume 32-bit x86
                 asset_name = 'v2ray-linux-32.zip'

        elif os_type == 'windows':
            if '64' in machine: # Covers amd64, x86_64
                asset_name = 'v2ray-windows-64.zip'
            else: # Assume 32-bit
                asset_name = 'v2ray-windows-32.zip'
        # Add MacOS support if needed
        # elif os_type == 'darwin':
        #     if 'arm64' in machine:
        #         asset_name = 'v2ray-macos-arm64.zip'
        #     else:
        #         asset_name = 'v2ray-macos-64.zip'


        if not asset_name:
            logging.critical(f"Unsupported OS/Architecture combination: {os_type} / {machine}")
            sys.exit(1)

        logging.info(f"Determined V2Ray asset: {asset_name}")

        # Get download URL from GitHub API
        download_url = get_asset_download_url(asset_name)
        if not download_url:
            logging.critical(f"Could not find download URL for asset {asset_name}. Manual installation required.")
            sys.exit(1)

        logging.info(f"Downloading V2Ray from: {download_url}")

        # Clean install directory and download
        # Ensure V2Ray dir exists first for cleaning logic
        os.makedirs(V2RAY_DIR, exist_ok=True)
        clean_directory(V2RAY_DIR) # Clean before downloading
        os.makedirs(V2RAY_DIR, exist_ok=True) # Recreate after cleaning

        try:
            import zipfile
            import urllib.request

            # Download the zip file
            zip_path = os.path.join(V2RAY_DIR, asset_name) # Save zip in V2Ray dir temporarily
            # Use requests for better handling (timeouts, progress)
            with requests.get(download_url, stream=True, timeout=300) as r: # 5 min timeout
                 r.raise_for_status()
                 with open(zip_path, 'wb') as f:
                      for chunk in r.iter_content(chunk_size=8192):
                           f.write(chunk)
            logging.info(f"Downloaded V2Ray archive to {zip_path}")


            # Extract the zip file
            logging.info(f"Extracting {zip_path} to {V2RAY_DIR}...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                 # Extract only necessary files (v2ray, geoip.dat, geosite.dat)
                 # or extract all if structure is simple
                 zip_ref.extractall(V2RAY_DIR)
            logging.info("Extraction complete.")

            # Clean up the zip file
            os.remove(zip_path)
            logging.debug(f"Removed V2Ray archive: {zip_path}")

            # Set executable permission
            v2ray_executable_path = os.path.join(V2RAY_DIR, V2RAY_BIN)
            if platform.system() != 'Windows':
                if os.path.exists(v2ray_executable_path):
                     logging.info(f"Setting executable permission for {v2ray_executable_path}")
                     os.chmod(v2ray_executable_path, 0o755)
                else:
                     # Maybe the executable is in a subdirectory? Find it.
                     found = False
                     for root, dirs, files in os.walk(V2RAY_DIR):
                          if V2RAY_BIN in files:
                               v2ray_executable_path = os.path.join(root, V2RAY_BIN)
                               logging.info(f"Found V2Ray executable at {v2ray_executable_path}")
                               os.chmod(v2ray_executable_path, 0o755)
                               # Optional: Move it to the main V2RAY_DIR?
                               # shutil.move(v2ray_executable_path, os.path.join(V2RAY_DIR, V2RAY_BIN))
                               # shutil.move(os.path.join(root, 'geoip.dat'), os.path.join(V2RAY_DIR, 'geoip.dat'))
                               # shutil.move(os.path.join(root, 'geosite.dat'), os.path.join(V2RAY_DIR, 'geosite.dat'))
                               found = True
                               break
                     if not found:
                           raise RuntimeError(f"V2Ray executable '{V2RAY_BIN}' not found in extracted files.")


            # Verify installation by running version command
            installed_version = check_v2ray_installed()
            if installed_version:
                logging.info(f"✅ V2Ray installation successful. Version: {installed_version}")
            else:
                raise RuntimeError("V2Ray installed but version check failed.")

        except (zipfile.BadZipFile, urllib.error.URLError, requests.exceptions.RequestException) as download_err:
            logging.critical(f"Download or extraction failed: {download_err}")
            # Clean up potentially corrupted install directory
            clean_directory(V2RAY_DIR)
            sys.exit(1)
        except Exception as e:
            logging.critical(f"V2Ray installation failed during setup: {e}")
            clean_directory(V2RAY_DIR)
            sys.exit(1)

    except Exception as e:
        # Catch errors in platform detection or URL finding
        logging.critical(f"V2Ray installation failed: {e}")
        sys.exit(1)

def print_real_time_channel_stats_table(stats_data):
    if not stats_data:
        return
    logging.info("\n--- Real-time Channel Test Statistics ---")
    header = f"{'Channel File/URL':<45} | {'Total':<7} | {'Active':<7} | {'Failed':<7} | {'Skip':<5} | {'Tested':<10} | {'Success%':<8}"
    logging.info(header)
    logging.info("-" * len(header))
    sorted_channels_list = sorted(stats_data.items(), key=lambda item: item[0])
    for channel_filename, stats in sorted_channels_list:
        base_channel_name = os.path.splitext(channel_filename)[0]
        if base_channel_name.replace('_', '').isalnum():
            display_name = f"https://t.me/s/ {base_channel_name}"
        else:
            display_name = channel_filename
        total_prepared = stats['total_prepared']
        active = stats['active']
        failed = stats['failed']
        skip = stats['skip']
        processed_for_channel = active + failed + skip
        active_plus_failed = active + failed
        success_percent = (active / active_plus_failed *
                           100) if active_plus_failed > 0 else 0.0
        logging.info(f"{display_name:<45} | {total_prepared:<7} | {active:<7} | {failed:<7} | {skip:<5} | {processed_for_channel:>3}/{total_prepared:<3}    | {success_percent:>7.1f}%")
    logging.info("--- End Real-time ---")


def logger_thread(log_q):
    global channel_test_stats
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    tested_channels_dir = os.path.join(TESTED_SERVERS_DIR, 'Channels')
    os.makedirs(protocols_dir, exist_ok=True)
    os.makedirs(tested_channels_dir, exist_ok=True)
    working_file = os.path.join(TESTED_SERVERS_DIR, 'working_servers.txt')
    dead_file = os.path.join(TESTED_SERVERS_DIR, 'dead_servers.txt')
    skip_file = os.path.join(TESTED_SERVERS_DIR, 'skipped_servers.txt')
    counts = {'success': 0, 'failure': 0, 'skip': 0, 'received': 0}
    protocol_success_counts = defaultdict(int)
    processed_since_last_rt_update = 0

    # Add this section to write to channel_stats.log
    channel_stats_file = os.path.join(LOGS_DIR, "channel_stats.log")

    try:
        with open(working_file, 'w', encoding='utf-8') as wf, \
                open(dead_file, 'w', encoding='utf-8') as df, \
                open(skip_file, 'w', encoding='utf-8') as sf:
            start_t = time.monotonic()
            total_to_process = 0
            while True:
                try:
                    record = log_q.get(timeout=3.0)
                except queue.Empty:
                    if total_to_process > 0 and sum(counts[s] for s in ['success', 'failure', 'skip']) < total_to_process:
                        prog_processed = sum(counts[s] for s in [
                                             'success', 'failure', 'skip'])
                        prog_elapsed = time.monotonic() - start_t
                        prog_percent = (
                            prog_processed / total_to_process * 100) if total_to_process else 0
                        logging.info(
                            f"⏳ Overall Progress: {prog_processed}/{total_to_process} ({prog_percent:.1f}%) | Time: {prog_elapsed:.1f}s")
                        if channel_test_stats:
                            print_real_time_channel_stats_table(
                                channel_test_stats)
                    continue
                if record is None:
                    logging.info("Logger thread: stop signal received.")
                    break
                status, s_info, msg = record
                if status == 'received':
                    counts['received'] += 1
                    total_to_process = counts['received']
                    continue
                link = s_info.get('original_link', 'N/A')
                proto = s_info.get('protocol', 'unknown').lower()
                source_ch_file = s_info.get(
                    'source_file', 'unknown_channel.txt')
                if status in counts:
                    counts[status] += 1
                if status == 'success':
                    protocol_success_counts[proto] += 1
                if source_ch_file != 'unknown_channel.txt' and source_ch_file in channel_test_stats:
                    if status == 'success':
                        channel_test_stats[source_ch_file]['active'] += 1
                    elif status == 'failure':
                        channel_test_stats[source_ch_file]['failed'] += 1
                    elif status == 'skip':
                        channel_test_stats[source_ch_file]['skip'] += 1
                try:
                    if status == 'success':
                        wf.write(f"{link}\n")
                        wf.flush()
                        with open(os.path.join(protocols_dir, f"{proto}.txt"), 'a', encoding='utf-8') as pf:
                            pf.write(f"{link}\n")
                        if source_ch_file != 'unknown_channel.txt':
                            with open(os.path.join(tested_channels_dir, source_ch_file), 'a', encoding='utf-8') as cf:
                                cf.write(f"{link}\n")
                    elif status == 'failure':
                        df.write(f"{link} | Reason: {msg}\n")
                        df.flush()
                    elif status == 'skip':
                        sf.write(f"{link} | Reason: {msg}\n")
                        sf.flush()
                except Exception as e:
                    logging.error(
                        f"Error writing to output file for {link}: {e}")
                processed_count_overall = sum(
                    counts[s] for s in ['success', 'failure', 'skip'])
                processed_since_last_rt_update += 1
                if processed_since_last_rt_update >= REALTIME_UPDATE_INTERVAL or processed_count_overall == total_to_process:
                    if total_to_process > 0 and channel_test_stats:
                        prog_elapsed = time.monotonic() - start_t
                        prog_percent = (
                            processed_count_overall / total_to_process * 100) if total_to_process else 0
                        logging.info(f"⏳ Overall Progress: {processed_count_overall}/{total_to_process} ({prog_percent:.1f}%) | "
                                     f"Active: {counts['success']} | Failed: {counts['failure']} | Skipped: {counts['skip']} | "
                                     f"Time: {prog_elapsed:.1f}s")
                        print_real_time_channel_stats_table(channel_test_stats)
                        processed_since_last_rt_update = 0

        # Save channel stats to file
        try:
            with open(channel_stats_file, 'w', encoding='utf-8') as f:
                f.write("Channel Statistics Report\n")
                f.write("Real-time Updates:\n")
                for ch_filename, stats in sorted(channel_test_stats.items(), key=lambda x: x[0]):
                    base_ch_name = os.path.splitext(ch_filename)[0]
                    display_name = f"https://t.me/s/ {base_ch_name}" if base_ch_name.replace(
                        '_', '').isalnum() else ch_filename
                    total = stats['total_prepared']
                    active = stats['active']
                    failed = stats['failed']
                    success_percent = (
                        active / (active + failed) * 100) if (active + failed) > 0 else 0.0
                    f.write(f"{display_name.ljust(45)} | Total: {str(total).ljust(5)} | Active: {str(active).ljust(5)} | Failed: {str(failed).ljust(5)} | Percent: {success_percent:.1f}%\n")

                f.write("\nFinal Ranking by Success Rate:\n")
                f.write(
                    "Channel                                       | Total  | Active | Failed | Success%\n")
                ranked_channels = []
                for ch_filename, stats in channel_test_stats.items():
                    base_ch_name = os.path.splitext(ch_filename)[0]
                    display_name = f"https://t.me/s/ {base_ch_name}" if base_ch_name.replace(
                        '_', '').isalnum() else ch_filename
                    total = stats['total_prepared']
                    active = stats['active']
                    failed = stats['failed']
                    success_percent = (
                        active / (active + failed) * 100) if (active + failed) > 0 else 0.0
                    ranked_channels.append(
                        (display_name, total, active, failed, success_percent))

                ranked_channels.sort(key=lambda x: (-x[4], -x[2], x[0]))
                for entry in ranked_channels:
                    f.write(
                        f"{entry[0].ljust(45)} | {str(entry[1]).ljust(6)} | {str(entry[2]).ljust(6)} | {str(entry[3]).ljust(6)} | {entry[4]:>6.1f}%\n")

            logging.info(f"📊 Channel statistics saved to {channel_stats_file}")
        except Exception as e:
            logging.error(f"❌ Error writing channel stats to file: {e}")

    except Exception as e:
        logging.critical(
            f"Critical error in logger thread: {e}", exc_info=True)
    finally:
        logging.info("\n" + "=" * 20 + " Testing Summary " + "=" * 20)
        total_tested_final = sum(counts[s]
                                 for s in ['success', 'failure', 'skip'])
        logging.info(
            f"Total Servers Received for Testing: {counts['received']}")
        logging.info(
            f"Total Servers Processed (Tested/Skipped): {total_tested_final}")
        logging.info(f"  ✅ Active:   {counts['success']}")
        logging.info(f"  ❌ Failed:   {counts['failure']}")
        logging.info(f"  ➖ Skipped:  {counts['skip']}")
        logging.info("-" * 50 + "\nActive Servers by Protocol:")
        if protocol_success_counts:
            for p, c in sorted(protocol_success_counts.items(), key=lambda item: item[1], reverse=True):
                logging.info(f"  {p.upper():<10}: {c}")
        else:
            logging.info("  (No servers active by protocol)")
        logging.info(
            "\n" + "=" * 20 + " Channel Statistics Report (Final Ranking by Success Rate) " + "=" * 20)
        final_header = f"{'Channel File/URL':<45} | {'Total':<7} | {'Active':<7} | {'Failed':<7} | {'Skip':<5} | {'Success%':<8}"
        logging.info(final_header)
        logging.info("-" * len(final_header))
        ranked_channels = []
        if channel_test_stats:
            for ch_filename, stats in channel_test_stats.items():
                base_ch_name = os.path.splitext(ch_filename)[0]
                if base_ch_name.replace('_', '').isalnum():
                    display_name = f"https://t.me/s/ {base_ch_name}"
                else:
                    display_name = ch_filename
                active_plus_failed = stats['active'] + stats['failed']
                success_p = (stats['active'] / active_plus_failed *
                             100) if active_plus_failed > 0 else 0.0
                ranked_channels.append({
                    'name': display_name, 'total': stats['total_prepared'], 'active': stats['active'],
                    'failed': stats['failed'], 'skip': stats['skip'], 'success_percent': success_p
                })
            sorted_final_ranking = sorted(ranked_channels, key=lambda x: (
                x['success_percent'], x['active'], -x['total'], x['name']), reverse=True)
            for entry in sorted_final_ranking:
                logging.info(
                    f"{entry['name']:<45} | {entry['total']:<7} | {entry['active']:<7} | {entry['failed']:<7} | {entry['skip']:<5} | {entry['success_percent']:>7.1f}%")
        if not ranked_channels:
            logging.info(
                "  (No channel-specific test data available for final ranking)")
        logging.info("=" * len(final_header))
        logging.info(f"\nWorking servers saved to: {working_file}")
        logging.info(f"Protocol-specific working servers in: {protocols_dir}")
        logging.info(
            f"Channel-specific working servers in: {tested_channels_dir}")
        logging.info(f"Failed servers saved to: {dead_file}")
        logging.info(f"Skipped servers saved to: {skip_file}")
        logging.info("--- Logger thread finished ---")


if __name__ == "__main__":
    logging.info("--- Starting Part 1: Telegram Channel Scraping ---")
    channels_file_path = CHANNELS_FILE
    try:
        if not os.path.exists(channels_file_path):
            logging.error(
                f"Telegram sources file not found: {channels_file_path}")
            sys.exit(1)
        with open(channels_file_path, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip()
                        and not line.strip().startswith('#')]
        normalized_urls = []
        for url in raw_urls:
            norm_url = normalize_telegram_url(url)
            if norm_url and norm_url not in normalized_urls:
                normalized_urls.append(norm_url)
        normalized_urls.sort()
        logging.info(
            f"✅ Found {len(normalized_urls)} unique, normalized Telegram channels to process.")
    except Exception as e:
        logging.error(
            f"❌ Error processing Telegram channel list ({channels_file_path}): {e}")
        sys.exit(1)
    total_channels_count = len(normalized_urls)
    processed_ch_count = 0
    total_new_added = 0
    failed_fetches = 0
    for idx, ch_url in enumerate(normalized_urls, 1):
        logging.info(
            f"--- Processing Channel {idx}/{total_channels_count}: {ch_url} ---")
        success_flag, new_srvs = process_channel(ch_url)
        if success_flag == 1:
            processed_ch_count += 1
            total_new_added += new_srvs
        else:
            failed_fetches += 1
        if idx % BATCH_SIZE == 0 and idx < total_channels_count:
            logging.info(
                f"--- Batch of {BATCH_SIZE} processed, sleeping for {SLEEP_TIME}s ---")
            time.sleep(SLEEP_TIME)
    logging.info(f"--- Telegram Scraping Finished ---")
    logging.info(
        f"Successfully processed {processed_ch_count}/{total_channels_count} channels.")
    if failed_fetches > 0:
        logging.warning(
            f"{failed_fetches} channels failed during fetch/processing.")
    logging.info(
        f"Added {total_new_added} new unique servers globally from scraping.")
    logging.info("\n--- Starting Part 2: GeoIP Analysis ---")
    country_data_map = process_geo_data()
    if country_data_map:
        logging.info("✅ GeoIP analysis complete.")
    else:
        logging.warning("⚠️ GeoIP analysis did not return data or failed.")
    logging.info("\n--- Starting Part 3: Generating Extraction Report ---")
    try:
        extraction_channel_stats = get_channel_stats()
        save_extraction_data(extraction_channel_stats, country_data_map)
        logging.info("✅ Extraction report generated.")
    except Exception as e:
        logging.error(f"❌ Failed to generate extraction report: {e}")
    logging.info("\n--- Starting Part 4: Server Testing ---")
    logging.info(f"Cleaning previous test results in: {TESTED_SERVERS_DIR}...")
    clean_directory(TESTED_SERVERS_DIR)
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Channels'), exist_ok=True)
    all_servers_to_test = []
    servers_read = 0
    parsing_errs = defaultdict(int)
    proto_counts = defaultdict(int)
    skipped_dis = 0
    if not os.path.exists(CHANNELS_DIR):
        logging.error(
            f"Source channels directory {CHANNELS_DIR} not found. Cannot load servers for testing.")
        sys.exit(1)
    source_channel_files = [f for f in os.listdir(
        CHANNELS_DIR) if f.endswith('.txt')]
    if not source_channel_files:
        logging.error(f"😐 No channel files in {CHANNELS_DIR} to test from.")
        sys.exit(1)
    for ch_filename in source_channel_files:
        _ = channel_test_stats[ch_filename]
        servers = read_links_from_file(os.path.join(CHANNELS_DIR, ch_filename))
        servers_read += len(servers)
        for link in servers:
            try:
                parsed_url = urlparse(link)
                proto = parsed_url.scheme.lower()
                if proto not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[proto]:
                    if proto not in ENABLED_PROTOCOLS:
                        parsing_errs[f"unsupported_{proto}"] += 1
                    else:
                        parsing_errs["disabled"] += 1
                        skipped_dis += 1
                    continue
                s_info = None
                try:
                    if proto == 'vless':
                        s_info = parse_vless_link(link)
                    elif proto == 'vmess':
                        s_info = parse_vmess_link(link)
                    elif proto == 'trojan':
                        s_info = parse_trojan_link(link)
                    elif proto == 'ss':
                        s_info = parse_ss_link(link)
                    if s_info:
                        s_info['source_file'] = ch_filename
                        all_servers_to_test.append(s_info)
                        proto_counts[proto] += 1
                        channel_test_stats[ch_filename]['total_prepared'] += 1
                    else:
                        parsing_errs[f"parse_no_impl_{proto}"] += 1
                        logging.warning(
                            f"Parser for {proto} returned None for link: {link[:60]}")
                except ValueError as ve:
                    parsing_errs[f"parse_invalid_{proto}"] += 1
                    logging.debug(
                        f"Invalid {proto} link in {ch_filename} ({ve}): {link[:60]}")
                except Exception as pe:
                    parsing_errs["parse_general"] += 1
                    logging.warning(
                        f"General parsing error for link in {ch_filename} ({type(pe).__name__}: {pe}): {link[:60]}")
            except Exception as oe:
                parsing_errs["outer_processing"] += 1
                logging.warning(
                    f"Error processing link line from {ch_filename} ({type(oe).__name__}: {oe}): {link[:60]}")
    logging.info(
        f"Read {servers_read} links. Prepared {len(all_servers_to_test)} for testing.")
    if skipped_dis > 0:
        logging.info(
            f"Skipped {skipped_dis} servers due to disabled protocols.")
    if parsing_errs:
        logging.warning("Parsing issues encountered:")
        for error_type, count_val in parsing_errs.items():
            logging.warning(f"  - {error_type}: {count_val}")
    if not all_servers_to_test:
        logging.error(
            "❌ No valid and enabled servers found to test after parsing. Exiting.")
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description="Scrape Telegram for proxies and test them.")
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS,
                        help=f"Max testing threads (default: {MAX_THREADS})")
    parser.add_argument('--skip-install', action='store_true',
                        help="Skip V2Ray check and installation.")
    cli_args = parser.parse_args()
    MAX_THREADS = cli_args.max_threads
    logging.info("\n--- V2Ray Check ---")
    if not cli_args.skip_install:
        installed_ver = check_v2ray_installed()
        latest_ver = get_latest_version()
        logging.info(
            f"Installed V2Ray version: {installed_ver or 'Not found'}")
        logging.info(
            f"Latest V2Ray version (GitHub): {latest_ver or 'Could not fetch'}")
        if not installed_ver or (latest_ver and installed_ver != latest_ver):
            logging.info("🚀 Attempting V2Ray installation/update...")
            install_v2ray()
            installed_ver = check_v2ray_installed()
            if not installed_ver:
                logging.critical(
                    "V2Ray installation/update attempted but failed or version check still fails. Exiting.")
                sys.exit(1)
            logging.info(
                f"Using V2Ray version after install/update: {installed_ver}")
        else:
            logging.info(f"✅ Using existing V2Ray version: {installed_ver}")
    else:
        logging.warning(
            "Skipping V2Ray check and installation as requested (--skip-install).")
        if not check_v2ray_installed():
            logging.error(
                "V2Ray check skipped, but V2Ray not found or not working. Testing cannot proceed.")
            sys.exit(1)
        else:
            logging.info(
                f"Confirmed V2Ray is present (version: {check_v2ray_installed()}) despite skipping install check.")
    logging.info(f"\n--- Starting Server Testing ({MAX_THREADS} threads) ---")
    test_log_queue = queue.Queue()
    logger_t = threading.Thread(target=logger_thread, args=(
        test_log_queue,), name="LoggerThread", daemon=True)
    logger_t.start()
    for s_info_item in all_servers_to_test:
        test_log_queue.put(('received', s_info_item, None))
    with ThreadPoolExecutor(max_workers=MAX_THREADS, thread_name_prefix="Tester") as executor:
        futures_list = []
        for s_info_item in all_servers_to_test:
            try:
                l_port = get_next_port()
                cfg_data = generate_config(s_info_item, l_port)
                futures_list.append(executor.submit(
                    test_server, s_info_item, cfg_data, l_port, test_log_queue))
            except Exception as e:
                logging.error(
                    f"❌ Error preparing test (config generation) for {s_info_item.get('original_link', 'N/A')}: {e}")
                s_info_item['source_file'] = s_info_item.get(
                    'source_file', 'unknown_channel.txt')
                test_log_queue.put(
                    ('skip', s_info_item, f"Config gen error: {str(e)[:100]}"))
        logging.info(
            f"Submitted {len(futures_list)} testing tasks. Waiting for completion...")
        for fut_idx, fut in enumerate(futures_list):
            try:
                fut.result()
            except Exception as fe:
                logging.error(
                    f"A testing future (index {fut_idx}) completed with an unexpected error: {fe}", exc_info=False)
    logging.info(
        "All testing tasks completed. Signaling logger thread to stop...")
    test_log_queue.put(None)
    logger_t.join(timeout=25)
    if logger_t.is_alive():
        logging.warning("Logger thread did not exit cleanly after timeout.")
    logging.info("--- Testing Phase Complete ---")
