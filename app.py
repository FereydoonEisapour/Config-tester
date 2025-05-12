
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
# Removed duplicate re import
import base64 # Added from appTester.py
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

# --- Parameters from app.py (Extraction Part) ---
SLEEP_TIME = 3                   # Anti-rate-limiting delay between batches (seconds)
BATCH_SIZE = 10                  # Channels processed before sleep interval
FETCH_CONFIG_LINKS_TIMEOUT = 15  # HTTP request timeout for Telegram scraping (seconds)

# Maximum entries per file
MAX_CHANNEL_SERVERS = 1000          # Max entries per channel file
MAX_PROTOCOL_SERVERS = 10000        # Max entries per protocol file
MAX_REGION_SERVERS = 10000          # Max entries per region file
MAX_MERGED_SERVERS = 100000         # Max entries in merged file

# --- Parameters from appTester.py (Testing Part) ---
V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Keep this definition
V2RAY_DIR = os.path.join(BASE_DIR, 'data', 'v2ray') # Adjusted path for app.py structure
# TESTED_SERVERS_DIR needs to be defined using BASE_DIR for consistency
TESTED_SERVERS_DIR = os.path.join(BASE_DIR, 'Tested_Servers')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
# CHANNELS_DIR is already defined above, using the "Servers/Channels" structure

TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 20 # Default, can be overridden by args
START_PORT = 10000
# *** Critical: Use appTester.py values ***
REQUEST_TIMEOUT = 30  # Increased timeout from appTester.py
PROCESS_START_WAIT = 15 # Decreased wait time from appTester.py
# MAX_RETRIES = 2 # This was defined but not used in app.py testing part, removed for now

# Protocol enable/disable configuration (Kept from app.py, ensure it matches needs)
ENABLED_PROTOCOLS = {
    'vless': True,
    'vmess': False,
    'trojan': False,
    'ss': False
}

def clean_directory(dir_path):
    if os.path.exists(dir_path):
        # Check if it's the V2Ray directory to avoid deleting the binary during cleaning
        # Only clean if it's NOT the V2Ray directory itself or is empty
        is_v2ray_dir = os.path.abspath(dir_path) == os.path.abspath(V2RAY_DIR)
        if is_v2ray_dir and os.listdir(dir_path):
             logging.warning(f"Skipping cleaning of non-empty V2Ray directory: {dir_path}")
             # Optionally, clean specific subfolders or files if needed, but avoid binary deletion
             # Example: Clean logs within V2Ray dir if they exist
             # v2ray_log_path = os.path.join(dir_path, 'access.log')
             # if os.path.exists(v2ray_log_path): os.unlink(v2ray_log_path)
             return # Exit function to avoid full clean

        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    # Add protection against deleting the v2ray executable if it ended up here by mistake
                    if filename == V2RAY_BIN and os.path.abspath(os.path.dirname(file_path)) == os.path.abspath(V2RAY_DIR):
                         logging.warning(f"Skipping deletion of V2Ray binary: {file_path}")
                         continue
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        logging.info(f"Cleaned directory: {dir_path}")
    else:
        # Make sure V2Ray dir exists if we are trying to create it
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")


# === Directory Setup ===
# Clean "Servers" directory at the start of extraction
# Note: clean_directory for TESTED_SERVERS_DIR happens later, before testing starts
logging.info("Cleaning extraction directories...")
clean_directory(os.path.join(BASE_DIR, "Servers")) # Cleans Protocols, Regions, Merged, Channels

# Create directories if they don't exist (needed after cleaning)
for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR, V2RAY_DIR, TESTED_SERVERS_DIR, LOGS_DIR]:
     os.makedirs(directory, exist_ok=True)
os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True) # Ensure subdirs exist


# ========================
# Protocol Detection Patterns (Extraction Part)
# ========================
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

# ========================
# Extraction Functions (from app.py)
# ========================
def normalize_telegram_url(url):
    url = url.strip()
    if url.startswith("https://t.me/"):
        parts = url.split('/')
        # Handle both https://t.me/channel and https://t.me/s/channel
        if len(parts) >= 4:
            if parts[3] == 's':
                 # Already in https://t.me/s/ format or invalid format like https://t.me//abc
                 if len(parts) > 4 and parts[4]: # Ensure there's a channel name after /s/
                      return url
                 elif len(parts) == 4 and parts[3] == 's': # Case like https://t.me/s/ (invalid)
                      return "" # Or handle as error
                 else: # Convert https://t.me/channel to https://t.me/s/channel
                      return f"https://t.me/s/{'/'.join(parts[3:])}"
            else: # Case https://t.me/channel
                 return f"https://t.me/s/{'/'.join(parts[3:])}"
        else: # Invalid like https://t.me/
             return ""
    elif url and not url.startswith("http://") and not url.startswith("https://"):
        # Handle channel name only
        return f"https://t.me/s/{url}"
    return "" # Return empty for other invalid inputs


def extract_channel_name(url):
    """Extracts normalized channel name from Telegram URL (handles /s/)."""
    try:
        parsed_url = urlparse(url)
        path_parts = [part for part in parsed_url.path.split('/') if part] # Remove empty parts
        if path_parts:
            if path_parts[0] == 's':
                return path_parts[1] if len(path_parts) > 1 else "unknown_channel"
            else:
                return path_parts[0]
    except Exception:
        pass # Handle potential errors if URL format is unexpected
    # Fallback if parsing fails or path is weird
    return url.split('/')[-1] if '/' in url else url


def count_servers_in_file(file_path):
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Count non-empty lines that don't start with # (comments)
            return len([line for line in f if line.strip() and not line.strip().startswith('#')])
    except Exception as e:
        logging.error(f"❌ Error counting servers in {file_path}: {e}")
        return 0

def get_current_counts():
    counts = {}
    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        counts[proto] = count_servers_in_file(proto_file)
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
    # Ensure total is not negative if regional somehow exceeds merged (shouldn't happen)
    counts['failed'] = max(0, counts['total'] - regional_servers)
    return counts, country_data

def get_channel_stats():
    channel_stats = {}
    if os.path.exists(CHANNELS_DIR):
        for channel_file in Path(CHANNELS_DIR).glob("*.txt"):
            channel_name = channel_file.stem
            count = count_servers_in_file(channel_file)
            channel_stats[channel_name] = count
    return channel_stats

def save_extraction_data(channel_stats, country_data):
    current_counts, country_stats = get_current_counts() # Recalculate just before saving
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True) # Ensure report dir exists
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers (Merged): {current_counts['total']}\n")
            log.write(f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")

            log.write("\n=== Server Type Summary ===\n")
            # Filter protocols present in counts and sort
            valid_protocols = {p: current_counts.get(p, 0) for p in PATTERNS}
            sorted_protocols = sorted(valid_protocols.items(), key=lambda x: x[1], reverse=True)
            for proto, count in sorted_protocols:
                 log.write(f"{proto.upper():<20} : {count}\n")

            log.write("\n=== Channel Statistics ===\n")
            # Add check if channel_stats is empty
            if not channel_stats:
                 log.write("No channel data available.\n")
            else:
                for channel, total in sorted(channel_stats.items(), key=lambda x: x[1], reverse=True):
                    log.write(f"{channel:<30}: {total}\n") # Increased width for channel name

    except Exception as e:
        logging.error(f"❌ Error writing extraction report to {LOG_FILE}: {e}")


def fetch_config_links(url):
    """Scrapes Telegram channel content for proxy configuration links."""
    logging.info(f"Fetching configs from: {url}")
    try:
        # Add a user-agent header
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=FETCH_CONFIG_LINKS_TIMEOUT, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Refined selectors based on typical Telegram web view structure
        message_containers = soup.select('div.tgme_widget_message_bubble, div.tgme_widget_message_text') # Combine selectors
        code_blocks = soup.find_all(['code', 'pre'])

        configs = {proto: set() for proto in PATTERNS}
        configs["all"] = set() # To store all unique links found for the channel

        # Process code blocks first (often contain clean links)
        for code_tag in code_blocks:
            code_text = code_tag.get_text('\n').strip() # Use newline separator for multi-line code blocks
            # Simple cleaning for backticks (might need more robust cleaning)
            clean_text = re.sub(r'(^`{1,3}|`{1,3}$)', '', code_text, flags=re.MULTILINE).strip()
            lines = clean_text.splitlines() # Process line by line within code blocks
            for line in lines:
                line = line.strip()
                if not line: continue
                for proto, pattern in PATTERNS.items():
                    # Use findall on each line
                    matches = re.findall(pattern, line)
                    if matches:
                        valid_matches = {m for m in matches if urlparse(m).scheme == proto} # Basic validation
                        configs[proto].update(valid_matches)
                        configs["all"].update(valid_matches)

        # Process general message text
        for container in message_containers:
            # Extract text carefully, handling potential nested tags
            # get_text with a separator helps preserve structure somewhat
            general_text = container.get_text(separator='\n', strip=True)
            lines = general_text.splitlines() # Process line by line
            for line in lines:
                 line = line.strip()
                 if not line: continue
                 # Check against patterns on each line
                 for proto, pattern in PATTERNS.items():
                      matches = re.findall(pattern, line)
                      if matches:
                           valid_matches = {m for m in matches if urlparse(m).scheme == proto} # Basic validation
                           configs[proto].update(valid_matches)
                           configs["all"].update(valid_matches)

        # Convert sets to lists for return
        final_configs = {k: list(v) for k, v in configs.items() if v} # Only include non-empty lists
        found_count = len(final_configs.get("all", []))
        logging.info(f"Found {found_count} potential configs in {url}")
        return final_configs

    except requests.exceptions.Timeout:
         logging.error(f"Timeout error fetching {url} after {FETCH_CONFIG_LINKS_TIMEOUT}s")
         return None
    except requests.exceptions.RequestException as e:
        logging.error(f"🛜❌ Connection or HTTP error for {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"❌ Unexpected error scraping {url}: {e}")
        return None


def load_existing_configs():
    existing = {proto: set() for proto in PATTERNS}
    existing["merged"] = set()

    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        if os.path.exists(proto_file):
            try:
                with open(proto_file, 'r', encoding='utf-8') as f:
                    # Read lines, strip whitespace, filter empty lines
                    existing[proto] = {line.strip() for line in f if line.strip()}
            except Exception as e:
                logging.error(f"Error reading existing {proto} configs from {proto_file}: {e}")

    merged_file_path = MERGED_SERVERS_FILE
    if os.path.exists(merged_file_path):
        try:
            with open(merged_file_path, 'r', encoding='utf-8') as f:
                existing['merged'] = {line.strip() for line in f if line.strip()}
        except Exception as e:
            logging.error(f"Error reading existing merged configs from {merged_file_path}: {e}")

    return existing


def trim_file(file_path, max_lines):
    """Trim file to keep only the latest entries up to max_lines."""
    if not os.path.exists(file_path) or max_lines <= 0:
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Strip lines and filter out empty ones *before* counting and trimming
        valid_lines = [line for line in lines if line.strip()]

        if len(valid_lines) > max_lines:
            logging.info(f"Trimming {file_path} from {len(valid_lines)} to {max_lines} lines.")
            # Keep the *first* max_lines entries (which are the newest added)
            trimmed_lines = valid_lines[:max_lines]
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(line if line.endswith('\n') else line + '\n' for line in trimmed_lines)
        # Optional: If you want to keep the *last* lines instead:
        # trimmed_lines = valid_lines[-max_lines:]

    except Exception as e:
        logging.error(f"Error trimming {file_path}: {e}")

def process_channel(url):
    """Executes full processing pipeline for a Telegram channel."""
    channel_name = extract_channel_name(url)
    if not channel_name or channel_name == "unknown_channel":
        logging.error(f"Could not extract a valid channel name from URL: {url}")
        return 0, 0 # Failed to process

    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    logging.info(f"Processing channel: {channel_name} ({url})")

    # Load existing configurations *before* fetching new ones
    existing_configs = load_existing_configs()

    # Fetch new configurations
    configs = fetch_config_links(url)
    if configs is None: # Handle fetch failure explicitly
        logging.error(f"Failed to fetch configs for {channel_name}. Skipping.")
        return 0, 0 # Indicate channel fetch failure
    if not configs or "all" not in configs or not configs["all"]:
        logging.info(f"No new valid proxy links found for {channel_name}.")
        # Still create/touch the channel file to indicate it was processed
        Path(channel_file).touch()
        return 1, 0 # Indicate channel processed, but 0 new links found overall

    # --- Channel File Update ---
    all_fetched_channel_configs = set(configs.get("all", []))

    existing_channel_configs = set()
    if os.path.exists(channel_file):
        try:
            with open(channel_file, 'r', encoding='utf-8') as f:
                existing_channel_configs = {line.strip() for line in f if line.strip()}
        except Exception as e:
            logging.error(f"Error reading channel file {channel_file}: {e}")

    # Find genuinely new configs for *this specific channel*
    new_configs_for_channel = all_fetched_channel_configs - existing_channel_configs
    added_to_channel_count = len(new_configs_for_channel)

    if new_configs_for_channel:
        logging.info(f"Adding {added_to_channel_count} new configs to channel file: {channel_name}.txt")
        # Prepend new configs to existing ones
        updated_channel_configs = list(new_configs_for_channel) + list(existing_channel_configs)
        try:
            with open(channel_file, 'w', encoding='utf-8') as f:
                # Write unique configs, respecting the limit
                unique_lines = []
                seen = set()
                for line in updated_channel_configs:
                     if line not in seen:
                          unique_lines.append(line)
                          seen.add(line)
                # Write up to MAX_CHANNEL_SERVERS
                f.write('\n'.join(unique_lines[:MAX_CHANNEL_SERVERS]) + '\n')
            trim_file(channel_file, MAX_CHANNEL_SERVERS) # Ensure limit after writing
        except Exception as e:
            logging.error(f"Error writing to channel file {channel_file}: {e}")
    elif not os.path.exists(channel_file):
         # Create empty file if it doesn't exist and no new configs found
         Path(channel_file).touch()


    # --- Protocol and Merged File Update ---
    genuinely_new_added_to_global = 0

    for proto, links in configs.items():
        if proto == "all" or not links:
            continue # Skip the 'all' list and empty protocol lists

        # Find links that are new *globally* for this protocol
        new_global_proto_links = set(links) - existing_configs.get(proto, set())
        if not new_global_proto_links:
            continue # No new links for this protocol globally

        logging.info(f"Found {len(new_global_proto_links)} globally new {proto.upper()} configs from {channel_name}")

        # Update Protocol File
        proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        try:
            # Read existing lines for this protocol
            existing_proto_lines = list(existing_configs.get(proto, set()))
            # Combine: new links first, then existing
            updated_proto_lines = list(new_global_proto_links) + existing_proto_lines
            # Write unique lines up to the limit
            with open(proto_path, 'w', encoding='utf-8') as f:
                unique_lines = []
                seen = set()
                for line in updated_proto_lines:
                     if line not in seen:
                          unique_lines.append(line)
                          seen.add(line)
                f.write('\n'.join(unique_lines[:MAX_PROTOCOL_SERVERS]) + '\n')
            trim_file(proto_path, MAX_PROTOCOL_SERVERS) # Ensure limit
            # Update the in-memory set for the next iteration within this channel processing
            existing_configs[proto].update(new_global_proto_links)
        except Exception as e:
            logging.error(f"Error writing to {proto} file ({proto_path}): {e}")

        # Update Merged File (only add links that are not already in the merged list)
        new_for_merged = new_global_proto_links - existing_configs.get('merged', set())
        if new_for_merged:
            merged_path = MERGED_SERVERS_FILE
            try:
                existing_merged_lines = list(existing_configs.get('merged', set()))
                updated_merged_lines = list(new_for_merged) + existing_merged_lines
                with open(merged_path, 'w', encoding='utf-8') as f:
                    unique_lines = []
                    seen = set()
                    for line in updated_merged_lines:
                         if line not in seen:
                              unique_lines.append(line)
                              seen.add(line)
                    f.write('\n'.join(unique_lines[:MAX_MERGED_SERVERS]) + '\n')
                trim_file(merged_path, MAX_MERGED_SERVERS) # Ensure limit
                # Update the in-memory merged set
                existing_configs['merged'].update(new_for_merged)
                genuinely_new_added_to_global += len(new_for_merged) # Count truly new additions
            except Exception as e:
                logging.error(f"Error updating merged configs file ({merged_path}): {e}")

    logging.info(f"Finished processing {channel_name}. Added {added_to_channel_count} to channel file. Added {genuinely_new_added_to_global} new unique configs globally.")
    return 1, genuinely_new_added_to_global # Return success and count of *globally* new servers added


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
    """Performs geographical analysis using GeoIP database."""
    if not GEOIP_DATABASE_PATH.exists() or GEOIP_DATABASE_PATH.stat().st_size < 1024 * 1024: # Check size
        logging.warning("⚠️ GeoIP database missing or invalid. Attempting download...")
        success = download_geoip_database()
        if not success:
            logging.error("❌ Cannot perform GeoIP analysis without the database.")
            return {} # Return empty if download fails

    geo_reader = None
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
        logging.info("GeoIP database loaded successfully.")
    except Exception as e:
        logging.error(f"❌ Error opening GeoIP database ({GEOIP_DATABASE_PATH}): {e}")
        return {}

    country_configs = defaultdict(list) # Store configs per country
    failed_geoip_count = 0
    processed_count = 0

    # Clean existing region files before processing
    if os.path.exists(REGIONS_DIR):
         logging.info(f"Cleaning existing region files in {REGIONS_DIR}...")
         for region_file in Path(REGIONS_DIR).glob("*.txt"):
              try:
                   region_file.unlink()
              except OSError as e:
                   logging.error(f"Error deleting region file {region_file}: {e}")
    else:
         os.makedirs(REGIONS_DIR) # Ensure directory exists


    # Process merged configurations
    configs = []
    merged_file_path = MERGED_SERVERS_FILE
    if os.path.exists(merged_file_path):
        try:
            with open(merged_file_path, 'r', encoding='utf-8') as f:
                configs = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(configs)} configs from {merged_file_path} for GeoIP processing.")
        except Exception as e:
            logging.error(f"Error reading merged file {merged_file_path} for GeoIP: {e}")
            configs = [] # Ensure configs is empty list on error
    else:
        logging.warning(f"Merged servers file not found: {merged_file_path}. Cannot perform GeoIP.")
        if geo_reader: geo_reader.close()
        return {}


    for config in configs:
        processed_count += 1
        ip = None
        country = "Unknown" # Default country
        try:
            # Improved IP extraction for various formats (VLESS, VMess, Trojan, SS)
            parsed = urlparse(config)
            if parsed.scheme in ['vless', 'trojan', 'hysteria', 'hysteria2', 'tuic']:
                ip = parsed.hostname
            elif parsed.scheme == 'vmess':
                try:
                    # Decode VMess base64 part
                    vmess_json_str = urlsafe_b64decode(parsed.netloc + parsed.path + '==').decode('utf-8')
                    vmess_data = json.loads(vmess_json_str)
                    ip = vmess_data.get('add')
                except Exception:
                    logging.debug(f"Could not parse VMess for GeoIP: {config[:50]}...")
                    pass # Keep ip as None
            elif parsed.scheme == 'ss':
                # SS address is usually directly in hostname after decoding userinfo
                ip = parsed.hostname

            if ip:
                # Attempt GeoIP lookup
                try:
                    country_response = geo_reader.country(ip)
                    # Use ISO code for consistency, fallback to name
                    country = country_response.country.iso_code or country_response.country.name or "Unknown"
                except geoip2.errors.AddressNotFoundError:
                    logging.debug(f"GeoIP address not found for IP: {ip} (Config: {config[:50]}...)")
                    country = "Unknown" # Explicitly mark as Unknown
                    failed_geoip_count += 1
                except Exception as geo_e:
                    logging.warning(f"GeoIP lookup error for IP {ip}: {geo_e}")
                    country = "Unknown" # Mark as Unknown on other GeoIP errors
                    failed_geoip_count += 1
            else:
                # If IP extraction failed
                failed_geoip_count += 1
                logging.debug(f"Could not extract IP for GeoIP from: {config[:50]}...")

        except Exception as parse_e:
            # Catch errors during URL parsing or IP extraction
            logging.warning(f"Error processing config for GeoIP ({config[:50]}...): {parse_e}")
            country = "Unknown"
            failed_geoip_count += 1

        # Add config to the country list (even if Unknown)
        country_configs[country].append(config)

    # Close the GeoIP reader
    if geo_reader:
        geo_reader.close()
        logging.info("GeoIP database closed.")

    # Write configs to country-specific files
    country_counter = {}
    logging.info("Writing configs to region files...")
    for country, country_list in country_configs.items():
        country_counter[country] = len(country_list)
        # Sanitize country name for filename if needed (e.g., replace spaces, although ISO codes are better)
        filename_country = country.replace(" ", "_")
        region_file = os.path.join(REGIONS_DIR, f"{filename_country}.txt")
        try:
            # Sort configs within the country file? Optional.
            # country_list.sort()
            with open(region_file, 'w', encoding='utf-8') as f:
                 # Write only up to the max limit for region files
                f.write('\n'.join(country_list[:MAX_REGION_SERVERS]) + '\n')
            # No need to trim here if we slice before writing
            # trim_file(region_file, MAX_REGION_SERVERS)
        except Exception as e:
            logging.error(f"Error writing to region file {region_file}: {e}")

    logging.info(f"GeoIP processing complete. Processed: {processed_count}, Successful lookups: {processed_count - failed_geoip_count}, Failed/Unknown: {failed_geoip_count}")
    return dict(country_counter) # Return the counts per country

# ========================
# Testing Infrastructure (Adapted from appTester.py)
# ========================

# Configure logging (Using CleanFormatter from app.py)
class CleanFormatter(logging.Formatter):
    def format(self, record):
        # Use standard format for file, clean for console
        if hasattr(record, 'clean_output'): # Check flag set by console handler
            if record.levelno == logging.INFO:
                return f"{record.msg}"
            elif record.levelno >= logging.WARNING: # ERROR, CRITICAL, WARNING
                 return f"{record.levelname}: {record.msg}"
            # Add other levels if needed
        return super().format(record) # Default format for file handler

# Set up logger (Ensure it's not reconfigured accidentally)
if not logging.getLogger().hasHandlers():
     logger = logging.getLogger()
     logger.setLevel(logging.INFO)

     # Console handler (clean output)
     console_handler = logging.StreamHandler(sys.stdout) # Explicitly use sys.stdout
     console_formatter = CleanFormatter()
     # Add a flag to the formatter/handler to indicate it's the clean one
     console_handler.addFilter(lambda record: setattr(record, 'clean_output', True) or True)
     console_handler.setFormatter(console_formatter)
     logger.addHandler(console_handler)

     # File handler (detailed logs for testing phase)
     # Use a different log file for testing details to avoid overwriting extraction report
     test_log_file = os.path.join(LOGS_DIR, 'testing_debug.log')
     file_handler = logging.FileHandler(test_log_file, encoding='utf-8')
     file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
     file_handler.setFormatter(file_formatter)
     logger.addHandler(file_handler)
else:
     # Logger already configured, ensure file handler for testing exists if needed
     logger = logging.getLogger()
     test_log_file = os.path.join(LOGS_DIR, 'testing_debug.log')
     # Check if a file handler for the test log already exists
     if not any(isinstance(h, logging.FileHandler) and h.baseFilename == test_log_file for h in logger.handlers):
          file_handler = logging.FileHandler(test_log_file, encoding='utf-8')
          file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
          file_handler.setFormatter(file_formatter)
          logger.addHandler(file_handler)


# Disable SSL warnings for requests
try:
     import urllib3
     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
     requests.packages.urllib3.disable_warnings()


# Thread-safe port counter
current_port = START_PORT
port_lock = threading.Lock()

def get_next_port():
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
        # Optional: Reset port number if it gets too high, e.g., back to START_PORT
        # if current_port > START_PORT + MAX_THREADS * 10: # Example reset condition
        #     current_port = START_PORT
    return port

def read_links_from_file(file_path):
    """Reads non-empty, non-comment lines from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            links = file.readlines()
        # Strip whitespace and filter comments/empty lines
        return [link.strip() for link in links if link.strip() and not link.strip().startswith('#')]
    except FileNotFoundError:
         logging.error(f"File not found: {file_path}")
         return []
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return []

# --- Parsing Functions (Copied directly from appTester.py for consistency) ---
def parse_vless_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vless':
        raise ValueError("Invalid VLESS link")

    uuid = parsed.username
    # Allow UUID without dashes as well
    if not uuid or not re.match(r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$', uuid, re.I):
        raise ValueError(f"Invalid UUID format: {uuid}")

    query = parse_qs(parsed.query)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Missing hostname in VLESS link")

    port = parsed.port
    if not port:
        # Try to extract port from netloc if not present after colon (e.g., address:port#fragment)
        # This is less standard but might occur.
         match = re.search(r':(\d+)', parsed.netloc)
         if match:
              port = int(match.group(1))
         else:
              # Default port based on security
              port = 443 if query.get('security', [''])[0] in ['tls', 'reality'] else 80


    # Handle potential missing values more gracefully
    security = query.get('security', ['none'])[0] or 'none'
    encryption = query.get('encryption', ['none'])[0] or 'none' # Should be 'none' for VLESS normally
    network = query.get('type', ['tcp'])[0] or 'tcp'
    sni = query.get('sni', [hostname])[0] or hostname

    ws_path = query.get('path', ['/'])[0] if network == 'ws' else '/' # Default path for ws
    ws_host = query.get('host', [sni])[0] if network == 'ws' else sni # Default host for ws (often same as SNI)

    pbk = query.get('pbk', [''])[0] if security == 'reality' else ''
    sid = query.get('sid', [''])[0] if security == 'reality' else ''
    fp = query.get('fp', [''])[0] if security == 'reality' else ''
    flow = query.get('flow', [''])[0] # Flow can exist without reality/tls

    alpn_list = []
    if 'alpn' in query and query['alpn'][0]:
         alpn_list = [val.strip() for val in query['alpn'][0].split(',') if val.strip()]


    return {
        'original_link': link,
        'protocol': 'vless',
        'uuid': uuid.replace('-', ''), # Store UUID without dashes internally if needed
        'host': hostname,
        'port': port,
        'security': security,
        'encryption': encryption, # VLESS uses 'none' typically here
        'network': network,
        'ws_path': ws_path,
        'ws_host': ws_host,
        'sni': sni,
        'pbk': pbk,
        'sid': sid,
        'fp': fp,
        'alpn': alpn_list,
        'flow': flow
    }


def parse_vmess_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vmess':
        raise ValueError("Invalid VMESS link")

    # Handle non-standard URL encoding or padding issues
    base64_data = parsed.netloc + parsed.path
    try:
        # Add padding if necessary
        padding = '=' * ((4 - len(base64_data) % 4) % 4)
        json_str = urlsafe_b64decode(base64_data + padding).decode('utf-8')
        data = json.loads(json_str)
    except (TypeError, ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to decode or parse VMess JSON: {e} - Data: {base64_data}")

    # Extract fields with defaults
    host = data.get('add')
    if not host: raise ValueError("Missing 'add' (address) in VMess config")
    port = int(data.get('port', 0)) # Use 0 to indicate potentially missing
    if not port: raise ValueError("Missing 'port' in VMess config")
    uuid = data.get('id')
    if not uuid: raise ValueError("Missing 'id' (UUID) in VMess config")

    # More robust defaults
    network = data.get('net', 'tcp') or 'tcp'
    security = data.get('tls', 'none') or 'none' # 'tls' or 'none' usually
    ws_path = data.get('path', '/') if network == 'ws' else '/'
    ws_host = data.get('host', host) if network == 'ws' else host # Default ws host to address if missing
    sni = data.get('sni', ws_host if security == 'tls' else '') # SNI usually matches ws host or address if TLS

    # VMess specific fields
    alter_id = int(data.get('aid', 0))
    vmess_sec = data.get('scy', 'auto') or 'auto' # Encryption method for VMess itself


    return {
        'original_link': link,
        'protocol': 'vmess',
        'uuid': uuid,
        'host': host,
        'port': port,
        'network': network,
        'security': security, # This refers to TLS layer
        'ws_path': ws_path,
        'ws_host': ws_host,
        'sni': sni,
        'alter_id': alter_id,
        'encryption': vmess_sec # VMess's own security parameter
    }


def parse_trojan_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'trojan':
        raise ValueError("Invalid Trojan link")

    password = parsed.username
    if not password: raise ValueError("Missing password in Trojan link")
    host = parsed.hostname
    if not host: raise ValueError("Missing hostname in Trojan link")
    port = parsed.port
    if not port: raise ValueError("Missing port in Trojan link")

    query = parse_qs(parsed.query)

    # Defaults reflect common Trojan usage
    security = query.get('security', ['tls'])[0] or 'tls' # Trojan almost always uses TLS
    sni = query.get('sni', [host])[0] or host
    network = query.get('type', ['tcp'])[0] or 'tcp' # Can be tcp or ws
    ws_path = query.get('path', ['/'])[0] if network == 'ws' else '/'
    ws_host = query.get('host', [sni])[0] if network == 'ws' else sni

    alpn_list = []
    # Default ALPN often includes h2 and http/1.1 for Trojan over TLS
    default_alpn = ['h2', 'http/1.1']
    if 'alpn' in query and query['alpn'][0]:
         alpn_list = [val.strip() for val in query['alpn'][0].split(',') if val.strip()]
    else:
        alpn_list = default_alpn # Use default if not specified

    return {
        'original_link': link,
        'protocol': 'trojan',
        'password': password,
        'host': host,
        'port': port,
        'security': security, # Should generally be 'tls'
        'sni': sni,
        'alpn': alpn_list,
        'network': network,
        'ws_path': ws_path,
        'ws_host': ws_host
    }

def parse_ss_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'ss':
        raise ValueError("Invalid Shadowsocks link")

    try:
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            raise ValueError("Missing host or port in Shadowsocks link")

        # Fragment often contains the name/tag
        name = parsed.fragment or f"ss_{host}"

        # Userinfo can be plain method:pass or base64 encoded
        userinfo_raw = parsed.username # Before @, might be None if no userinfo
        if userinfo_raw: # Handle case ss://host:port (no userinfo) - unlikely standard
             userinfo_decoded = unquote(userinfo_raw)
        else:
             # Attempt to get from netloc if format is like ss://method:pass@host:port
             if '@' in parsed.netloc:
                  userinfo_part = parsed.netloc.split('@')[0]
                  userinfo_decoded = unquote(userinfo_part)
             else:
                  # Maybe it's the non-standard base64 ss://BASE64INFO#name ?
                  # Let's prioritize standard formats first. If standard fails, this is fallback.
                   try:
                         # Check if netloc looks like base64
                         maybe_b64 = parsed.netloc.split('#')[0] # Remove fragment if present
                         if len(maybe_b64) % 4 != 0: maybe_b64 += '=' * (4 - len(maybe_b64) % 4)

                         decoded_bytes = urlsafe_b64decode(maybe_b64)
                         decoded_str = decoded_bytes.decode('utf-8')
                         if ':' in decoded_str:
                              method, password = decoded_str.split(':', 1)
                              # We already have host/port from initial parse
                              return {
                                   'original_link': link, 'protocol': 'shadowsocks',
                                   'method': method, 'password': password,
                                   'host': host, 'port': int(port),
                                   'network': 'tcp', 'name': name # Assume tcp
                               }
                         else:
                              raise ValueError("Base64 part does not contain 'method:password'")
                   except Exception:
                        raise ValueError("Shadowsocks link missing credentials (method:password)")


        # Try decoding base64 first (common format ss://BASE64@host:port)
        method = None
        password = None
        try:
            padding = '=' * ((4 - len(userinfo_decoded) % 4) % 4)
            decoded_cred = urlsafe_b64decode(userinfo_decoded + padding).decode('utf-8')
            if ':' in decoded_cred:
                method, password = decoded_cred.split(':', 1)
            else:
                 # If decode succeeds but no colon, it's ambiguous, treat as error or fallback
                 pass # Fallback to plain text check below
        except Exception:
            # If base64 decode fails, assume it's plain text method:password
            pass

        # If base64 failed or was skipped, check for plain text method:password
        if not method and ':' in userinfo_decoded:
             method, password = userinfo_decoded.split(':', 1)


        # Final check if we have credentials
        if not method or password is None: # Password can be empty string
            raise ValueError(f"Could not extract 'method:password' from userinfo: {userinfo_decoded}")

        return {
            'original_link': link,
            'protocol': 'shadowsocks',
            'method': method,
            'password': password,
            'host': host,
            'port': int(port),
            'network': 'tcp', # Shadowsocks primarily uses TCP for the proxy connection itself
            'name': name
        }

    except Exception as e:
        raise ValueError(f"Invalid Shadowsocks link format: {str(e)} - Link: {link}")


# --- Config Generation (Copied directly from appTester.py) ---
def generate_config(server_info, local_port):
    # Basic structure
    config = {
        "log": {
            # "loglevel": "debug", # Uncomment for debugging V2Ray itself
             "access": None, # Disable access log file
             "error": None   # Disable error log file
        },
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth", # No auth needed for local testing proxy
                "udp": True,      # Enable UDP forwarding
                "ip": "127.0.0.1" # Listen only on localhost
                },
            "sniffing": {         # Enable sniffing for destination domain
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        }],
        "outbounds": [{
            "protocol": server_info['protocol'],
            "settings": {},
            "streamSettings": {
                 # Default values, will be overridden
                 "network": server_info.get('network', 'tcp'),
                 "security": server_info.get('security', 'none'),
                 # Initialize complex settings to None initially
                 "tlsSettings": None,
                 "realitySettings": None,
                 "wsSettings": None,
                 "tcpSettings": None,
                 "kcpSettings": None,
                 "quicSettings": None,
                 "httpSettings": None,
                 "grpcSettings": None
            },
            "mux": { # Enable Mux for potentially better performance
                "enabled": True,
                "concurrency": 8 # Default concurrency
            }
        }]
    }

    # Protocol specific settings
    outbound_settings = {}
    if server_info['protocol'] == 'vless':
        outbound_settings = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "encryption": server_info['encryption'], # Should be "none"
                    "flow": server_info.get('flow', '') # Add flow if present
                }]
            }]
        }
    elif server_info['protocol'] == 'vmess':
        outbound_settings = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{
                    "id": server_info['uuid'],
                    "alterId": server_info['alter_id'],
                    "security": server_info['encryption'] # VMess specific encryption e.g., "aes-128-gcm"
                }]
            }]
        }
    elif server_info['protocol'] == 'trojan':
        outbound_settings = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "password": server_info['password']
                # Trojan flow is handled by stream settings (TLS usually)
            }]
        }
    elif server_info['protocol'] == 'shadowsocks':
        outbound_settings = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "method": server_info['method'],
                "password": server_info['password'],
                "ota": False # OTA is deprecated and generally false
                # UDP support relies on V2Ray handling it based on inbound UDP setting
            }]
        }

    config['outbounds'][0]['settings'] = outbound_settings

    # Stream settings based on network and security
    stream_settings = config['outbounds'][0]['streamSettings']

    network = stream_settings['network']
    security = stream_settings['security']

    # TLS Settings (used if security is 'tls')
    if security == 'tls':
        tls_settings = {
            "serverName": server_info.get('sni', server_info['host']), # Use SNI, fallback to host
            "allowInsecure": True, # Allow self-signed certs for testing flexibility
            # "disableSystemRoot": False, # Use system root CAs
        }
        if server_info.get('alpn'):
            tls_settings["alpn"] = server_info['alpn']
        # Fingerprint applied here if needed for TLS
        if server_info.get('fp') and server_info.get('fp') != 'none':
             tls_settings["fingerprint"] = server_info['fp'] # Common fingerprints: chrome, firefox, safari, ios, android, random
        stream_settings['tlsSettings'] = tls_settings

    # REALITY Settings (used if security is 'reality')
    elif security == 'reality':
        if not server_info.get('pbk') or not server_info.get('fp'):
             raise ValueError("REALITY config missing 'pbk' (publicKey) or 'fp' (fingerprint)")
        reality_settings = {
            "show": False, # Must be false for REALITY
            "fingerprint": server_info['fp'],
            "serverName": server_info.get('sni', server_info['host']), # REALITY requires SNI (serverName)
            "publicKey": server_info['pbk'],
            "shortId": server_info.get('sid', ''), # Short ID
            "spiderX": server_info.get('spx', '/') # SpiderX path
        }
        stream_settings['realitySettings'] = reality_settings
        # REALITY implies TLS, V2Ray handles this internally, no explicit tlsSettings needed here

    # Network specific settings
    if network == 'ws':
        ws_settings = {
            "path": server_info.get('ws_path', '/'),
            "headers": {
                # Use ws_host if available, fallback to SNI/host
                "Host": server_info.get('ws_host', server_info.get('sni', server_info['host']))
            }
        }
         # Add early data header if needed (less common)
        # "maxEarlyData": 1024,
        # "useBrowserForwarding": False
        stream_settings['wsSettings'] = ws_settings

    # Add other network types if needed (grpc, kcp, quic, etc.) - Example for gRPC:
    # elif network == 'grpc':
    #     grpc_settings = {
    #         "serviceName": server_info.get('serviceName', ''), # Get from query parameters
    #         "multiMode": server_info.get('mode', '') == 'multi', # Check 'mode' query param
    #         # "idle_timeout": 60,
    #         # "health_check_timeout": 20,
    #         # "permit_without_stream": False,
    #         # "initial_windows_size": 0,
    #     }
    #     stream_settings['grpcSettings'] = grpc_settings

    # Clean up streamSettings: remove keys with None values
    config['outbounds'][0]['streamSettings'] = {k: v for k, v in stream_settings.items() if v is not None}

    return config

# --- Test Server Function (Adapted from appTester.py, with refined logging) ---
def test_server(server_info, config, local_port, log_queue):
    process = None
    config_path = None
    test_success = False
    error_message = "Test did not complete"
    response_time = -1.0

    try:
        # Ensure V2Ray directory exists
        os.makedirs(V2RAY_DIR, exist_ok=True)
        v2ray_executable_path = os.path.join(V2RAY_DIR, V2RAY_BIN)

        if not os.path.exists(v2ray_executable_path):
            raise FileNotFoundError(f"V2Ray executable not found at {v2ray_executable_path}")
        if not os.access(v2ray_executable_path, os.X_OK):
             # Attempt to make it executable on Linux/Mac
             if platform.system() != "Windows":
                  try:
                       os.chmod(v2ray_executable_path, 0o755)
                       logging.info(f"Made {v2ray_executable_path} executable.")
                  except Exception as chmod_err:
                       raise PermissionError(f"V2Ray not executable and chmod failed: {chmod_err} at {v2ray_executable_path}")
             else:
                  raise PermissionError(f"V2Ray not executable: {v2ray_executable_path}")


        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as f:
            json.dump(config, f, indent=2) # Add indent for readability if debugging manually
            config_path = f.name
        logging.debug(f"Using temp config: {config_path} for {server_info.get('host')}:{server_info.get('port')}")

        # Construct V2Ray command
        cmd = [v2ray_executable_path, 'run', '--config', config_path]
        logging.debug(f"Running V2Ray command: {' '.join(cmd)}")

        # Start V2Ray process
        # Use DETACHED_PROCESS or CREATE_NO_WINDOW on Windows? Maybe not necessary.
        # Capture stderr for better error reporting
        process = subprocess.Popen(
            cmd,
            cwd=V2RAY_DIR, # Run from V2Ray directory
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8', # Decode stdout/stderr
            # Close file handles in child process on Unix-like systems
            close_fds=(platform.system() != 'Windows')
        )

        # Wait for V2Ray to potentially start and listen
        logging.debug(f"Waiting {PROCESS_START_WAIT}s for V2Ray process ({process.pid}) to start...")
        try:
             # Wait for a short time, checking if process exited early
             process.wait(timeout=PROCESS_START_WAIT)
             # If wait() returns, process has exited
             stderr_output = process.stderr.read()
             stdout_output = process.stdout.read()
             raise RuntimeError(f"V2Ray process exited prematurely (code {process.returncode}). Stderr: {stderr_output[:500]}... Stdout: {stdout_output[:500]}...")
        except subprocess.TimeoutExpired:
             # Process is still running, likely started successfully
             logging.debug(f"V2Ray process ({process.pid}) seems to be running.")
             pass # Continue to testing

        # If process exited somehow *after* timeout check (race condition?)
        if process.poll() is not None:
             stderr_output = process.stderr.read()
             stdout_output = process.stdout.read()
             raise RuntimeError(f"V2Ray process exited unexpectedly after wait (code {process.returncode}). Stderr: {stderr_output[:500]}... Stdout: {stdout_output[:500]}...")


        # Define proxies for the request
        proxies = {
            'http': f'socks5h://127.0.0.1:{local_port}', # Use socks5h for DNS resolution through proxy
            'https': f'socks5h://127.0.0.1:{local_port}'
        }
        logging.debug(f"Testing connection to {TEST_LINK} via proxy 127.0.0.1:{local_port}")

        # Perform the actual test request
        start_time = time.monotonic() # Use monotonic clock for duration
        try:
            response = requests.get(
                TEST_LINK,
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
                verify=False, # Disable SSL verification for the test request itself
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ProxyTester/1.0)'} # Identify tester
            )
            elapsed = time.monotonic() - start_time
            response_time = elapsed

            # Check response status
            if response.status_code == 200:
                # Optional: Check response content if needed
                # e.g., if 'origin' in response.json():
                test_success = True
                error_message = f"{response.status_code} OK"
                logging.info(f"✅ Success ({response_time:.2f}s) - {server_info.get('protocol')} {server_info.get('host')}:{server_info.get('port')}")
            else:
                test_success = False
                error_message = f"HTTP Status {response.status_code}"
                logging.warning(f"⚠️ Failed ({error_message}) - {server_info.get('protocol')} {server_info.get('host')}:{server_info.get('port')}")

        except requests.exceptions.Timeout:
            elapsed = time.monotonic() - start_time
            test_success = False
            error_message = f"Request Timeout ({elapsed:.1f}s > {REQUEST_TIMEOUT}s)"
            logging.warning(f"⚠️ Failed ({error_message}) - {server_info.get('protocol')} {server_info.get('host')}:{server_info.get('port')}")
        except requests.exceptions.ProxyError as pe:
            elapsed = time.monotonic() - start_time
            test_success = False
            error_message = f"Proxy Error: {str(pe)[:100]}" # Keep message concise
            logging.warning(f"⚠️ Failed ({error_message}) - {server_info.get('protocol')} {server_info.get('host')}:{server_info.get('port')}")
        except requests.exceptions.RequestException as e:
            elapsed = time.monotonic() - start_time
            test_success = False
            error_message = f"Request Exception: {str(e)[:100]}"
            logging.warning(f"⚠️ Failed ({error_message}) - {server_info.get('protocol')} {server_info.get('host')}:{server_info.get('port')}")


    except FileNotFoundError as fnf_err:
         test_success = False
         error_message = f"Setup Error: {str(fnf_err)}"
         logging.error(f"❌ Setup Error for {server_info.get('host')}: {fnf_err}")
    except PermissionError as perm_err:
         test_success = False
         error_message = f"Permission Error: {str(perm_err)}"
         logging.error(f"❌ Permission Error for {server_info.get('host')}: {perm_err}")
    except RuntimeError as rt_err: # Catch V2Ray start/exit errors
         test_success = False
         error_message = f"V2Ray Runtime Error: {str(rt_err)[:150]}"
         logging.error(f"❌ V2Ray Error for {server_info.get('host')}: {rt_err}")
    except Exception as e:
        # Catch any other unexpected errors during setup or testing
        test_success = False
        error_message = f"Unexpected Test Error: {str(e)[:150]}"
        logging.error(f"❌ Unexpected Error testing {server_info.get('host')}: {e}", exc_info=False) # Set exc_info=True for full traceback in log file
    finally:
        # --- Cleanup ---
        # Terminate V2Ray process
        if process and process.poll() is None: # Check if process exists and is running
            logging.debug(f"Terminating V2Ray process ({process.pid})...")
            try:
                 # Try graceful termination first
                 process.terminate()
                 try:
                      # Wait briefly for termination
                      process.wait(timeout=5)
                      logging.debug(f"V2Ray process ({process.pid}) terminated gracefully.")
                 except subprocess.TimeoutExpired:
                      # Force kill if terminate didn't work
                      logging.warning(f"V2Ray process ({process.pid}) did not terminate gracefully, killing.")
                      process.kill()
                      process.wait(timeout=2) # Wait briefly after kill
                      logging.debug(f"V2Ray process ({process.pid}) killed.")
            except Exception as term_err:
                logging.error(f"Error terminating/killing V2Ray process ({process.pid}): {term_err}")

        # Remove temporary config file
        if config_path and os.path.exists(config_path):
            logging.debug(f"Removing temp config file: {config_path}")
            try:
                os.remove(config_path)
            except Exception as rm_err:
                # Non-critical error, just log it
                logging.warning(f"Could not remove temp config file {config_path}: {rm_err}")

        # Send result to the logger thread
        if test_success:
            log_queue.put(('success', server_info, f"{response_time:.2f}s"))
        else:
            log_queue.put(('failure', server_info, error_message))


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


# Helper functions for install_v2ray to query GitHub API
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

_latest_release_data = None # Cache release data

def asset_name_exists(asset_name):
     """Checks if a specific asset name exists in the latest release."""
     global _latest_release_data
     if _latest_release_data is None:
          _latest_release_data = get_github_latest_release_data()

     if _latest_release_data and 'assets' in _latest_release_data:
          for asset in _latest_release_data['assets']:
               if asset.get('name') == asset_name:
                    return True
     return False

def get_asset_download_url(asset_name):
    """Finds the download URL for a specific asset in the latest release."""
    global _latest_release_data
    if _latest_release_data is None:
        _latest_release_data = get_github_latest_release_data()

    if _latest_release_data and 'assets' in _latest_release_data:
        for asset in _latest_release_data['assets']:
            if asset.get('name') == asset_name:
                url = asset.get('browser_download_url')
                logging.debug(f"Found download URL for {asset_name}: {url}")
                return url
    logging.error(f"Asset '{asset_name}' not found in the latest GitHub release.")
    return None


# --- Logger Thread (Using the simpler version from appTester.py for now) ---
def logger_thread(log_queue):
    """Logs test results to console and files."""
    protocols_dir = os.path.join(TESTED_SERVERS_DIR, 'Protocols')
    os.makedirs(protocols_dir, exist_ok=True)

    # Define output files within TESTED_SERVERS_DIR
    working_file = os.path.join(TESTED_SERVERS_DIR, 'working_servers.txt')
    dead_file = os.path.join(TESTED_SERVERS_DIR, 'dead_servers.txt')
    skip_file = os.path.join(TESTED_SERVERS_DIR, 'skipped_servers.txt')

    # Counters
    counts = {'success': 0, 'failure': 0, 'skip': 0, 'received': 0}
    protocol_success_counts = defaultdict(int)

    # Open files in append mode, ensuring directory exists
    os.makedirs(TESTED_SERVERS_DIR, exist_ok=True)
    try:
        with open(working_file, 'w', encoding='utf-8') as working_f, \
             open(dead_file, 'w', encoding='utf-8') as dead_f, \
             open(skip_file, 'w', encoding='utf-8') as skip_f:

            start_time = time.monotonic()
            total_servers_to_process = 0 # Will be set by the 'received' count

            while True:
                try:
                    # Use timeout to periodically print progress
                    record = log_queue.get(timeout=5.0) # Check every 5 seconds
                except queue.Empty:
                    # Print progress if queue is empty for a while
                    if total_servers_to_process > 0:
                         processed = counts['success'] + counts['failure'] + counts['skip']
                         elapsed = time.monotonic() - start_time
                         percent = (processed / total_servers_to_process) * 100 if total_servers_to_process else 0
                         logging.info(f"⏳ Progress: {processed}/{total_servers_to_process} ({percent:.1f}%) | Active: {counts['success']} | Failed: {counts['failure']} | Skipped: {counts['skip']} | Time: {elapsed:.1f}s")
                    continue # Go back to waiting for queue items

                if record is None: # Sentinel value to stop the thread
                    logging.info("Logger thread received stop signal.")
                    break

                status, server_info, message = record

                # Increment total count when a server is first received
                if status == 'received':
                     counts['received'] += 1
                     total_servers_to_process = counts['received'] # Update total expected
                     continue # Don't log 'received' status further

                # Should always have 'original_link' after 'received' check
                link = server_info.get('original_link', 'UNKNOWN_LINK')
                protocol = server_info.get('protocol', 'unknown').lower()
                host = server_info.get('host', 'N/A')
                port = server_info.get('port', 'N/A')

                # Update counts
                if status in counts:
                    counts[status] += 1
                else:
                     logging.warning(f"Unknown status received in logger: {status}")

                # Log based on status
                log_func = logging.info # Default for success/skip
                if status == 'failure':
                    log_func = logging.warning # Use warning for failures
                elif status == 'success':
                     protocol_success_counts[protocol] += 1


                # Log message format for console/debug log (already handled by test_server)
                # log_func(f"{status.upper():<7} | {protocol:<8} | {host}:{port} | {message} | Link: {link[:40]}...")


                # Write to respective files
                try:
                    if status == 'success':
                        working_f.write(f"{link}\n")
                        working_f.flush() # Ensure it's written immediately

                        # Write to protocol-specific file
                        protocol_file = os.path.join(protocols_dir, f"{protocol}.txt")
                        # Open protocol file in append mode each time or keep handles open?
                        # Appending each time is safer for concurrency but slower.
                        with open(protocol_file, 'a', encoding='utf-8') as pf:
                            pf.write(f"{link}\n")
                            # No need to flush within 'with open'

                    elif status == 'failure':
                        dead_f.write(f"{link} | Reason: {message}\n")
                        dead_f.flush()
                    elif status == 'skip':
                        skip_f.write(f"{link} | Reason: {message}\n")
                        skip_f.flush()
                except Exception as write_e:
                     logging.error(f"Error writing link {link} to output file: {write_e}")


                # Log progress periodically based on count, not just timeout
                processed = counts['success'] + counts['failure'] + counts['skip']
                if processed % 50 == 0 and processed > 0: # Log every 50 processed servers
                     elapsed = time.monotonic() - start_time
                     percent = (processed / total_servers_to_process) * 100 if total_servers_to_process else 0
                     logging.info(f"⏳ Progress: {processed}/{total_servers_to_process} ({percent:.1f}%) | Active: {counts['success']} | Failed: {counts['failure']} | Skipped: {counts['skip']} | Time: {elapsed:.1f}s")


    except Exception as e:
        logging.error(f"Critical error in logger thread: {e}", exc_info=True)
    finally:
        # Final Summary Report
        logging.info("\n" + "="*20 + " Testing Summary " + "="*20)
        total_processed = counts['success'] + counts['failure'] + counts['skip']
        total_received = counts['received']
        if total_received != total_processed:
             logging.warning(f"Mismatch: Received {total_received} servers, but processed {total_processed} results.")

        logging.info(f"Total Servers Tested: {total_processed}")
        logging.info(f"  ✅ Active:   {counts['success']}")
        logging.info(f"  ❌ Failed:   {counts['failure']}")
        logging.info(f"  ➖ Skipped:  {counts['skip']}")
        logging.info("-" * 50)
        logging.info("Active Servers by Protocol:")
        if protocol_success_counts:
             # Sort by count descending
             sorted_protocols = sorted(protocol_success_counts.items(), key=lambda item: item[1], reverse=True)
             for proto, count in sorted_protocols:
                  logging.info(f"  {proto.upper():<10}: {count}")
        else:
             logging.info("  (No servers were successfully tested)")
        logging.info("="*58)
        logging.info(f"Working servers saved to: {working_file}")
        logging.info(f"Failed servers saved to: {dead_file}")
        logging.info(f"Skipped servers saved to: {skip_file}")


# ========================
# Main Execution
# ========================
if __name__ == "__main__":

    # --- Part 1: Extraction from Telegram ---
    logging.info("--- Starting Part 1: Telegram Channel Scraping ---")
    channels_file = CHANNELS_FILE
    try:
        if not os.path.exists(channels_file):
             logging.error(f"Telegram sources file not found: {channels_file}")
             sys.exit(1)

        with open(channels_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

        normalized_urls = list({norm_url for url in raw_urls if (norm_url := normalize_telegram_url(url))}) # Normalize and unique
        normalized_urls.sort()

        # Optionally rewrite the file with normalized URLs
        # with open(channels_file, 'w', encoding='utf-8') as f:
        #     f.write('\n'.join(normalized_urls))

        logging.info(f"✅ Found {len(normalized_urls)} unique, normalized Telegram channels to process.")

    except Exception as e:
        logging.error(f"❌ Error processing Telegram channel list ({channels_file}): {e}")
        sys.exit(1)

    # Batch processing with rate limiting
    total_channels = len(normalized_urls)
    processed_channels = 0
    total_new_servers_added = 0
    failed_channel_fetches = 0

    for idx, channel_url in enumerate(normalized_urls, 1):
        logging.info(f"--- Processing Channel {idx}/{total_channels}: {channel_url} ---")
        success, new_servers = process_channel(channel_url)
        if success == 1: # Channel processed (even if 0 new servers found globally)
            processed_channels += 1
            total_new_servers_added += new_servers
            logging.info(f"✅ Finished Channel {idx}. Added {new_servers} new global servers.")
        else:
             failed_channel_fetches +=1
             logging.error(f"❌ Failed to process Channel {idx}: {channel_url}")


        # Sleep if batch size is reached and it's not the last channel
        if idx % BATCH_SIZE == 0 and idx < total_channels:
            logging.info(f"--- Processed batch of {BATCH_SIZE}, pausing for {SLEEP_TIME}s ---")
            time.sleep(SLEEP_TIME)

    logging.info(f"--- Telegram Scraping Finished ---")
    logging.info(f"Successfully processed {processed_channels}/{total_channels} channels.")
    if failed_channel_fetches > 0:
         logging.warning(f"{failed_channel_fetches} channels failed during processing.")
    logging.info(f"Added {total_new_servers_added} new unique servers globally.")

    # --- Part 2: GeoIP Processing ---
    logging.info("--- Starting Part 2: GeoIP Analysis ---")
    country_data = process_geo_data()
    if country_data:
         logging.info("✅ GeoIP analysis complete.")
    else:
         logging.warning("⚠️ GeoIP analysis could not be performed or yielded no results.")

    # --- Part 3: Extraction Report ---
    logging.info("--- Starting Part 3: Generating Extraction Report ---")
    try:
         channel_stats = get_channel_stats() # Get counts from channel files
         save_extraction_data(channel_stats, country_data)
         current_counts, _ = get_current_counts() # Recalculate final counts
         logging.info("\n✅ Extraction Phase Complete")
         logging.info(f"📊 Final Extraction Statistics:")
         logging.info(f"  Total Merged Servers: {current_counts.get('total', 0)}")
         logging.info(f"  GeoIP Successful:   {current_counts.get('successful', 0)}")
         logging.info(f"  GeoIP Failed:       {current_counts.get('failed', 0)}")
         # Log protocol counts
         for proto, count in current_counts.items():
              if proto not in ['total', 'successful', 'failed']:
                   logging.info(f"  {proto.upper():<10}: {count}")

         logging.info(f"Detailed report saved to: {LOG_FILE}")
         logging.info(f"Server files saved in: {os.path.join(BASE_DIR, 'Servers')}")

    except Exception as report_err:
         logging.error(f"❌ Failed to generate extraction report: {report_err}")

    # --- Part 4: Server Testing ---
    logging.info("\n--- Starting Part 4: Server Testing ---")

    # Clean previous *testing* results
    logging.info(f"Cleaning previous test results in: {TESTED_SERVERS_DIR}...")
    clean_directory(TESTED_SERVERS_DIR)
    # Recreate necessary subdirectories after cleaning
    os.makedirs(os.path.join(TESTED_SERVERS_DIR, 'Protocols'), exist_ok=True)

    # Load servers from the *Channel* files generated in Part 1
    # This ensures we test servers attributed to their source channel
    channel_files_dir = CHANNELS_DIR
    logging.info(f"Loading servers for testing from: {channel_files_dir}")
    channel_files = [f for f in os.listdir(channel_files_dir) if f.endswith('.txt')]

    if not channel_files:
        logging.error(f"😐 No channel files found in {channel_files_dir} to test servers from.")
        sys.exit(1)

    all_servers_to_test = []
    servers_read_count = 0
    parsing_errors = defaultdict(int)
    protocol_counts = defaultdict(int)
    skipped_disabled = 0

    for channel_filename in channel_files:
        file_path = os.path.join(channel_files_dir, channel_filename)
        # Channel name is filename without extension
        channel_name = os.path.splitext(channel_filename)[0]
        # Read links from this channel's file
        servers = read_links_from_file(file_path)
        servers_read_count += len(servers)

        for link in servers:
            try:
                parsed_url = urlparse(link)
                proto = parsed_url.scheme.lower()

                # Skip if protocol is not recognized or explicitly disabled
                if proto not in ENABLED_PROTOCOLS:
                    # logging.debug(f"Skipping unsupported protocol {proto.upper()} from {channel_filename}: {link[:40]}...")
                    parsing_errors[f"unsupported_{proto}"] += 1
                    continue
                if not ENABLED_PROTOCOLS[proto]:
                     # logging.debug(f"Skipping disabled protocol {proto.upper()} from {channel_filename}: {link[:40]}...")
                     parsing_errors["disabled"] += 1
                     skipped_disabled += 1
                     continue

                # Attempt to parse the link based on protocol
                server_info = None
                try:
                    if proto == 'vless':
                        server_info = parse_vless_link(link)
                    elif proto == 'vmess':
                        server_info = parse_vmess_link(link)
                    elif proto == 'trojan':
                        server_info = parse_trojan_link(link)
                    elif proto == 'ss': # Ensure 'ss' is handled if enabled
                        server_info = parse_ss_link(link)
                    # Add other enabled protocols here if needed
                    # elif proto == 'hysteria': server_info = parse_hysteria_link(link)
                    # ...

                    if server_info:
                         # Add the source file (channel name) to the info dict
                         server_info['source_file'] = channel_name
                         all_servers_to_test.append(server_info)
                         protocol_counts[proto] += 1
                    else:
                         # This case should ideally not happen if proto is in ENABLED_PROTOCOLS
                         logging.warning(f"Parser not implemented or returned None for enabled protocol {proto} in {channel_filename}: {link[:60]}...")
                         parsing_errors[f"parse_no_impl_{proto}"] += 1

                except ValueError as parse_ve:
                     logging.warning(f"Invalid {proto.upper()} link format in {channel_filename} ({parse_ve}): {link[:60]}...")
                     parsing_errors[f"parse_invalid_{proto}"] += 1
                except Exception as parse_e:
                    logging.error(f"General parsing error for link in {channel_filename} ({type(parse_e).__name__}: {parse_e}): {link[:60]}...")
                    parsing_errors["parse_general"] += 1

            except Exception as outer_e:
                # Catch errors like urlparse failing on malformed input
                logging.error(f"Error processing link line from {channel_filename} ({type(outer_e).__name__}: {outer_e}): {link[:60]}...")
                parsing_errors["outer_processing"] += 1


    # Report loading summary
    logging.info(f"Read {servers_read_count} links from {len(channel_files)} channel files.")
    logging.info(f"Prepared {len(all_servers_to_test)} valid servers for testing.")
    if skipped_disabled > 0:
         logging.info(f"Skipped {skipped_disabled} servers due to disabled protocols.")
    if parsing_errors:
        logging.warning("Parsing issues encountered:")
        for error_type, count in parsing_errors.items():
             logging.warning(f"  - {error_type}: {count}")
    logging.info("Servers per enabled protocol:")
    for proto, count in protocol_counts.items():
         logging.info(f"  - {proto.upper()}: {count}")


    if not all_servers_to_test:
        logging.error("❌ No valid and enabled servers found to test after parsing. Exiting.")
        sys.exit(1)


    # Check/Install V2Ray
    parser = argparse.ArgumentParser(description="Scrape Telegram for proxies and test them.")
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS,
                        help=f"Maximum number of testing threads (default: {MAX_THREADS})")
    parser.add_argument('--skip-install', action='store_true',
                        help="Skip V2Ray check and installation attempt.")
    args = parser.parse_args()

    MAX_THREADS = args.max_threads # Update MAX_THREADS from command line arg

    logging.info("\n--- V2Ray Check ---")
    logging.info(f"Using V2Ray directory: {V2RAY_DIR}")
    if not args.skip_install:
         installed_version = check_v2ray_installed()
         latest_version = get_latest_version()

         logging.info(f"Installed V2Ray version: {installed_version or 'Not found'}")
         logging.info(f"Latest V2Ray version (GitHub): {latest_version or 'Could not fetch'}")

         # Install if not installed, or if versions mismatch (and latest is known)
         needs_install = False
         if not installed_version:
              logging.warning("V2Ray not found or version check failed.")
              needs_install = True
         elif latest_version and installed_version != latest_version:
              logging.warning(f"Installed V2Ray version ({installed_version}) differs from latest ({latest_version}).")
              needs_install = True
         # Add condition to install even if latest_version fetch failed? Maybe only if not installed.
         # elif not latest_version and not installed_version: needs_install = True


         if needs_install:
              logging.info("🚀 Attempting V2Ray installation...")
              install_v2ray()
              # Re-check version after install attempt
              installed_version = check_v2ray_installed()
              if not installed_version:
                   logging.critical("V2Ray installation attempted but failed or version check still fails. Exiting.")
                   sys.exit(1)
              logging.info(f"Using newly installed V2Ray version: {installed_version}")
         else:
              logging.info(f"✅ Using existing V2Ray version: {installed_version}")
    else:
         logging.warning("Skipping V2Ray check and installation as requested (--skip-install).")
         # Check if it exists anyway, otherwise testing will fail
         if not check_v2ray_installed():
              logging.error("V2Ray check skipped, but V2Ray not found or not working. Testing cannot proceed.")
              sys.exit(1)


    # Start testing using ThreadPoolExecutor
    logging.info(f"\n--- Starting Server Testing ({MAX_THREADS} threads) ---")
    log_queue = queue.Queue()
    # Start the logger thread (using the simpler version adopted from appTester.py)
    logger_t = threading.Thread(target=logger_thread, args=(log_queue,), name="LoggerThread")
    logger_t.daemon = True # Allow main thread to exit even if logger is stuck
    logger_t.start()

    # First, put all servers onto the queue with 'received' status for accurate total count
    for server_info in all_servers_to_test:
        log_queue.put(('received', server_info, None))

    # Use ThreadPoolExecutor for managing worker threads
    with ThreadPoolExecutor(max_workers=MAX_THREADS, thread_name_prefix="Tester") as executor:
        futures = []
        for server_info in all_servers_to_test:
            try:
                # Protocol should have been checked already, but double-check just in case
                proto = server_info['protocol']
                if proto not in ENABLED_PROTOCOLS or not ENABLED_PROTOCOLS[proto]:
                    # This shouldn't happen if loading logic is correct, but log if it does
                    log_queue.put(('skip', server_info, "Protocol disabled unexpectedly"))
                    continue

                local_port = get_next_port()
                logging.debug(f"Generating config for {proto} server {server_info['host']}:{server_info['port']} on local port {local_port}")
                config = generate_config(server_info, local_port)

                # Submit the test task to the executor
                future = executor.submit(test_server, server_info, config, local_port, log_queue)
                futures.append(future)

            except ValueError as config_ve: # Catch config generation value errors (e.g., missing fields)
                 error_msg = f"Config generation error: {str(config_ve)[:150]}"
                 logging.error(f"❌ {error_msg} for link: {server_info.get('original_link', 'N/A')}")
                 # Send failure to logger queue directly
                 log_queue.put(('failure', server_info, error_msg))
            except Exception as e:
                # Catch any other errors during config generation or submission
                error_msg = f"Error preparing test: {str(e)[:150]}"
                logging.error(f"❌ {error_msg} for link: {server_info.get('original_link', 'N/A')}", exc_info=False)
                log_queue.put(('failure', server_info, error_msg))


        # Wait for all submitted tasks to complete
        logging.info(f"Submitted {len(futures)} testing tasks. Waiting for completion...")
        # Optional: Use concurrent.futures.as_completed for real-time results if needed
        # for future in concurrent.futures.as_completed(futures):
        #     try: future.result() # Access result/exception if needed here
        #     except Exception as e: logging.error(f"A test task raised an exception: {e}")
        # Wait for all futures to finish processing
        for future in futures:
             try:
                  future.result() # Wait for task completion and retrieve potential exceptions
             except Exception as future_ex:
                  # Exceptions from within test_server should ideally be caught there
                  # and put on the queue. This catches unexpected errors in the future itself.
                  logging.error(f"A testing future completed with an unexpected error: {future_ex}", exc_info=False)


    # Signal the logger thread to finish and wait for it
    logging.info("All testing tasks completed. Signaling logger thread to stop...")
    log_queue.put(None) # Send sentinel value
    logger_t.join(timeout=10) # Wait for logger thread to finish writing
    if logger_t.is_alive():
         logging.warning("Logger thread did not exit cleanly after 10 seconds.")

    logging.info("--- Testing Phase Complete ---")

