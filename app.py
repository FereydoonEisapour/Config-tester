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
from urllib.parse import urlparse, parse_qs, unquote
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from bs4 import BeautifulSoup
import base64

# Constants
V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
V2RAY_DIR = os.path.join(os.getcwd(), 'v2ray')
LOG_DIR = 'logs'
TEST_LINK = "https://www.google.com"
MAX_THREADS = 8  # Optimized for GitHub Actions
START_PORT = 3000  # Allowed port range for CI
REQUEST_TIMEOUT = 10
PROCESS_START_WAIT = 2

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Thread-safe port counter
current_port = START_PORT
port_lock = threading.Lock()

def initialize_directories():
    """Create required directories and default files"""
    required_dirs = [
        'Files',
        'Tested Servers/Protocols',
        LOG_DIR,
        V2RAY_DIR
    ]
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)
    
    # Create default git_links.txt if missing
    if not os.path.exists('Files/git_links.txt'):
        with open('Files/git_links.txt', 'w') as f:
            f.write("https://github.com/XTLS/Xray-core\n")
            f.write("https://github.com/v2fly/v2ray-core\n")

def get_next_port():
    """Safely allocate ports in multi-threaded environment"""
    global current_port
    with port_lock:
        port = current_port
        current_port += 1
    return port

def download_content(url):
    """Download content from URL with error handling"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"Error fetching {url}: {str(e)}")
        return None

def read_links_from_file(file_path):
    """Read links from text file"""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return []

def remove_duplicate_links(input_file):
    """Remove duplicate links from input file"""
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            links = list(set(file.read().splitlines()))
        
        with open(input_file, "w", encoding="utf-8") as file:
            file.write("\n".join(links))
        
        logging.info(f"Removed duplicates. {len(links)} unique links remain.")
        return links
    except Exception as e:
        logging.error(f"Error removing duplicates: {str(e)}")
        return []

def process_and_save_links(links, output_folder):
    """Process links and categorize by protocol"""
    server_count = {}
    processed = set()
    
    for link in links:
        content = download_content(link)
        if not content:
            continue
            
        for line in content.splitlines():
            line = line.strip()
            if not line or line in processed:
                continue
                
            processed.add(line)
            
            # Classify protocols
            if line.startswith(('ss://', 'vmess://', 'vless://')):
                protocol = line.split('://')[0]
                server_count[protocol] = server_count.get(protocol, 0) + 1
                save_path = os.path.join(output_folder, f'{protocol}.txt')
                with open(save_path, 'a') as f:
                    f.write(f"{line}\n")
                    
    logging.info("Server classification completed:")
    for proto, count in server_count.items():
        logging.info(f"{proto}: {count} servers")

def check_v2ray_installed():
    """Check if V2Ray is properly installed"""
    try:
        result = subprocess.run(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), '--version'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        return result.stdout.decode().split()[1]
    except Exception:
        return None

def install_v2ray():
    """Install V2Ray with GitHub Actions compatibility"""
    try:
        # Clean existing installation
        if os.path.exists(V2RAY_DIR):
            shutil.rmtree(V2RAY_DIR)
            
        # Get latest version
        response = requests.get(
            'https://api.github.com/repos/v2fly/v2ray-core/releases/latest',
            timeout=5
        )
        version = response.json()['tag_name'].lstrip('v')
        
        # Download and extract
        url = f'https://github.com/v2fly/v2ray-core/releases/download/v{version}/v2ray-linux-64.zip'
        zip_path = os.path.join(V2RAY_DIR, 'v2ray.zip')
        
        os.makedirs(V2RAY_DIR, exist_ok=True)
        
        # Download using curl
        subprocess.run(
            f'curl -L {url} -o {zip_path}',
            shell=True, check=True
        )
        
        # Extract and set permissions
        subprocess.run(
            f'unzip -o {zip_path} -d {V2RAY_DIR}',
            shell=True, check=True
        )
        os.chmod(os.path.join(V2RAY_DIR, V2RAY_BIN), 0o755)
        
        logging.info(f"V2Ray {version} installed successfully")
        
    except Exception as e:
        logging.critical(f"V2Ray installation failed: {str(e)}")
        sys.exit(1)

# --- Protocol Parsers ---
def parse_vless_link(link):
    """Parse VLESS link into configuration"""
    parsed = urlparse(link)
    query = parse_qs(parsed.query)
    return {
        'protocol': 'vless',
        'uuid': parsed.username,
        'host': parsed.hostname,
        'port': parsed.port,
        'security': query.get('security', [''])[0] or 'none',
        'network': query.get('type', ['tcp'])[0],
        'sni': query.get('sni', [parsed.hostname])[0],
        'original_link': link
    }

def parse_vmess_link(link):
    """Parse VMess link into configuration"""
    base64_data = link.split('://')[1]
    decoded = urlsafe_b64decode(base64_data + '==').decode('utf-8')
    data = json.loads(decoded)
    return {
        'protocol': 'vmess',
        'uuid': data.get('id'),
        'host': data.get('add'),
        'port': data.get('port'),
        'network': data.get('net', 'tcp'),
        'security': data.get('tls', 'none'),
        'original_link': link
    }

def parse_ss_link(link):
    """Parse Shadowsocks link into configuration"""
    decoded = urlsafe_b64decode(link.split('://')[1] + '==').decode('utf-8')
    parts = decoded.split('@')
    method, password = parts[0].split(':')
    host, port = parts[1].split(':')
    return {
        'protocol': 'shadowsocks',
        'method': method,
        'password': password,
        'host': host,
        'port': int(port),
        'original_link': link
    }

# --- Core Testing Logic ---
def generate_config(server_info, local_port):
    """Generate V2Ray configuration JSON"""
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
    
    # Protocol-specific settings
    if server_info['protocol'] == 'vless':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{"id": server_info['uuid']}]
            }]
        }
    elif server_info['protocol'] == 'vmess':
        config['outbounds'][0]['settings'] = {
            "vnext": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "users": [{"id": server_info['uuid']}]
            }]
        }
    elif server_info['protocol'] == 'shadowsocks':
        config['outbounds'][0]['settings'] = {
            "servers": [{
                "address": server_info['host'],
                "port": server_info['port'],
                "method": server_info['method'],
                "password": server_info['password']
            }]
        }
    
    return config

def test_server(server_info, config, local_port, log_queue):
    """Test server connectivity"""
    process = None
    config_path = None
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
            json.dump(config, f)
            config_path = f.name
            
        # Start V2Ray process
        process = subprocess.Popen(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), 'run', '--config', config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(PROCESS_START_WAIT)
        
        # Test connection
        proxies = {'http': f'socks5://127.0.0.1:{local_port}'}
        start_time = time.time()
        response = requests.get(TEST_LINK, proxies=proxies, 
                              timeout=REQUEST_TIMEOUT, verify=False)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            log_queue.put(('success', server_info, f"Connected ({elapsed:.2f}s)"))
        else:
            log_queue.put(('failure', server_info, f"HTTP Error {response.status_code}"))
            
    except Exception as e:
        log_queue.put(('failure', server_info, f"Error: {str(e)}"))
    finally:
        if process:
            process.terminate()

def logger_thread(log_queue, log_file, working_file, dead_file):
    """Handle logging and result categorization"""
    with open(log_file, 'a') as log_f, \
         open(working_file, 'a') as working_f, \
         open(dead_file, 'a') as dead_f:
         
        while True:
            record = log_queue.get()
            if record is None:
                break
            status, server_info, message = record
            
            # Write to main log
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = (
                f"[{timestamp}] {server_info['protocol']}://{server_info['host']}:{server_info['port']} | "
                f"Message: {message}\n"
            )
            log_f.write(log_entry)
            
            # Categorize results
            if status == 'success':
                working_f.write(f"{server_info['original_link']}\n")
            else:
                dead_f.write(f"{server_info['original_link']}\n")

if __name__ == "__main__":
    initialize_directories()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(LOG_DIR, 'debug.log')),
            logging.StreamHandler()
        ]
    )
    
    # Install V2Ray if missing
    if not check_v2ray_installed():
        install_v2ray()
    
    # Process input links
    input_file = 'Files/git_links.txt'
    unique_links = remove_duplicate_links(input_file)
    output_folder = 'Files/ServerByType'
    process_and_save_links(unique_links, output_folder)
    
    # Configure arguments
    parser = argparse.ArgumentParser(description='Proxy Server Tester')
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS)
    args = parser.parse_args()
    
    # Initialize logging system
    log_queue = queue.Queue()
    logger = threading.Thread(
        target=logger_thread,
        args=(
            log_queue,
            os.path.join(LOG_DIR, 'latest.log'),
            os.path.join('Tested Servers', 'working.txt'),
            os.path.join('Tested Servers', 'dead.txt')
        )
    )
    logger.start()
    
    # Collect servers for testing
    servers = []
    for proto_file in os.listdir(output_folder):
        if proto_file.endswith('.txt'):
            with open(os.path.join(output_folder, proto_file), 'r') as f:
                servers.extend(f.read().splitlines())
    
    # Execute tests
    with ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        futures = []
        for link in servers:
            try:
                if link.startswith('vless://'):
                    server_info = parse_vless_link(link)
                elif link.startswith('vmess://'):
                    server_info = parse_vmess_link(link)
                elif link.startswith('ss://'):
                    server_info = parse_ss_link(link)
                else:
                    continue
                
                local_port = get_next_port()
                config = generate_config(server_info, local_port)
                futures.append(executor.submit(test_server, server_info, config, local_port, log_queue))
            except Exception as e:
                logging.error(f"Error processing {link}: {str(e)}")
        
        for future in futures:
            future.result()
    
    log_queue.put(None)
    logger.join()
    logging.info("Testing process completed!")