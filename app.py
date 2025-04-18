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
from base64 import urlsafe_b64decode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from bs4 import BeautifulSoup
import base64

# Constants
V2RAY_BIN = 'v2ray' if platform.system() == 'Linux' else 'v2ray.exe'
V2RAY_DIR = 'v2ray'
LOG_DIR = 'logs'
TEST_LINK = "http://httpbin.org/get"
MAX_THREADS = 10
START_PORT = 20000
REQUEST_TIMEOUT = 15
PROCESS_START_WAIT = 3

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

# First part - Link processing functions
def download_content(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
    return None

def read_links_from_file(file_path):
    try:  
        with open(file_path, "r", encoding="utf-8") as file:
            links = file.readlines()
        links = [link.strip() for link in links if link.strip()]
        return links
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return []

def remove_duplicate_links(input_file):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            links = file.readlines()
        
        unique_links = list(set([link.strip() for link in links if link.strip()]))
        
        with open(input_file, "w", encoding="utf-8") as file:
            for link in unique_links:
                file.write(link + "\n")
        
        logging.info(f"Duplicate links removed. {len(unique_links)} unique links remain in {input_file}.")
        return unique_links
    except FileNotFoundError:
        logging.error(f"File {input_file} not found.")
        return []
    except Exception as e:
        logging.error(f"Error removing duplicate links: {e}")
        return []

def process_and_save_links(links, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    def is_base64(s):
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False
    
    server_count = {}
    processed_lines = set()
    
    for index, link in enumerate(links):
        logging.info(f"Processing raw content from link {index + 1}: {link}")
        content = download_content(link)
        if content:
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line in processed_lines:
                    continue
                
                processed_lines.add(line)
                
                if line.startswith(('ss://', 'vmess://', 'vless://', 'hysteria://', 'tuic://', 'h2://', 'trojan://')):
                    server_type = line.split("://")[0]
                    output_file = os.path.join(output_folder, f'{server_type.lower()}.txt')
                    with open(output_file, 'a', encoding='utf-8') as out_file:
                        out_file.write(line + '\n')
                    server_count[server_type] = server_count.get(server_type, 0) + 1
                
                elif line.startswith("hysteria2://"):
                    server_type = "hysteria2"
                    output_file = os.path.join(output_folder, f'{server_type.lower()}.txt')
                    with open(output_file, 'a', encoding='utf-8') as out_file:
                        out_file.write(line + '\n')
                    server_count[server_type] = server_count.get(server_type, 0) + 1
                
                elif is_base64(line):
                    try:
                        decoded = base64.b64decode(line).decode('utf-8')
                        json_data = json.loads(decoded)
                        server_type = json_data.get('ps', 'unknown').lower()
                        output_file = os.path.join(output_folder, f'{server_type}.txt')
                        with open(output_file, 'a', encoding='utf-8') as out_file:
                            out_file.write(json.dumps(json_data, ensure_ascii=False) + '\n')
                        server_count[server_type] = server_count.get(server_type, 0) + 1
                    except Exception:
                        pass

    logging.info("Server count by type:")
    for server_type, count in server_count.items():
        logging.info(f"{server_type}: {count} servers")

def extract_links_from_file(input_file, output_file):
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            links = [line.strip() for line in file if line.strip()]
        
        all_extracted_links = set()
        
        for link in links:
            logging.info(f"Processing {link}...")
            try:
                response = requests.get(link)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                extracted_links = [a.get("href") for a in soup.find_all("a", href=True)]
                
                raw_links = []
                for extracted_link in extracted_links:
                    if extracted_link.startswith("http"):
                        raw_links.append(extracted_link)
                    elif extracted_link.startswith("/"):
                        raw_links.append(requests.compat.urljoin(link, extracted_link))
                
                filtered_links = [
                    rl.strip() for rl in raw_links 
                    if rl.strip().startswith(("https://github.com/", "https://raw.githubusercontent.com/")) and 
                    rl.strip().endswith((".txt", ".yaml", ".yml", ".md", ".conf"))
                ]
                
                raw_github_links = []
                for fl in filtered_links:
                    if "/blob/" in fl:
                        parts = fl.split("/")
                        username = parts[3]
                        repo = parts[4]
                        branch = parts[6]
                        path_to_file = "/".join(parts[7:])
                        raw_link = f"https://raw.githubusercontent.com/{username}/{repo}/{branch}/{path_to_file}"
                        raw_github_links.append(raw_link)
                    else:
                        raw_github_links.append(fl)
                
                all_extracted_links.update(raw_github_links)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching {link}: {e}")
        
        all_extracted_links = list(all_extracted_links)
        
        with open(output_file, "w", encoding="utf-8") as file:
            for link in all_extracted_links:
                file.write(link + "\n")
        
        logging.info(f"{len(all_extracted_links)} unique links extracted and saved to {output_file}.")
        return all_extracted_links
    except FileNotFoundError:
        logging.error(f"File {input_file} not found.")
        return []
    except Exception as e:
        logging.error(f"Unknown error: {e}")
        return []

# Second part - Testing functions
def check_v2ray_installed():
    try:
        result = subprocess.run(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), 'version'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
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
        if os_type == 'windows':
            url = f'{base_url}/v2ray-windows-64.zip'
        else:
            url = f'{base_url}/v2ray-linux-64.zip'

        if os.path.exists(V2RAY_DIR):
            shutil.rmtree(V2RAY_DIR, ignore_errors=True)
        os.makedirs(V2RAY_DIR, exist_ok=True)

        try:
            import zipfile
            import urllib.request
            zip_path, _ = urllib.request.urlretrieve(url)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(V2RAY_DIR)
            os.chmod(os.path.join(V2RAY_DIR, V2RAY_BIN), 0o755)
        except Exception as e:
            sys.exit(f"Installation failed: {e}")
    except Exception as e:
        logging.critical(f"V2Ray installation failed: {e}")
        sys.exit(1)


def parse_vless_link(link):
    parsed = urlparse(link)
    if parsed.scheme != 'vless':
        raise ValueError("Invalid VLESS link")
    query = parse_qs(parsed.query)
    return {
        'original_link': link,
        'protocol': 'vless',
        'uuid': parsed.username,
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
    if '@' in parsed.netloc:
        parts = parsed.netloc.split('@')
        method, password = parts[0].split(':')
        host, port = parts[1].split(':')
    else:
        decoded = urlsafe_b64decode(parsed.netloc + '==').decode('utf-8')
        method, password, host_port = decoded.split(':', 2)
        host, port = host_port.split('@')[1].split(':', 1)
    return {
        'original_link': link,
        'protocol': 'shadowsocks',
        'method': method,
        'password': password,
        'host': host,
        'port': int(port),
        'network': 'tcp'
    }

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
    stream = {k: v for k, v in stream.items() if v is not None}
    config['outbounds'][0]['streamSettings'] = stream
    config = {k: v for k, v in config.items() if v}
    return config

def test_server(server_info, config, local_port, log_queue):
    process = None
    config_path = None
    try:
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
            json.dump(config, f)
            config_path = f.name
        process = subprocess.Popen(
            [os.path.join(V2RAY_DIR, V2RAY_BIN), 'run', '--config', config_path],
            cwd=V2RAY_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(PROCESS_START_WAIT)
        if process.poll() is not None:
            raise RuntimeError("V2Ray process terminated prematurely")
        timeout = REQUEST_TIMEOUT * 1.5 if server_info.get('security') in ['tls', 'reality'] else REQUEST_TIMEOUT
        start_time = time.time()
        proxies = {
            'http': f'socks5h://127.0.0.1:{local_port}',
            'https': f'socks5h://127.0.0.1:{local_port}'
        }
        response = requests.get(
            TEST_LINK,
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        elapsed = time.time() - start_time
        if response.status_code in (200, 204):
            log_queue.put(('success', server_info, f"Success ({elapsed:.2f}s)"))
        else:
            log_queue.put(('failure', server_info, f"HTTP {response.status_code}"))
    except requests.exceptions.RequestException as e:
        log_queue.put(('failure', server_info, f"Request failed: {str(e)}"))
    except Exception as e:
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
            except Exception as e:
                print(f"Config cleanup failed: {e}")

def logger_thread(log_queue, log_file, working_file, dead_file):
    protocols_dir = os.path.join('Tested Servers', 'Protocols')
    os.makedirs(protocols_dir, exist_ok=True)
    
    with open(log_file, 'a') as log_f, \
         open(working_file, 'a') as working_f, \
         open(dead_file, 'a') as dead_f:
         
        while True:
            record = log_queue.get()
            if record is None:
                break
            status, server_info, message = record
            
            # Write to main log file
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = (
                f"[{timestamp}] Host: {server_info.get('host', 'N/A')}:{server_info.get('port', 'N/A')} | "
                f"Protocol: {server_info.get('protocol', 'N/A')} | "
                f"Security: {server_info.get('security', 'N/A')} | "
                f"Network: {server_info.get('network', 'N/A')} | "
                f"Message: {message}\n"
            )
            log_f.write(log_entry)
            
            # Write to working/dead files and protocol-specific files
            if status == 'success':
                working_f.write(f"{server_info.get('original_link', 'N/A')}\n")
                protocol = server_info.get('protocol', 'unknown').lower()
                protocol_file = os.path.join(protocols_dir, f'{protocol}.txt')
                with open(protocol_file, 'a') as pf:
                    pf.write(f"{server_info.get('original_link', 'N/A')}\n")
            else:
                dead_f.write(f"{server_info.get('original_link', 'N/A')}\n")
            
            # Flush all buffers
            log_f.flush()
            working_f.flush()
            dead_f.flush()

# Main execution
if __name__ == "__main__":
    # First part: Process and categorize links
    sys.stdout.reconfigure(encoding='utf-8')
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()]
    )
    
    input_file = os.path.join('files', 'git_links.txt')
    temp_output_file = os.path.join('files', 'filtered_links.txt')
    output_folder = os.path.join('files', 'ServerByType')
    
    logging.info("Starting link processing...")
    os.makedirs('files', exist_ok=True)
    unique_links = remove_duplicate_links(input_file)
    
    if not unique_links:
        logging.error("No valid links found in the input file after removing duplicates.")
        sys.exit(1)
    
    filtered_links = extract_links_from_file(input_file, temp_output_file)
    
    if filtered_links:
        process_and_save_links(filtered_links, output_folder)
        logging.info(f"All information processed and categorized into folder '{output_folder}'.")
    else:
        logging.error("No valid links were found during extraction.")
    
    # Second part: Test servers
    parser = argparse.ArgumentParser(description='Multi-Protocol Server Tester')
    parser.add_argument('--max-threads', type=int, default=MAX_THREADS)
    parser.add_argument('--servers-dir', default=output_folder)
    parser.add_argument('--log-dir', default=LOG_DIR)
    args = parser.parse_args()
    
    # Create required directories
    os.makedirs('Tested Servers', exist_ok=True)
    os.makedirs(os.path.join('Tested Servers', 'Protocols'), exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    
    log_file = os.path.join(args.log_dir, 'latest_log.txt')
    working_file = os.path.join('Tested Servers', 'working_servers.txt')
    dead_file = os.path.join('Tested Servers', 'dead_servers.txt')
    
    log_queue = queue.Queue()
    logger = threading.Thread(
        target=logger_thread,
        args=(log_queue, log_file, working_file, dead_file)
    )
    logger.start()
    
    installed_version = check_v2ray_installed()
    latest_version = get_latest_version()
    if installed_version and latest_version:
        if installed_version != latest_version:
            print(f"Updating V2Ray from {installed_version} to {latest_version}")
            install_v2ray()
        else:
            print(f"V2Ray {installed_version} is up to date")
    else:
        print("Installing V2Ray...")
        install_v2ray()
    
    try:
        servers = []
        servers_dir = args.servers_dir
        for filename in os.listdir(servers_dir):
            if filename.endswith('.txt'):
                file_path = os.path.join(servers_dir, filename)
                with open(file_path, 'r') as f:
                    servers.extend([line.strip() for line in f if line.strip()])
        if not servers:
            sys.exit(f"No servers found in {servers_dir}")
    except Exception as e:
        sys.exit(f"Error reading servers: {str(e)}")
    
    with ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        futures = []
        for link in servers:
            try:
                parsed = urlparse(link)
                if parsed.scheme == 'vless':
                    server_info = parse_vless_link(link)
                elif parsed.scheme == 'vmess':
                    server_info = parse_vmess_link(link)
                elif parsed.scheme == 'trojan':
                    server_info = parse_trojan_link(link)
                elif parsed.scheme == 'ss':
                    server_info = parse_ss_link(link)
                else:
                    raise ValueError(f"Unsupported protocol: {parsed.scheme}")
                local_port = get_next_port()
                config = generate_config(server_info, local_port)
                futures.append(executor.submit(test_server, server_info, config, local_port, log_queue))
            except Exception as e:
                log_queue.put(('failure', {'original_link': link}, f"Parse error: {str(e)}"))
        for future in futures:
            future.result()
    
    log_queue.put(None)
    logger.join()
    print(f"Testing completed. Results saved to Tested Servers/ and {args.log_dir}")