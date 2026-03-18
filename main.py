import urllib.parse
import requests
import os
import socket

# --- КОНФИГ ---
URL_LIST_FILE = 'Url.txt'
SNI_WHITELIST_FILE = 'SNI.txt'
RESULT_WHITE = 'whitelist_keys.txt'
RESULT_BLACK = 'blacklist_keys.txt'

def is_alive(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            return True
    except:
        return False

def get_geo(ip):
    try:
        # Используем API без ключа (лимит 45 запросов в минуту, для 100+ ключей пойдет)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if response.get('status') == 'success':
            code = response.get('countryCode', 'UN')
            flag = "".join(chr(ord(c) + 127397) for c in code.upper())
            return f"{flag} {response.get('country', 'Unknown')}"
    except:
        pass
    return "🌐 Unknown"

def load_data(filename):
    if not os.path.exists(filename): return set()
    with open(filename, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}

def run_process():
    white_snis = {s.lower() for s in load_data(SNI_WHITELIST_FILE)}
    raw_input = load_data(URL_LIST_FILE)

    if not raw_input: return

    unique_keys = {}
    for key in raw_input:
        try:
            parsed = urllib.parse.urlparse(key)
            if not parsed.hostname or not parsed.port: continue
            server_id = f"{parsed.hostname}:{parsed.port}"
            if server_id not in unique_keys:
                unique_keys[server_id] = key
        except: continue

    white_list, black_list = [], []

    for addr, key in unique_keys.items():
        parsed = urllib.parse.urlparse(key)
        host, port, protocol = parsed.hostname, parsed.port, parsed.scheme.upper()

        if not is_alive(host, port): continue

        geo = get_geo(host)
        params = urllib.parse.parse_qs(parsed.query)
        current_sni = params.get('sni', ['no-sni'])[0]

        # Название: [Страна] | [Протокол] | [SNI]
        new_label = f"{geo} | {protocol} | {current_sni}"
        final_key = f"{key.split('#')[0]}#{urllib.parse.quote(new_label)}"

        if current_sni.lower() in white_snis:
            white_list.append(final_key)
        else:
            black_list.append(final_key)

    with open(RESULT_WHITE, 'w', encoding='utf-8') as f: f.write('\n'.join(white_list))
    with open(RESULT_BLACK, 'w', encoding='utf-8') as f: f.write('\n'.join(black_list))

if __name__ == "__main__":
    run_process()
