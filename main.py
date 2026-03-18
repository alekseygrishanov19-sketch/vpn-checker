import urllib.parse
import requests
import os
import socket
import time

# Файлы
URL_FILE = 'Url.txt'
SNI_FILE = 'SNI.txt'
WHITE_OUT = 'whitelist_keys.txt'
BLACK_OUT = 'blacklist_keys.txt'

def is_online(host, port):
    """Реальная проверка порта."""
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            return True
    except:
        return False

def get_geo(ip):
    """Определяем страну через IP-API."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if r.get('status') == 'success':
            cc = r.get('countryCode', 'UN')
            flag = "".join(chr(ord(c) + 127397) for c in cc.upper())
            return f"{flag} {r.get('country', 'Unknown')}"
    except:
        pass
    return "🌐 Unknown"

def main():
    if not os.path.exists(URL_FILE): return

    # Загружаем SNI для отбора
    whitelist_snis = {line.strip().lower() for line in open(SNI_FILE, 'r') if line.strip()} if os.path.exists(SNI_FILE) else set()

    # Собираем уникальные сервера
    unique_servers = {}
    with open(URL_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                p = urllib.parse.urlparse(line)
                sid = f"{p.hostname}:{p.port}"
                if sid not in unique_servers:
                    unique_servers[sid] = line
            except: continue

    white_res, black_res = [], []

    for sid, key in unique_servers.items():
        p = urllib.parse.urlparse(key)
        if not is_online(p.hostname, p.port): continue

        geo = get_geo(p.hostname)
        proto = p.scheme.upper()
        params = urllib.parse.parse_qs(p.query)
        sni = params.get('sni', ['no-sni'])[0]

        # Новое название: 🇷🇺 Russia | VLESS | ads.x5.ru
        new_name = f"{geo} | {proto} | {sni}"
        final_key = f"{key.split('#')[0]}#{urllib.parse.quote(new_name)}"

        if sni.lower() in whitelist_snis:
            white_res.append(final_key)
        else:
            black_res.append(final_key)

    with open(WHITE_OUT, 'w', encoding='utf-8') as f: f.write('\n'.join(white_res))
    with open(BLACK_OUT, 'w', encoding='utf-8') as f: f.write('\n'.join(black_res))

if __name__ == "__main__":
    main()
