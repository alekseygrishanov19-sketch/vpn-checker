import urllib.parse
import requests
import os
import socket
import re

# Файлы
URL_FILE = 'Url.txt'
SNI_FILE = 'SNI.txt'
WHITE_OUT = 'whitelist_keys.txt'
BLACK_OUT = 'blacklist_keys.txt'

def is_alive(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            return True
    except:
        return False

def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if r.get('status') == 'success':
            cc = r.get('countryCode', 'UN')
            flag = "".join(chr(ord(c) + 127397) for c in cc.upper())
            return f"{flag} {r.get('country', 'Unknown')}"
    except: pass
    return "🌐 Unknown"

def main():
    if not os.path.exists(URL_FILE): return
    
    # 1. Загружаем SNI
    white_snis = {line.strip().lower() for line in open(SNI_FILE, 'r') if line.strip()} if os.path.exists(SNI_FILE) else set()
    
    # 2. Собираем ключи (из файла и по внешним ссылкам)
    all_raw_keys = []
    with open(URL_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            # Если это ссылка на другой список (GitHub Raw и т.д.)
            if line.startswith('http'):
                try:
                    print(f"[*] Скачиваю ключи из: {line}")
                    resp = requests.get(line, timeout=15)
                    if resp.status_code == 200:
                        # Разделяем полученный текст на строки
                        downloaded_keys = resp.text.splitlines()
                        all_raw_keys.extend(downloaded_keys)
                except Exception as e:
                    print(f"[!] Ошибка загрузки {line}: {e}")
            else:
                # Если это сразу ключ vless/vmess
                all_raw_keys.append(line)

    # 3. Дедупликация по серверу
    unique_keys = {}
    for key in all_raw_keys:
        key = key.strip()
        if not key or not ('://' in key): continue
        try:
            p = urllib.parse.urlparse(key)
            if not p.hostname or not p.port: continue
            sid = f"{p.hostname}:{p.port}"
            if sid not in unique_keys:
                unique_keys[sid] = key
        except: continue

    print(f"[*] Всего уникальных серверов на проверку: {len(unique_keys)}")

    white_res, black_res = [], []

    # 4. Проверка и сортировка
    for sid, key in unique_keys.items():
        try:
            p = urllib.parse.urlparse(key)
            host, port, proto = p.hostname, p.port, p.scheme.upper()
            
            if not is_alive(host, port): continue

            geo = get_geo(host)
            params = urllib.parse.parse_qs(p.query)
            sni = params.get('sni', ['no-sni'])[0]

            new_name = f"{geo} | {proto} | {sni}"
            final_key = f"{key.split('#')[0]}#{urllib.parse.quote(new_name)}"

            if sni.lower() in white_snis:
                white_res.append(final_key)
            else:
                black_res.append(final_key)
        except: continue

    # 5. Сохранение
    with open(WHITE_OUT, 'w', encoding='utf-8') as f: f.write('\n'.join(white_res))
    with open(BLACK_OUT, 'w', encoding='utf-8') as f: f.write('\n'.join(black_res))
    print(f"[+] Готово! White: {len(white_res)}, Black: {len(black_res)}")

if __name__ == "__main__":
    main()
