import urllib.parse
import requests
import os
import socket

# Имена файлов
URL_FILE = 'Url.txt'
SNI_FILE = 'SNI.txt'
WHITE_OUT = 'whitelist_keys.txt'
BLACK_OUT = 'blacklist_keys.txt'

def is_alive(host, port):
    """Реальная проверка порта (TCP)."""
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            return True
    except:
        return False

def get_geo(ip):
    """Определяем страну по IP через API."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10).json()
        if response.get('status') == 'success':
            cc = response.get('countryCode', 'UN')
            # Перевод кода в эмодзи флага
            flag = "".join(chr(ord(c) + 127397) for c in cc.upper())
            return f"{flag} {response.get('country', 'Unknown')}"
    except:
        pass
    return "🌐 Unknown"

def main():
    # Проверка наличия исходных файлов
    if not os.path.exists(URL_FILE):
        print(f"[-] Ошибка: {URL_FILE} не найден.")
        return
    
    # Загрузка SNI из файла
    white_snis = set()
    if os.path.exists(SNI_FILE):
        with open(SNI_FILE, 'r', encoding='utf-8') as f:
            white_snis = {line.strip().lower() for line in f if line.strip()}

    # Очистка дубликатов по серверу (host:port)
    unique_keys = {}
    with open(URL_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            key = line.strip()
            if not key: continue
            try:
                parsed = urllib.parse.urlparse(key)
                if not parsed.hostname or not parsed.port: continue
                sid = f"{parsed.hostname}:{parsed.port}"
                if sid not in unique_servers:
                    unique_keys[sid] = key
            except: continue

    white_res, black_res = [], []

    # Обработка ключей
    for sid, key in unique_keys.items():
        try:
            p = urllib.parse.urlparse(key)
            host, port, proto = p.hostname, p.port, p.scheme.upper()
            
            # Проверяем, живой ли ключ
            if not is_alive(host, port):
                continue

            geo = get_geo(host)
            params = urllib.parse.parse_qs(p.query)
            sni = params.get('sni', ['no-sni'])[0]

            # Формат: [Флаг Страна] | [VLESS] | [ads.x5.ru]
            new_name = f"{geo} | {proto} | {sni}"
            final_key = f"{key.split('#')[0]}#{urllib.parse.quote(new_name)}"

            if sni.lower() in white_snis:
                white_res.append(final_key)
            else:
                black_res.append(final_key)
        except:
            continue

    # Сохраняем результаты
    with open(WHITE_OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(white_res))
    with open(BLACK_OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(black_res))
    
    print(f"[+] Процесс завершен. White: {len(white_res)}, Black: {len(black_res)}")

if __name__ == "__main__":
    main()
