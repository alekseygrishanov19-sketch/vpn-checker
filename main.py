import urllib.parse
import requests
import os
import socket
import time

# --- НАСТРОЙКИ ---
URL_LIST_FILE = 'Url.txt'
SNI_WHITELIST_FILE = 'SNI.txt'
RESULT_WHITE = 'whitelist_keys.txt'
RESULT_BLACK = 'blacklist_keys.txt'
TIMEOUT = 3 # Секунды на проверку порта

def is_alive(host, port):
    """Проверяет доступность порта (TCP connect)."""
    try:
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return True
    except:
        return False

def get_geo(ip):
    """Определяет страну и флаг по IP."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
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

def main():
    # 1. Загружаем белый список SNI
    white_snis = {s.lower() for s in load_data(SNI_WHITELIST_FILE)}
    
    # 2. Собираем ключи из Url.txt
    raw_input = load_data(URL_LIST_FILE)
    if not raw_input:
        print("[-] Url.txt пуст!")
        return

    # Убираем дубликаты по серверу (IP:PORT)
    unique_keys = {}
    for key in raw_input:
        try:
            parsed = urllib.parse.urlparse(key)
            if not parsed.hostname or not parsed.port: continue
            server_id = f"{parsed.hostname}:{parsed.port}"
            if server_id not in unique_keys:
                unique_keys[server_id] = key
        except: continue

    print(f"[*] После очистки дублей: {len(unique_keys)} уникальных серверов.")

    white_list = []
    black_list = []

    # 3. Основной цикл проверки
    for addr, key in unique_keys.items():
        parsed = urllib.parse.urlparse(key)
        host = parsed.hostname
        port = parsed.port
        protocol = parsed.scheme.upper() # VLESS, VMESS, TROJAN и т.д.

        print(f"[/] Тестирую {addr} ({protocol})... ", end='', flush=True)

        # ПРОВЕРКА №1: Жив ли сервер вообще (TCP Port)
        if not is_alive(host, port):
            print("❌ МЕРТВ")
            continue

        # ПРОВЕРКА №2: Определяем ГЕО по конечному IP
        geo = get_geo(host)
        
        # Разбираем параметры SNI
        params = urllib.parse.parse_qs(parsed.query)
        current_sni = params.get('sni', ['no-sni'])[0]

        # 4. Формируем новое имя: [Страна] | Протокол | SNI
        # Формат: 🇷🇺 Russia | VLESS | ads.x5.ru
        new_label = f"{geo} | {protocol} | {current_sni}"
        
        # Пересобираем ссылку с новым именем
        clean_url = key.split('#')[0]
        final_key = f"{clean_url}#{urllib.parse.quote(new_label)}"

        # 5. Сортировка
        if current_sni.lower() in white_snis:
            white_list.append(final_key)
            print(f"✅ ЖИВ (Whitelist)")
        else:
            black_list.append(final_key)
            print(f"✅ ЖИВ (Blacklist)")

    # 6. Сохранение
    with open(RESULT_WHITE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(white_list))
    with open(RESULT_BLACK, 'w', encoding='utf-8') as f:
        f.write('\n'.join(black_list))

    print(f"\n--- ИТОГО ---")
    print(f"Живых в Whitelist (SNI): {len(white_list)}")
    print(f"Живых в Blacklist (VPN): {len(black_list)}")
    print(f"Результаты: {RESULT_WHITE} и {RESULT_BLACK}")

if __name__ == "__main__":
    main()
