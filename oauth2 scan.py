import requests
import urllib.parse
import sys
import os

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

if os.name == 'nt':
    os.system('color')

def check1(u):
    print(f"\n{BLUE}Проверка state...{RESET}")
    
    p = urllib.parse.urlparse(u)
    b = f"{p.scheme}://{p.netloc}{p.path}"
    q = urllib.parse.parse_qs(p.query)
    
    if not q or 'state' not in q:
        print(f"{YELLOW}Нет state в url{RESET}")
        return "да"
    
    print(f"{GREEN}Найден state: {q['state'][0]}{RESET}")
    print(f"{BLUE}Проверяю без state...{RESET}")
    
    t = q.copy()
    del t['state']
    new = b + "?" + urllib.parse.urlencode(t, doseq=True)
    
    try:
        r = requests.get(new, allow_redirects=True, timeout=3)
        final_url = r.url
        if ('code=' in final_url or 'token=' in final_url) and r.status_code < 400:
            print(f"{RED}УЯЗВИМОСТЬ! Работает без state{RESET}")
            return "да"
        else:
            print(f"{GREEN}Ок, state нужен{RESET}")
            return "нет"
    except requests.exceptions.Timeout:
        print(f"{YELLOW}Таймаут{RESET}")
        return "ошибка"
    except requests.exceptions.ConnectionError:
        print(f"{YELLOW}Не подключился{RESET}")
        return "ошибка"
    except Exception as e:
        print(f"{YELLOW}Ошибка: {e}{RESET}")
        return "ошибка"


def check2(u):
    print(f"\n{BLUE}Проверка redirect_uri...{RESET}")
    
    p = urllib.parse.urlparse(u)
    b = f"{p.scheme}://{p.netloc}{p.path}"
    q = urllib.parse.parse_qs(p.query)
    
    if 'redirect_uri' not in q:
        print(f"{YELLOW}Нет redirect_uri{RESET}")
        return "нет"
    
    orig = q['redirect_uri'][0]
    print(f"{GREEN}Оригинал: {orig}{RESET}")
    print(f"{BLUE}Пробую подменить на http://prohacker/callback{RESET}")
    
    t = q.copy()
    t['redirect_uri'] = ['http://prohacker/callback']
    new = b + "?" + urllib.parse.urlencode(t, doseq=True)
    
    try:
        r = requests.get(new, allow_redirects=False, timeout=3)

        if r.status_code == 400:
            print(f"{GREEN}Ок, отклонил подмену{RESET}")
            return "нет"

        if 'Location' in r.headers and 'prohacker' in r.headers['Location']:
            print(f"{RED}УЯЗВИМОСТЬ! Принял подмену{RESET}")
            print(f"{RED}Location: {r.headers['Location']}{RESET}")
            return "да"
        
        print(f"{GREEN}Ок, валидирует нормально{RESET}")
        return "нет"
    except requests.exceptions.Timeout:
        print(f"{YELLOW}Таймаут{RESET}")
        return "ошибка"
    except requests.exceptions.ConnectionError:
        print(f"{YELLOW}Не подключился{RESET}")
        return "ошибка"
    except Exception as e:
        print(f"{YELLOW}Ошибка: {e}{RESET}")
        return "ошибка"


if len(sys.argv) > 1:
    u = sys.argv[1]
else:
    u = input("Введи OAuth2 URL: ")

print(f"\n{BLUE}=== OAuth2 Security Scan ==={RESET}")
print(f"{BLUE}URL: {u}{RESET}")

s = check1(u)
r = check2(u)

print(f"\n{BLUE}--- Итог ---{RESET}")

if s == "да":
    print(f"{RED}STATE: УЯЗВИМОСТЬ ОБНАРУЖЕНА{RESET}")
    print(f"{RED}Параметр state не используется или не проверяется{RESET}")
    print(f"\n{YELLOW}Ссылки:{RESET}")
    print(f"{YELLOW}  https://owasp.org/www-community/vulnerabilities/Insufficient_CSRF_Protection{RESET}")
    print(f"{YELLOW}  https://cwe.mitre.org/data/definitions/352.html{RESET}")
    print(f"{YELLOW}  https://portswigger.net/web-security/oauth/openid-connect{RESET}")
elif s == "нет":
    print(f"{GREEN}STATE: Безопасно{RESET}")
else:
    print(f"{YELLOW}STATE: не проверил ({s}){RESET}")

if r == "да":
    print(f"{RED}REDIRECT_URI: УЯЗВИМОСТЬ ОБНАРУЖЕНА{RESET}")
    print(f"{RED}Сервер принимает подменённый redirect_uri{RESET}")
    print(f"\n{YELLOW}Ссылки:{RESET}")
    print(f"{YELLOW}  https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards{RESET}")
    print(f"{YELLOW}  https://cwe.mitre.org/data/definitions/601.html{RESET}")
    print(f"{YELLOW}  https://portswigger.net/web-security/oauth/openid-connect{RESET}")
elif r == "нет":
    print(f"{GREEN}REDIRECT_URI: Безопасно{RESET}")
else:
    print(f"{YELLOW}REDIRECT_URI: не проверил ({r}){RESET}")

