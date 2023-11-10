import requests
import re
import ssl
import socket
import random
import threading
from queue import Queue

# User agent'ları okuyan fonksiyon
def read_user_agents(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

# WAF tespiti yapan fonksiyon
def detect_waf(url, user_agents):
    user_agent = random.choice(user_agents)
    headers = {
        'User-Agent': user_agent
    }

    waf_patterns = {
        'Cloudflare': r'__cfduid|cloudflare-nginx',
        'Incapsula': r'incap_ses|visid_incap|Incapsula',
        'Akamai': r'akamai|akamaighost',
        'AWS WAF': r'awselb|awselb',
        'ModSecurity': r'ModSecurity|OWASP CRS',
        'Palo Alto Next Gen Firewall': r'Palo Alto Next Gen Firewall'
    }

    try:
        response = requests.get(url, headers=headers)
        response_headers = str(response.headers)

        for waf_name, pattern in waf_patterns.items():
            if re.search(pattern, response_headers, re.IGNORECASE):
                return f"WAF Detected: {waf_name}"

        return "No WAF Detected or WAF not in database"
    except Exception as e:
        return f"Error occurred: {e}"

# Davranışsal analiz yapan fonksiyon
def behavioral_analysis(url, user_agents):
    headers = {
        'User-Agent': random.choice(user_agents)
    }

    test_requests = [
        {'method': 'GET', 'path': '/'},
        {'method': 'GET', 'path': '<script\x0Atype="text/javascript">javascript:alert(1);</script>'},
        {'method': 'POST', 'path': '/', 'data': 'a=' * 3000},
        {'method': 'HEAD', 'path': '/'}
    ]

    responses = {}
    for req in test_requests:
        try:
            if req['method'] == 'GET':
                response = requests.get(url + req['path'], headers=headers)
            elif req['method'] == 'POST':
                response = requests.post(url + req['path'], data=req.get('data', ''), headers=headers)
            elif req['method'] == 'HEAD':
                response = requests.head(url + req['path'], headers=headers)

            responses[req['method'] + ' ' + req['path']] = response.status_code
        except Exception as e:
            responses[req['method'] + ' ' + req['path']] = str(e)

    return responses

# Kuyruktaki URL'ler için işlem yapan işçi fonksiyonu
def worker(queue, user_agents):
    while not queue.empty():
        url = queue.get()
        waf_result = detect_waf(url, user_agents)
        behavior_result = behavioral_analysis(url, user_agents)
        print(f"URL: {url}, WAF Result: {waf_result}, Behavioral Analysis: {behavior_result}")
        queue.task_done()

# Ana fonksiyon, iş parçacıklarını başlatır ve yönetir
def main(urls, user_agents_file, thread_count=5):
    user_agents = read_user_agents(user_agents_file)
    queue = Queue()

    for url in urls:
        queue.put(url)

    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(queue, user_agents))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

# Örnek Kullanım
urls = ["http://example.com", "http://testsite.com"]
user_agents_file = "user_agent.txt"
main(urls, user_agents_file)