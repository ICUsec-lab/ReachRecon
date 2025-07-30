#!/usr/bin/env python3
import requests
import socket
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

def dns_resolve(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def parse_status_codes(sc_arg):
    if not sc_arg:
        return None
    return [int(code.strip()) for code in sc_arg.split(",") if code.strip().isdigit()]

def check_dns(sub, domain, status_filters=None, debug=False):
    host = f"{sub}.{domain}"
    urls = [f"http://{host}", f"https://{host}"]

    if not dns_resolve(host):
        if debug:
            print(f"[DNS FAIL] {host} could not be resolved")
        return None

    for url in urls:
        try:
            if debug:
                print(f"[DEBUG] Trying: {url}")
            r = requests.get(url, timeout=3, verify=False)
            if not status_filters or r.status_code in status_filters:
                return url
        except Exception as e:
            if debug:
                print(f"[FAIL] {url} -> {e}")
    return None

def check_vhost(sub, base_url, domain, status_filters=None, debug=False):
    full_host = f"{sub}.{domain}"
    try:
        if debug:
            print(f"[DEBUG] Sending Host header: {full_host}")
        r = requests.get(base_url, headers={"Host": full_host}, timeout=3, verify=False)
        if not status_filters or r.status_code in status_filters:
            scheme = base_url.split("://")[0]
            return f"{scheme}://{full_host}"
    except Exception as e:
        if debug:
            print(f"[VHOST FAIL] {full_host} -> {e}")
    return None

def check_single_url(url, status_filters=None, debug=False):
    # Resolve hostname in URL before checking
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    hostname = parsed.hostname
    if not hostname:
        if debug:
            print(f"[ERROR] Could not parse hostname from URL: {url}")
        return None

    if not dns_resolve(hostname):
        if debug:
            print(f"[DNS FAIL] {hostname} could not be resolved")
        return None

    urls_to_try = [url]
    # Add https/http fallback if not already in URL
    if not url.startswith("https://"):
        https_url = url.replace("http://", "https://") if url.startswith("http://") else "https://" + hostname
        urls_to_try.insert(0, https_url)

    for try_url in urls_to_try:
        try:
            if debug:
                print(f"[DEBUG] Trying: {try_url}")
            r = requests.get(try_url, timeout=3, verify=False)
            if not status_filters or r.status_code in status_filters:
                return try_url
        except Exception as e:
            if debug:
                print(f"[FAIL] {try_url} -> {e}")
    return None

def process_file(file_path, domain=None, status_filters=None, debug=False, threads=20, output_file=None, vhost=False, base_url=None):
    try:
        with open(file_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        if vhost and base_url and domain:
            # File contains subdomains for vhost mode
            for sub in lines:
                futures.append(executor.submit(check_vhost, sub, base_url, domain, status_filters, debug))
        elif domain:
            # File contains subdomains for DNS fuzzing
            for sub in lines:
                futures.append(executor.submit(check_dns, sub, domain, status_filters, debug))
        else:
            # File contains full URLs
            for url in lines:
                futures.append(executor.submit(check_single_url, url, status_filters, debug))
        for future in as_completed(futures):
            res = future.result()
            if res:
                print(res)
                results.append(res)

    if output_file:
        try:
            with open(output_file, "w") as f:
                for line in sorted(set(results)):
                    f.write(line + "\n")
            if debug:
                print(f"[INFO] Saved results to {output_file}")
        except Exception as e:
            print(f"[ERROR] Could not write output: {e}")

def fuzz(domain, wordlist_path, status_filters=None, debug=False, threads=20, output_file=None, vhost=False, base_url=None):
    try:
        with open(wordlist_path, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file not found: {wordlist_path}")
        return

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for sub in subdomains:
            if vhost:
                futures.append(executor.submit(check_vhost, sub, base_url, domain, status_filters, debug))
            else:
                futures.append(executor.submit(check_dns, sub, domain, status_filters, debug))
        for future in as_completed(futures):
            res = future.result()
            if res:
                print(res)
                results.append(res)

    if output_file:
        try:
            with open(output_file, "w") as f:
                for line in sorted(set(results)):
                    f.write(line + "\n")
            if debug:
                print(f"[INFO] Saved results to {output_file}")
        except Exception as e:
            print(f"[ERROR] Could not write output: {e}")

def main():
    parser = argparse.ArgumentParser(description="Subdomain Fuzzer with DNS & VHost modes plus single URL and file processing")
    parser.add_argument("-u", help="Base domain (e.g. thetoppers.htb). For --vhost mode, include http(s)://")
    parser.add_argument("-wf", help="Subdomain wordlist path")
    parser.add_argument("-sc", help="Comma-separated status codes to match (e.g. 200,403)")
    parser.add_argument("-o", help="Output file for valid results")
    parser.add_argument("--vhost", action="store_true", help="Enable VHost fuzzing (Host header spoofing)")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default 20)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    # New flags for single url/subdomain and file input
    parser.add_argument("-s", help="Process a single subdomain (without protocol)")
    parser.add_argument("-w", help="Process a single URL (http/https optional)")
    parser.add_argument("-f", help="Process URLs or subdomains from file")

    args = parser.parse_args()

    status_codes = parse_status_codes(args.sc)

    # Determine mode of operation:

    if args.s:
        # Single subdomain fuzzing (like fuzz but just one subdomain)
        domain = args.u.strip().replace("http://", "").replace("https://", "") if args.u else None
        if not domain:
            print("[ERROR] -u is required when using -s")
            return
        result = None
        if args.vhost:
            if not args.u.startswith("http://") and not args.u.startswith("https://"):
                print("[ERROR] In --vhost mode, -u must start with http:// or https://")
                return
            parsed = urlparse(args.u)
            domain = parsed.netloc
            base_url = args.u.rstrip("/")
            result = check_vhost(args.s, base_url, domain, status_codes, args.debug)
        else:
            result = check_dns(args.s, domain, status_codes, args.debug)
        if result:
            print(result)
        else:
            print("[INFO] No matching result found for single subdomain.")
        return

    if args.w:
        # Single URL check
        result = check_single_url(args.w, status_codes, args.debug)
        if result:
            print(result)
        else:
            print("[INFO] No matching result found for single URL.")
        return

    if args.f:
        # File processing: determine whether domain and vhost are specified
        domain = None
        base_url = None
        if args.vhost:
            if not args.u:
                print("[ERROR] -u is required with --vhost when processing a file")
                return
            if not args.u.startswith("http://") and not args.u.startswith("https://"):
                print("[ERROR] In --vhost mode, -u must start with http:// or https://")
                return
            parsed = urlparse(args.u)
            domain = parsed.netloc
            base_url = args.u.rstrip("/")
        else:
            domain = args.u.strip().replace("http://", "").replace("https://", "") if args.u else None
        process_file(args.f, domain, status_codes, args.debug, args.threads, args.o, args.vhost, base_url)
        return

    if args.u and args.wf:
        # Wordlist fuzzing mode
        if args.vhost:
            if not args.u.startswith("http://") and not args.u.startswith("https://"):
                print("[ERROR] In --vhost mode, -u must start with http:// or https://")
                return
            parsed = urlparse(args.u)
            domain = parsed.netloc
            base_url = args.u.rstrip("/")
        else:
            domain = args.u.strip().replace("http://", "").replace("https://", "")
            base_url = None
        fuzz(domain, args.wf, status_codes, args.debug, args.threads, args.o, args.vhost, base_url)
        return

    print("No valid options provided. Use -h for help.")

if __name__ == "__main__":
    main()
