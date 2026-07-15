#!/usr/bin/env python3
"""
Advanced Subdomain Enumerator
Usage: python3 subdomain_scanner.py -d example.com -w wordlist.txt
"""

import dns.resolver
import dns.exception
import threading
import queue
import random
import string
import subprocess
import time
import httpx
import os
import json
import csv
import logging
import argparse
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import Counter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- LOGGING SETUP ----------------
def setup_logging(verbose: bool, log_file: Optional[str] = None):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers
    )

logger = logging.getLogger(__name__)

# ---------------- DATA CLASSES ----------------
@dataclass
class SubdomainResult:
    subdomain: str
    ips: list = field(default_factory=list)
    cnames: list = field(default_factory=list)
    http_url: Optional[str] = None
    http_status: Optional[int] = None
    https_url: Optional[str] = None
    https_status: Optional[int] = None
    is_live: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ---------------- ARGUMENT PARSER ----------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Enumerator — DNS + HTTP/HTTPS + Screenshots",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS/HTTP timeout in seconds (default: 3)")
    parser.add_argument("-o", "--output", default="results", help="Output folder (default: results/)")
    parser.add_argument("--no-subfinder", action="store_true", help="Skip Subfinder OSINT discovery")
    parser.add_argument("--no-screenshots", action="store_true", help="Skip Gowitness screenshots")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Seconds to sleep between requests per thread")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("--log-file", help="Save logs to a file")
    parser.add_argument("--retries", type=int, default=2, help="DNS retry attempts (default: 2)")
    return parser.parse_args()

# ---------------- HELPERS ----------------
def random_string(length=12) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def check_wildcard(domain: str, timeout: float) -> Optional[list]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    fake_sub = f"{random_string()}.{domain}"
    try:
        answers = resolver.resolve(fake_sub, "A")
        return [str(ip) for ip in answers]
    except Exception:
        return None

# ---------------- SUBFINDER ----------------
def run_subfinder(domain: str) -> list:
    logger.info("Running Subfinder...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            logger.warning("Subfinder exited with errors.")
            return []
        subs = list(set(result.stdout.splitlines()))
        logger.info(f"Subfinder found {len(subs)} subdomains.")
        return subs
    except FileNotFoundError:
        logger.warning("Subfinder not found — skipping OSINT discovery.")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Subfinder timed out.")
        return []

# ---------------- DNS RESOLUTION ----------------
def resolve_subdomain(target: str, resolver: dns.resolver.Resolver, retries: int):
    ips, cnames = [], []

    for attempt in range(retries + 1):
        try:
            answers = resolver.resolve(target, "A")
            ips = [str(ip) for ip in answers]
            break
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            break
        except Exception:
            if attempt == retries:
                logger.debug(f"DNS A failed for {target} after {retries+1} attempts")

    if not ips:
        for attempt in range(retries + 1):
            try:
                answers = resolver.resolve(target, "CNAME")
                cnames = [str(r) for r in answers]
                break
            except Exception:
                pass

    return ips, cnames

# ---------------- HTTP + HTTPS CHECK ----------------
def check_http_https(subdomain: str, timeout: float):
    http_url, http_status = None, None
    https_url, https_status = None, None

    try:
        url = f"https://{subdomain}"
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            r = client.get(url)
            https_url = url
            https_status = r.status_code
    except Exception:
        pass

    try:
        url = f"http://{subdomain}"
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            r = client.get(url)
            http_url = url
            http_status = r.status_code
    except Exception:
        pass

    return http_url, http_status, https_url, https_status

# ---------------- OUTPUT HELPERS ----------------
def save_results(results: list, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    live_file = os.path.join(output_dir, "live_subdomains.txt")
    with open(live_file, "w") as f:
        for r in results:
            if r.is_live:
                if r.https_url:
                    f.write(r.https_url + "\n")
                if r.http_url:
                    f.write(r.http_url + "\n")

    with open(os.path.join(output_dir, "live_https.txt"), "w") as f:
        for r in results:
            if r.https_url:
                f.write(r.https_url + "\n")

    with open(os.path.join(output_dir, "live_http.txt"), "w") as f:
        for r in results:
            if r.http_url:
                f.write(r.http_url + "\n")

    json_file = os.path.join(output_dir, f"results_{timestamp}.json")
    with open(json_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    csv_file = os.path.join(output_dir, f"results_{timestamp}.csv")
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "subdomain", "ips", "cnames",
            "http_url", "http_status",
            "https_url", "https_status",
            "is_live", "timestamp"
        ])
        writer.writeheader()
        for r in results:
            row = asdict(r)
            row["ips"] = ", ".join(r.ips)
            row["cnames"] = ", ".join(r.cnames)
            writer.writerow(row)

    logger.info(f"Results saved → {output_dir}/")
    logger.info(f"  live_subdomains.txt — all live URLs")
    logger.info(f"  live_https.txt      — HTTPS only")
    logger.info(f"  live_http.txt       — HTTP only")
    return live_file

# ---------------- WORKER ----------------
def worker(
    q: queue.Queue,
    wildcard_ips,
    results: list,
    results_lock: threading.Lock,
    counter: Counter,
    counter_lock: threading.Lock,
    total: int,
    args,
    output_dir: str,
):
    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    while True:
        try:
            target = q.get_nowait()
        except queue.Empty:
            break

        try:
            ips, cnames = resolve_subdomain(target, resolver, args.retries)

            if not ips and not cnames:
                with counter_lock:
                    counter["tested"] += 1
                    if not args.verbose:
                        print(f"\r  Tested: {counter['tested']}/{total}", end="", flush=True)
                q.task_done()
                continue

            if wildcard_ips and ips and all(ip in wildcard_ips for ip in ips):
                logger.debug(f"Wildcard match, skipping: {target}")
                with counter_lock:
                    counter["tested"] += 1
                q.task_done()
                continue

            result = SubdomainResult(subdomain=target, ips=ips, cnames=cnames)

            http_url, http_status, https_url, https_status = check_http_https(target, args.timeout)

            if http_url:
                result.http_url = http_url
                result.http_status = http_status
                result.is_live = True

            if https_url:
                result.https_url = https_url
                result.https_status = https_status
                result.is_live = True

            if result.is_live:
                parts = []
                if https_url:
                    parts.append(f"HTTPS {https_status}")
                if http_url:
                    parts.append(f"HTTP {http_status}")
                logger.info(f"[LIVE] {target}  →  {' | '.join(parts)}  |  IPs: {', '.join(ips)}")
            else:
                logger.debug(f"[DNS-ONLY] {target}  →  IPs: {', '.join(ips)}")

            with results_lock:
                results.append(result)
                if result.is_live:
                    with open(os.path.join(output_dir, "live_subdomains.txt"), "a") as f:
                        if result.https_url:
                            f.write(result.https_url + "\n")
                        if result.http_url:
                            f.write(result.http_url + "\n")

        except Exception as e:
            logger.debug(f"Worker error for {target}: {e}")

        finally:
            if args.rate_limit > 0:
                time.sleep(args.rate_limit)

        q.task_done()
        with counter_lock:
            counter["tested"] += 1
            if not args.verbose:
                print(f"\r  Tested: {counter['tested']}/{total}", end="", flush=True)

# ---------------- SCREENSHOTS (Gowitness v3) ----------------
def take_screenshots(live_file: str, output_dir: str):
    screenshot_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    logger.info("Taking screenshots with Gowitness v3...")
    try:
        subprocess.run([
            "gowitness", "scan", "file",
            "-f", live_file,
            "--screenshot-path", screenshot_dir,
            "--timeout", "10",
            "--threads", "10",
        ], check=True)
        logger.info(f"Screenshots saved → {screenshot_dir}/")
        logger.info("View report: gowitness report serve")
    except FileNotFoundError:
        logger.warning("Gowitness not found — skipping screenshots.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Gowitness error: {e}")

# ---------------- MAIN ----------------
def main():
    args = parse_args()
    setup_logging(args.verbose, args.log_file)
    os.makedirs(args.output, exist_ok=True)

    open(os.path.join(args.output, "live_subdomains.txt"), "w").close()

    logger.info("=" * 50)
    logger.info("  Advanced Subdomain Enumerator")
    logger.info("=" * 50)
    logger.info(f"Target domain : {args.domain}")
    logger.info(f"Threads       : {args.threads}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Retries       : {args.retries}")
    logger.info(f"Output folder : {args.output}/")
    logger.info("=" * 50)

    try:
        with open(args.wordlist, "r") as f:
            brute_subs = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(brute_subs)} words from wordlist.")
    except FileNotFoundError:
        logger.error(f"Wordlist not found: {args.wordlist}")
        sys.exit(1)

    subfinder_subs = [] if args.no_subfinder else run_subfinder(args.domain)

    all_targets = set()
    for sub in brute_subs:
        all_targets.add(f"{sub}.{args.domain}")
    for sub in subfinder_subs:
        all_targets.add(sub)

    total = len(all_targets)
    logger.info(f"Total unique targets: {total}")

    wildcard_ips = check_wildcard(args.domain, args.timeout)
    if wildcard_ips:
        logger.warning(f"Wildcard DNS detected → {wildcard_ips}. Results will be filtered.")
    else:
        logger.info("No wildcard DNS detected.")

    q = queue.Queue()
    for target in all_targets:
        q.put(target)

    results = []
    results_lock = threading.Lock()
    counter = Counter()
    counter_lock = threading.Lock()

    logger.info("Starting scan...\n")
    start_time = time.time()

    threads = []
    for _ in range(min(args.threads, total)):
        t = threading.Thread(
            target=worker,
            args=(q, wildcard_ips, results, results_lock, counter, counter_lock, total, args, args.output),
            daemon=True
        )
        t.start()
        threads.append(t)

    q.join()
    elapsed = round(time.time() - start_time, 2)

    print()
    logger.info("=" * 50)
    logger.info("Scan complete!")
    logger.info(f"Total tested  : {counter['tested']}")
    logger.info(f"Live found    : {sum(1 for r in results if r.is_live)}")
    logger.info(f"HTTPS live    : {sum(1 for r in results if r.https_url)}")
    logger.info(f"HTTP live     : {sum(1 for r in results if r.http_url)}")
    logger.info(f"DNS-only      : {sum(1 for r in results if not r.is_live and (r.ips or r.cnames))}")
    logger.info(f"Time taken    : {elapsed}s")
    logger.info("=" * 50)

    live_file = save_results(results, args.output)

    live_count = sum(1 for r in results if r.is_live)
    if live_count > 0 and not args.no_screenshots:
        take_screenshots(live_file, args.output)
    else:
        logger.info("No live subdomains found or screenshots disabled.")

if __name__ == "__main__":
    main()
