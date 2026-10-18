#!/usr/bin/env python3
"""Bounded VirusTotal UI enumeration. Private JSON input/output for the control plane."""
import base64
import json
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, urlsplit

# Operator supplies the egress proxy via ASTRANULL_SUBDOMAIN_PROXY_URL (config.proxyUrl); never hardcode a credential.
DEFAULT_PROXY = os.environ.get("ASTRANULL_SUBDOMAIN_PROXY_URL", "")
PAGE_SIZE = 40
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class SourceError(Exception):
    def __init__(self, code):
        self.code = code


def build_headers():
    rid = int((1 + random.random() % 50000) * 1e10)
    raw = f"{rid}-ZG9udCBiZSBldmls-{time.time():.3f}"
    return {
        "accept": "application/json",
        "accept-ianguage": "en-US,en;q=0.9,es;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "referer": "https://www.virustotal.com/",
        "sec-ch-ua": '"Not?A_Brand";v="24", "Chromium";v="152"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"),
        "x-tool": "vt-ui-main",
        "x-app-version": "v1x659x1",
        "x-vt-anti-abuse-header": base64.b64encode(raw.encode()).decode(),
    }


def page_url(domain, offset):
    cursor = base64.b64encode(json.dumps({"limit": PAGE_SIZE, "offset": offset}).encode()).decode()
    return f"https://www.virustotal.com/ui/domains/{domain}/subdomains?" + urlencode({
        "limit": PAGE_SIZE, "relationships": "resolutions", "cursor": cursor,
    })


def fetch_page(domain, offset, proxy, deadline, get, now, sleep, retries, base_delay):
    last = "subdomain_source_unreachable"
    for attempt in range(retries):
        remaining = deadline - now()
        if remaining <= 0:
            raise SourceError(last)
        chunks, size, too_large = [], 0, False

        def receive(chunk):
            nonlocal size, too_large
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                too_large = True
                raise ValueError("response limit")
            chunks.append(chunk)
            return len(chunk)

        try:
            response = get(page_url(domain, offset), headers=build_headers(),
                           impersonate="chrome", timeout=min(15, remaining),
                           proxies={"http": proxy, "https": proxy},
                           allow_redirects=False, content_callback=receive)
        except Exception:
            if too_large:
                raise SourceError("subdomain_source_response_too_large") from None
            last = "subdomain_source_unreachable"
        else:
            status = response.status_code
            if status == 200:
                try:
                    payload = json.loads(b"".join(chunks))
                    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
                        raise ValueError("invalid data")
                    if len(payload["data"]) > PAGE_SIZE:
                        raise ValueError("invalid page size")
                    return payload
                except (ValueError, TypeError):
                    raise SourceError("subdomain_source_failed") from None
            if status == 404:
                return {"data": []}
            last = ("subdomain_source_rate_limited" if status == 429 else
                    "subdomain_source_auth_failed" if status in (401, 403) else
                    "subdomain_source_failed")
            if status not in (403, 429) and status < 500:
                raise SourceError(last)
        if attempt + 1 == retries:
            break
        delay = base_delay * (2 ** attempt)
        if delay >= deadline - now():
            break
        sleep(delay)
    raise SourceError(last)


def enumerate_subdomains(config, get, now=time.monotonic, sleep=time.sleep):
    domain = str(config.get("domain", "")).lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", domain):
        raise SourceError("subdomain_source_failed")
    proxy = config.get("proxyUrl") or DEFAULT_PROXY
    try:
        parsed = urlsplit(proxy)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or not parsed.port:
            raise ValueError("invalid proxy")
    except ValueError:
        raise SourceError("subdomain_source_not_configured") from None
    max_results = max(1, min(1000, int(config.get("maxResults", 200))))
    deadline = now() + max(0.001, min(45, float(config.get("deadlineMs", 45000)) / 1000))
    workers = max(1, min(8, int(config.get("workers", 8))))
    retries = max(1, min(5, int(config.get("retries", 5))))
    base_delay = max(0, float(config.get("baseDelay", 15)))

    def page(offset):
        return fetch_page(domain, offset, proxy, deadline, get, now, sleep, retries, base_delay)

    def ids(payload):
        return [item["id"].rstrip(".") for item in payload["data"]
                if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]]

    first = page(0)
    found = set(ids(first))
    meta = first.get("meta")
    reported = meta.get("count") if isinstance(meta, dict) else None
    if type(reported) is not int or reported < 0:
        reported = None
    pages, stop_reason = 1, None
    offsets = []
    if len(first["data"]) == PAGE_SIZE:
        if reported is None:
            stop_reason = "unknown_total"
        else:
            offsets = list(range(PAGE_SIZE, min(reported, max_results), PAGE_SIZE))
    elif reported is not None and reported > len(first["data"]):
        stop_reason = "incomplete_source"

    if offsets:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # The queue contains at most 24 pages; no unbounded future or traffic generation.
            futures = {pool.submit(page, offset): offset for offset in offsets}
            for future in as_completed(futures):
                try:
                    payload = future.result()
                    found.update(ids(payload))
                    pages += 1
                    if len(payload["data"]) < min(PAGE_SIZE, reported - futures[future]):
                        stop_reason = stop_reason or "incomplete_source"
                except SourceError as error:
                    stop_reason = stop_reason or error.code.removeprefix("subdomain_source_")
    if stop_reason is None and reported is not None and reported > max_results:
        stop_reason = "max_results"
    return {"hostnames": sorted(found), "pages": pages, "reported_total": reported,
            "truncated": stop_reason is not None, "stop_reason": stop_reason}


def main():
    try:
        config = json.loads(sys.stdin.buffer.read(65536))
        try:
            from curl_cffi import requests
        except ImportError:
            raise SourceError("subdomain_source_not_configured") from None
        result = enumerate_subdomains(config, requests.get)
    except SourceError as error:
        result = {"error": error.code}
    except Exception:
        # Never serialize exceptions: transport messages can contain the proxy credential.
        result = {"error": "subdomain_source_failed"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
