#!/usr/bin/env python3
"""VirusTotal UI enumeration. Private JSON input/output for the control plane."""
import base64
import json
import os
import random
import re
import sys
import time
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import urlencode, urlsplit

# Operator-supplied default; runtime configuration can override it. Never log this value.
DEFAULT_PROXY = "http://spg2uldu0s:_vRC0ixnxOvchh4P40@dc.decodo.com:10000"
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


def fetch_page(domain, offset, proxy, deadline, get, now, sleep, retries, base_delay,
               request_timeout=60, progress=lambda event: None):
    last = "subdomain_source_unreachable"
    for attempt in range(retries):
        remaining = deadline - now() if deadline is not None else request_timeout
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
            progress({"phase": "fetching"})
            response = get(page_url(domain, offset), headers=build_headers(),
                           impersonate="chrome", timeout=min(request_timeout, remaining),
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
            if status in (403, 429):
                try:
                    error = json.loads(b"".join(chunks)).get("error", {})
                except (ValueError, AttributeError):
                    error = {}
                # A challenge needs human validation; repeating it cannot complete this lookup.
                if isinstance(error, dict) and error.get("code") == "RecaptchaRequiredError":
                    raise SourceError("subdomain_source_auth_failed")
            last = ("subdomain_source_rate_limited" if status == 429 else
                    "subdomain_source_auth_failed" if status in (401, 403) else
                    "subdomain_source_failed")
            if status not in (403, 429) and status < 500:
                raise SourceError(last)
        if attempt + 1 == retries:
            break
        delay = base_delay * (2 ** attempt)
        if deadline is not None and delay >= deadline - now():
            break
        sleep(delay)
    raise SourceError(last)


def enumerate_subdomains(config, get, now=time.monotonic, sleep=time.sleep, progress=lambda event: None):
    domain = str(config.get("domain", "")).lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", domain):
        raise SourceError("subdomain_source_failed")
    proxy = config.get("proxyUrl") or os.environ.get("ASTRANULL_SUBDOMAIN_PROXY_URL") or DEFAULT_PROXY
    try:
        parsed = urlsplit(proxy)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or not parsed.port:
            raise ValueError("invalid proxy")
    except ValueError:
        raise SourceError("subdomain_source_not_configured") from None
    # Match the supplied script's --max-pages=0: read the whole finite source by default.
    max_results = max(0, int(config.get("maxResults", 0)))
    deadline = now() + float(config["deadlineMs"]) / 1000 if config.get("deadlineMs") else None
    workers = max(1, min(8, int(config.get("workers", 8))))
    retries = max(1, min(5, int(config.get("retries", 5))))
    base_delay = max(0, float(config.get("baseDelay", 15)))
    request_timeout = max(0.001, min(60, float(config.get("requestTimeoutMs", 60000)) / 1000))

    def page(offset):
        return fetch_page(domain, offset, proxy, deadline, get, now, sleep, retries, base_delay,
                          request_timeout, progress)

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
    progress({"phase": "fetching", "pages": pages, "records": len(found), "reported_total": reported})
    offsets = range(0)
    if len(first["data"]) == PAGE_SIZE:
        if reported is None:
            stop_reason = "unknown_total"
        else:
            offsets = range(PAGE_SIZE, min(reported, max_results) if max_results else reported, PAGE_SIZE)
    elif reported is not None and reported > len(first["data"]):
        stop_reason = "incomplete_source"

    if offsets:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Keep only eight pending futures even when the source has thousands of pages.
            pending = {}
            remaining_offsets = iter(offsets)
            failed = []
            source_blocked = False

            def submit_next():
                offset = next(remaining_offsets, None)
                if offset is not None:
                    pending[pool.submit(page, offset)] = offset

            def collect(payload, offset):
                nonlocal pages, stop_reason
                found.update(ids(payload))
                pages += 1
                progress({"phase": "fetching", "pages": pages, "records": len(found), "reported_total": reported})
                if len(payload["data"]) < min(PAGE_SIZE, reported - offset):
                    stop_reason = stop_reason or "incomplete_source"

            for _ in range(workers):
                submit_next()
            while pending:
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    offset = pending.pop(future)
                    try:
                        collect(future.result(), offset)
                    except SourceError as error:
                        if error.code == "subdomain_source_auth_failed":
                            source_blocked = True
                            remaining_offsets = iter(())
                            stop_reason = "auth_failed"
                        else:
                            failed.append(offset)
                    submit_next()
            # Same final sequential recovery pass as the supplied script.
            for offset in sorted(failed):
                if source_blocked:
                    break
                if deadline is None:
                    sleep(1)
                try:
                    collect(page(offset), offset)
                except SourceError as error:
                    stop_reason = stop_reason or error.code.removeprefix("subdomain_source_")
    if stop_reason is None and max_results and reported is not None and reported > max_results:
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
        lock = threading.Lock()

        def progress(event):
            if config.get("progress"):
                with lock:
                    print(json.dumps({"type": "progress", "progress": event}), flush=True)

        result = enumerate_subdomains(config, requests.get, progress=progress)
    except SourceError as error:
        result = {"error": error.code}
    except Exception:
        # Never serialize exceptions: transport messages can contain the proxy credential.
        result = {"error": "subdomain_source_failed"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
