import base64
import importlib.util
import json
from pathlib import Path
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

spec = importlib.util.spec_from_file_location("vt", Path(__file__).resolve().parents[2] / "scripts/virustotal-subdomains.py")
vt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vt)

# The script ships with no baked-in proxy; the operator supplies one via ASTRANULL_SUBDOMAIN_PROXY_URL.
# Tests inject a dummy default so the transport cases exercise a configured proxy.
vt.DEFAULT_PROXY = "http://proxy.test:10000"


def response(status, payload, kwargs):
    kwargs["content_callback"](json.dumps(payload).encode())
    return type("Response", (), {"status_code": status})()


def offset_of(url):
    query = parse_qs(urlsplit(url).query)
    return json.loads(base64.b64decode(query["cursor"][0]))["offset"]


class EnumerationTests(unittest.TestCase):
    def test_parallel_offsets_proxy_and_browser_transport(self):
        calls, active, peak = [], 0, 0
        lock = threading.Lock()

        def get(url, **kwargs):
            nonlocal active, peak
            offset = offset_of(url)
            with lock:
                calls.append((url, kwargs))
                active += 1
                peak = max(peak, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            return response(200, {"data": [{"id": f"h{i}.example.com."} for i in range(offset, min(offset + 40, 165))],
                                  "meta": {"count": 165}}, kwargs)

        result = vt.enumerate_subdomains({"domain": "example.com", "maxResults": 200, "workers": 2}, get)
        self.assertEqual(len(result["hostnames"]), 165)
        self.assertEqual(result["pages"], 5)
        self.assertFalse(result["truncated"])
        self.assertEqual(sorted(offset_of(url) for url, _ in calls), [0, 40, 80, 120, 160])
        self.assertEqual(peak, 2)
        for url, kwargs in calls:
            self.assertEqual(urlsplit(url).netloc, "www.virustotal.com")
            self.assertIn("/ui/domains/example.com/subdomains", url)
            self.assertEqual(parse_qs(urlsplit(url).query)["relationships"], ["resolutions"])
            self.assertEqual(kwargs["impersonate"], "chrome")
            self.assertEqual(kwargs["proxies"], {"http": vt.DEFAULT_PROXY, "https": vt.DEFAULT_PROXY})
            self.assertFalse(kwargs["allow_redirects"])
            self.assertIn("-ZG9udCBiZSBldmls-", base64.b64decode(kwargs["headers"]["x-vt-anti-abuse-header"]).decode())

    def test_retries_403_429_with_fresh_headers_and_backoff(self):
        calls, sleeps = [], []

        def get(url, **kwargs):
            calls.append(kwargs["headers"]["x-vt-anti-abuse-header"])
            return response([403, 429, 200][len(calls) - 1], {"data": [{"id": "a.example.com"}]}, kwargs)

        result = vt.enumerate_subdomains({"domain": "example.com", "baseDelay": 1}, get, sleep=sleeps.append)
        self.assertEqual(result["hostnames"], ["a.example.com"])
        self.assertEqual(sleeps, [1, 2])
        self.assertEqual(len(set(calls)), 3)

    def test_partial_failure_preserves_successful_pages(self):
        def get(url, **kwargs):
            if offset_of(url):
                return response(429, {}, kwargs)
            return response(200, {"data": [{"id": f"h{i}.example.com"} for i in range(40)], "meta": {"count": 80}}, kwargs)

        result = vt.enumerate_subdomains({"domain": "example.com", "retries": 1}, get)
        self.assertEqual(len(result["hostnames"]), 40)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["stop_reason"], "rate_limited")

    def test_request_cap_and_unknown_total_are_visible(self):
        for meta, reason, expected_calls in [({"count": 99999999}, "max_results", 2), ({}, "unknown_total", 1)]:
            calls = []

            def get(url, **kwargs):
                calls.append(url)
                offset = offset_of(url)
                return response(200, {"data": [{"id": f"h{i}.example.com"} for i in range(offset, offset + 40)], "meta": meta}, kwargs)

            result = vt.enumerate_subdomains({"domain": "example.com", "maxResults": 80}, get)
            self.assertEqual(len(calls), expected_calls)
            self.assertEqual(result["stop_reason"], reason)

    def test_first_page_errors_invalid_json_size_and_proxy(self):
        for status, code in [(403, "auth_failed"), (429, "rate_limited"), (302, "failed"), (500, "failed")]:
            with self.subTest(status=status), self.assertRaises(vt.SourceError) as raised:
                vt.enumerate_subdomains({"domain": "example.com", "retries": 1},
                                        lambda url, **kwargs: response(status, {}, kwargs))
            self.assertEqual(raised.exception.code, "subdomain_source_" + code)

        def oversized(url, **kwargs):
            kwargs["content_callback"](b"x" * (vt.MAX_RESPONSE_BYTES + 1))

        with self.assertRaises(vt.SourceError) as raised:
            vt.enumerate_subdomains({"domain": "example.com"}, oversized)
        self.assertEqual(raised.exception.code, "subdomain_source_response_too_large")
        with self.assertRaises(vt.SourceError):
            vt.enumerate_subdomains({"domain": "example.com"}, lambda url, **kwargs: response(200, {}, kwargs))
        with self.assertRaises(vt.SourceError):
            vt.enumerate_subdomains({"domain": "example.com", "proxyUrl": "file:///secret"}, lambda **kwargs: None)

    def test_absent_proxy_is_not_configured_rather_than_a_baked_in_credential(self):
        saved = vt.DEFAULT_PROXY
        vt.DEFAULT_PROXY = ""
        try:
            with self.assertRaises(vt.SourceError) as raised:
                vt.enumerate_subdomains({"domain": "example.com"}, lambda url, **kwargs: response(200, {}, kwargs))
            self.assertEqual(raised.exception.code, "subdomain_source_not_configured")
        finally:
            vt.DEFAULT_PROXY = saved

    def test_network_error_and_deadline_do_not_retry_without_budget(self):
        calls, sleeps = [], []

        def get(url, **kwargs):
            calls.append(kwargs)
            raise RuntimeError("transport failure containing private credentials")

        with self.assertRaises(vt.SourceError) as raised:
            vt.enumerate_subdomains({"domain": "example.com", "deadlineMs": 1000}, get, now=lambda: 0, sleep=sleeps.append)
        self.assertEqual(raised.exception.code, "subdomain_source_unreachable")
        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(calls[0]["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
