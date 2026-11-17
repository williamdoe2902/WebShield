from __future__ import annotations

import ipaddress
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser
from typing import Any, Callable


MAX_PAGES = 30
MAX_RESPONSE_BYTES = 1_000_000
REQUEST_TIMEOUT = 5
REQUEST_INTERVAL = 0.25
_request_lock = threading.Lock()
_next_request_at = 0.0
SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "sqlite error",
    "sqlstate[",
    "ora-01756",
    "unclosed quotation mark after the character string",
    "postgresql error",
)
SECURITY_HEADERS = {
    "content-security-policy": ("Medium", "Add a Content-Security-Policy suited to the application's resources."),
    "strict-transport-security": ("Low", "Enable HSTS when the application is served over HTTPS."),
    "x-content-type-options": ("Low", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("Low", "Set X-Frame-Options or use frame-ancestors in Content-Security-Policy."),
    "referrer-policy": ("Low", "Set a restrictive Referrer-Policy, such as strict-origin-when-cross-origin."),
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"] or "")
        if tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "get").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        if tag in {"input", "textarea", "select"} and self._form is not None:
            self._form["inputs"].append({
                "name": attributes.get("name", ""),
                "type": attributes.get("type", tag),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _resolve_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_target(target: str, authorized: bool) -> str:
    if not authorized:
        raise ValueError("Confirm that you are authorized to scan this local lab target.")
    parsed = urllib.parse.urlsplit(target.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed.")
    if not _resolve_loopback(parsed.hostname):
        raise ValueError("Only localhost or a literal loopback IP address is allowed.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _request(url: str) -> tuple[str, dict[str, str], bytes] | None:
    global _next_request_at
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname or not _resolve_loopback(parsed.hostname):
        return None
    request = urllib.request.Request(url, headers={"User-Agent": "WebShield-Lab-Scanner/1.0"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    try:
        with _request_lock:
            delay = _next_request_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            try:
                try:
                    response = opener.open(request, timeout=REQUEST_TIMEOUT)
                except urllib.error.HTTPError as error:
                    if 300 <= error.code < 400:
                        return None
                    response = error
                with response:
                    body = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(body) > MAX_RESPONSE_BYTES:
                        body = body[:MAX_RESPONSE_BYTES]
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    final_url = response.geturl()
                    if not _resolve_loopback(urllib.parse.urlsplit(final_url).hostname or ""):
                        return None
                    return final_url, headers, body
            finally:
                _next_request_at = time.monotonic() + REQUEST_INTERVAL
    except (OSError, urllib.error.URLError, ValueError):
        return None


def _finding(title: str, severity: str, url: str, evidence: str, remediation: str) -> dict[str, str]:
    return {"title": title, "severity": severity, "url": url, "evidence": evidence, "remediation": remediation}


def scan_target(
    target: str,
    authorized: bool = False,
    max_pages: int = MAX_PAGES,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    start_url = validate_target(target, authorized)
    origin = urllib.parse.urlsplit(start_url)
    origin_key = (origin.scheme, origin.netloc.lower())
    queue = deque([start_url])
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []

    while queue and len(visited) < max(1, min(max_pages, MAX_PAGES)):
        current = queue.popleft()
        normalized = urllib.parse.urldefrag(current)[0]
        if normalized in visited:
            continue
        visited.add(normalized)
        fetched = _request(normalized)
        if fetched is None:
            if on_progress:
                on_progress(len(pages), len(visited), normalized)
            continue
        final_url, headers, body = fetched
        if urllib.parse.urlsplit(final_url).netloc.lower() != origin_key[1]:
            continue
        text = body.decode("utf-8", errors="replace")
        parser = PageParser()
        parser.feed(text)
        pages.append({"url": final_url, "status": "checked", "forms": parser.forms})
        if on_progress:
            on_progress(len(pages), len(visited), final_url)

        for header, (severity, remediation) in SECURITY_HEADERS.items():
            if header == "strict-transport-security" and urllib.parse.urlsplit(final_url).scheme != "https":
                continue
            if header not in headers:
                findings.append(_finding(
                    f"Missing {header}", severity, final_url,
                    f"The response does not include {header}.", remediation,
                ))

        for link in parser.links:
            absolute = urllib.parse.urljoin(final_url, link)
            parsed_link = urllib.parse.urlsplit(absolute)
            if (parsed_link.scheme, parsed_link.netloc.lower()) == origin_key and parsed_link.path:
                queue.append(absolute)

        query = urllib.parse.parse_qsl(urllib.parse.urlsplit(final_url).query, keep_blank_values=True)
        for name, value in query[:5]:
            if not name:
                continue
            marker = "webshield_check_7f3a"
            reflected_url = _replace_query(final_url, name, marker)
            reflected = _request(reflected_url)
            if reflected and marker.encode() in reflected[2]:
                findings.append(_finding(
                    "Possible reflected input", "Medium", reflected_url,
                    f"A benign marker in query parameter '{name}' appeared in the response.",
                    "HTML-encode untrusted values for their output context and use a strict Content-Security-Policy.",
                ))

            quote_url = _replace_query(final_url, name, value + "'")
            quote_response = _request(quote_url)
            if quote_response:
                response_text = quote_response[2].decode("utf-8", errors="ignore").lower()
                matched = next((marker for marker in SQL_ERROR_MARKERS if marker in response_text), None)
                if matched:
                    findings.append(_finding(
                        "Possible SQL error disclosure", "High", quote_url,
                        f"A database error signature appeared after a benign quote probe ({matched}).",
                        "Use parameterized queries, validate input, and return generic errors without database details.",
                    ))

    unique_findings = {(item["title"], item["url"]): item for item in findings}
    return {
        "target": start_url,
        "pages_scanned": len(pages),
        "pages_visited": len(visited),
        "pages": pages,
        "findings": list(unique_findings.values()),
    }


def _replace_query(url: str, name: str, value: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    updated = [(key, value if key == name else item) for key, item in query]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(updated), ""))