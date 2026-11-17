# WebShield

WebShield is an educational, local-lab web application scanner with a small FastAPI dashboard. It crawls a bounded set of same-origin pages, inventories links and HTML form inputs without submitting forms, checks common response security headers, and performs benign query-string reflection and database-error signature checks. Findings include severity, evidence, and remediation notes; reports can be printed or saved as HTML from the browser.

The dashboard also supports explicitly authorized local-app monitors. A monitor runs an initial scan when added, then repeats every five minutes while the server is running. New findings are shown in the dashboard. Monitor configuration and scan history are in-memory and are cleared when the server restarts. This is a local web-app monitor, not antivirus or a Windows Defender replacement.

## Safety scope

- Scans require an explicit authorization checkbox and accept only `localhost` or literal loopback IP addresses such as `127.0.0.1` and `::1`. Other hostnames are rejected to avoid DNS rebinding.
- Redirects are not followed. Each requested URL is checked again before the request.
- Crawling is capped at 30 pages, response bodies at 1 MB, requests at one every 250 ms, and request timeouts at five seconds.
- Forms are inventoried only; WebShield never submits them. No directory traversal tests, destructive actions, authentication bypasses, or exploit payloads are included.
- The dashboard is intended to bind to `127.0.0.1` and stores scan history in memory, so history clears when the process restarts.
- Monitors accept the same authorization and loopback-only constraints as manual scans. They are not persisted across restarts and run only while the dashboard server is active.
- Use only on systems you own or have explicit permission to assess. Findings are indicators for manual verification, not a penetration test or security certification.

## Run on Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in a browser. To run the scanner guard tests:

```powershell
python -m unittest discover -s tests -v
```

## Checks and limitations

The scanner identifies missing CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` headers. For discovered query parameters it substitutes a plain text marker to look for reflection and adds a single quote to check for recognizable database error messages. These are heuristic checks and may produce false positives or miss vulnerabilities. It does not detect stored XSS, blind SQL injection, or directory traversal.