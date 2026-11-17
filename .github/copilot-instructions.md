# WebShield workspace notes

- This is a local educational security scanner. Never remove the loopback-only target restriction, explicit authorization check, redirect refusal, request throttle, or scan bounds.
- Do not add destructive probes, exploit payloads, form submission, or scanning of public/non-local targets.
- Run focused checks with `python -m unittest discover -s tests -v` and launch with `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
- Dashboard history is in-memory by design. Keep all endpoints and reports intended for a local single-user workflow.