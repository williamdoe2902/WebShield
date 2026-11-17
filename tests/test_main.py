import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from app.main import _run_monitor_scan, list_monitors, monitors, scan_order, scans


class MonitorFindingTests(unittest.TestCase):
    def setUp(self):
        scans.clear()
        scan_order.clear()
        monitors.clear()
        monitors["monitor-1"] = {
            "id": "monitor-1",
            "target": "http://localhost/",
            "status": "queued",
            "finding_count": 0,
            "new_findings": [],
        }

    def tearDown(self):
        scans.clear()
        scan_order.clear()
        monitors.clear()

    def test_monitor_reports_only_findings_new_since_previous_check(self):
        findings = [{
            "title": "Missing header",
            "url": "http://localhost/",
            "severity": "Low",
        }]

        async def complete_scan(scan_id, _target):
            scans[scan_id].update({
                "status": "complete",
                "findings": list(findings),
                "finished_at": "2026-11-17T00:00:00+00:00",
            })

        with patch("app.main._run_scan", new=AsyncMock(side_effect=complete_scan)):
            asyncio.run(_run_monitor_scan("monitor-1"))
            self.assertEqual(len(monitors["monitor-1"]["new_findings"]), 1)

            asyncio.run(_run_monitor_scan("monitor-1"))
            self.assertEqual(monitors["monitor-1"]["new_findings"], [])

            findings.append({
                "title": "Missing CSP",
                "url": "http://localhost/",
                "severity": "Medium",
            })
            asyncio.run(_run_monitor_scan("monitor-1"))
            self.assertEqual(
                [finding["title"] for finding in monitors["monitor-1"]["new_findings"]],
                ["Missing CSP"],
            )

    def test_monitor_api_output_excludes_internal_finding_keys(self):
        monitors["monitor-1"]["finding_keys"] = {("title", "url", "Low")}
        result = asyncio.run(list_monitors())
        self.assertNotIn("finding_keys", result[0])
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()
