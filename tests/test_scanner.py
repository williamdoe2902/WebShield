import unittest
from unittest.mock import patch

from app.scanner import PageParser, _replace_query, validate_target


class TargetValidationTests(unittest.TestCase):
    def test_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "authorized"):
            validate_target("http://127.0.0.1:3000", False)

    def test_accepts_loopback_target(self):
        self.assertEqual(validate_target("http://127.0.0.1:3000", True), "http://127.0.0.1:3000/")

    @patch("app.scanner._resolve_loopback", return_value=False)
    def test_rejects_non_loopback_target(self, _resolve):
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_target("https://example.com", True)

    def test_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "HTTP"):
            validate_target("file:///etc/passwd", True)

    def test_rejects_named_hosts_even_if_they_look_like_lab_hosts(self):
        with self.assertRaisesRegex(ValueError, "localhost"):
            validate_target("http://juice-shop.local", True)

    def test_query_probe_preserves_other_parameters(self):
        self.assertEqual(
            _replace_query("http://127.0.0.1/?q=hello&page=2", "q", "test'"),
            "http://127.0.0.1/?q=test%27&page=2",
        )

    def test_parser_inventories_links_and_forms_without_submitting(self):
        parser = PageParser()
        parser.feed('<a href="/search?q=sample">Search</a><form method="post"><input name="email" type="email"></form>')
        self.assertEqual(parser.links, ["/search?q=sample"])
        self.assertEqual(parser.forms[0]["method"], "POST")
        self.assertEqual(parser.forms[0]["inputs"][0]["name"], "email")


if __name__ == "__main__":
    unittest.main()