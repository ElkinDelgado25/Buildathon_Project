"""Tests for the fixed command catalog parser."""

import unittest

from app.services.command_service import (
    CommandDispatcher,
    CommandValidationError,
    OWASP_CATEGORIES,
)


class CommandCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dispatcher = CommandDispatcher()

    def test_slash_prefix_is_normalized(self) -> None:
        self.assertEqual(
            self.dispatcher._parse("/owasp audit A03"),
            ["owasp", "audit", "a03"],
        )

    def test_quoted_instruction_is_one_token(self) -> None:
        self.assertEqual(
            self.dispatcher._parse('/owasp audit A03 "review injection"'),
            ["owasp", "audit", "a03", "review injection"],
        )

    def test_unclosed_quote_is_rejected(self) -> None:
        with self.assertRaises(CommandValidationError):
            self.dispatcher._parse('/owasp audit A03 "incomplete')

    def test_all_ten_owasp_categories_are_cataloged(self) -> None:
        self.assertEqual(set(OWASP_CATEGORIES), {f"A{number:02d}" for number in range(1, 11)})


if __name__ == "__main__":
    unittest.main()
