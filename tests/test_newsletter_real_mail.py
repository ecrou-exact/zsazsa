"""Parse two newsletter e-mails, both the way they arrive and with their
plain-text part removed.

The fixtures in test_newsletter_parsers.py are copies pasted out of a mail
client. A mailing list sends a different plain text, and a forward from a client
that drops the plain part leaves the collector converting HTML instead, so those
two shapes are what these cover.

tests/data holds the mails. The IT-ISAC one is an edition as it arrived, which
its TLP:CLEAR marking allows. The ETDA one carries the layout and the markup of a
real edition but invented articles: ETDA sends TLP:GREEN, which does not belong
in a public repository. Keep it that way when adding editions here.

    python -m unittest tests.test_newsletter_real_mail
"""

import email
import os
import re
import unittest
from email.message import EmailMessage

from core import imap_collector
from webapp import newsletter_parsers

DATA = os.path.join(os.path.dirname(__file__), "data")
ETDA_SECTIONS = ["Healthcare Sector", "Vulnerabilities", "Malware", "General News"]


def _load(name):
    with open(os.path.join(DATA, name), "rb") as fh:
        return email.message_from_bytes(fh.read())


def _html_only(msg):
    """The same message as a client sends it when it keeps no plain-text part."""
    part = next(p for p in msg.walk() if p.get_content_type() == "text/html")
    html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
    out = EmailMessage()
    out["Subject"] = msg["Subject"]
    out["From"] = msg["From"]
    out.set_content(html, subtype="html")
    return out


def _parse(msg, source):
    return newsletter_parsers.parse(source, imap_collector.extract_body(msg))


class EtdaListMail(unittest.TestCase):
    """The edition as the mailing list sends it: '* ' titles, no overview table."""

    def setUp(self):
        self.result = _parse(_load("etda_newsletter.eml"), "ETDA CTI Robot")
        self.articles = self.result["articles"]

    def test_report_metadata(self):
        self.assertEqual(self.result["report_title"],
                         "[FIRST] ETDA Cyber Threat Intelligence of 1 January 2026")
        self.assertEqual(self.result["tlp"], "green")

    def test_every_article_is_complete(self):
        self.assertEqual(len(self.articles), 6)
        for article in self.articles:
            self.assertTrue(article["title"])
            self.assertTrue(article["primary_url"].startswith("http"))
            self.assertIn(article["section"], ETDA_SECTIONS)

    def test_titles_carry_no_markup(self):
        # A bullet or heading marker left on a title means the decoration reached
        # it, and the title is what becomes the event name in MISP. A bare '#', as
        # in "#StopRansomware", is part of the name and stays.
        for article in self.articles:
            self.assertIsNone(re.match(r"[*+-]\s|#{1,6}\s", article["title"]),
                              article["title"])

    def test_section_headings_are_not_mistaken_for_titles(self):
        titles = [a["title"] for a in self.articles]
        for section in ETDA_SECTIONS:
            self.assertNotIn(section, titles)
        self.assertNotIn(self.result["report_title"], titles)

    def test_sections_are_read_in_order(self):
        seen = []
        for article in self.articles:
            if article["section"] not in seen:
                seen.append(article["section"])
        self.assertEqual(seen, ETDA_SECTIONS)

    def test_first_article(self):
        first = self.articles[0]
        self.assertEqual(first["title"], "Sample Imaging Gateway Advisory")
        self.assertEqual(first["section"], "Healthcare Sector")
        self.assertEqual(first["priority_key"], "important")
        self.assertEqual(first["primary_url"],
                         "https://example.org/advisories/imaging-gateway")
        self.assertEqual(first["related_urls"],
                         ["https://example.com/news/imaging-gateway-flaws"])
        self.assertTrue(first["intro"].startswith("Successful exploitation"))

    def test_priorities_the_review_page_preselects(self):
        # The review page ticks critical and urgent for the analyst, so the keys
        # have to come through, not just the label ETDA printed.
        graded = {a["title"]: a["priority_key"] for a in self.articles}
        self.assertEqual(graded["Example Router Firmware Authentication Bypass"], "critical")
        self.assertEqual(graded["#SampleRansomware: Example Crew"], "urgent")

    def test_a_title_starting_with_a_hash_is_not_a_heading(self):
        # "#StopRansomware" advisories are common and are not Markdown headings.
        self.assertIn("#SampleRansomware: Example Crew",
                      [a["title"] for a in self.articles])


class EtdaHtmlOnlyMail(unittest.TestCase):
    """The same edition with no plain-text part, which the collector converts to
    Markdown. This is the shape that used to parse to nothing at all."""

    def setUp(self):
        message = _load("etda_newsletter.eml")
        self.plain = _parse(message, "ETDA CTI Robot")
        self.converted = _parse(_html_only(message), "ETDA CTI Robot")

    def test_articles_are_found(self):
        self.assertEqual(len(self.converted["articles"]), 6)

    def test_markdown_escaping_is_undone_in_titles(self):
        # The converter escapes the underscore, and the title becomes the event
        # name in MISP, so it has to be the name ETDA wrote.
        self.assertIn("Example_Toolkit Path Traversal",
                      [a["title"] for a in self.converted["articles"]])

    def test_same_articles_as_the_plain_part(self):
        # Same edition, so whichever part it was read from must not change what
        # is offered for collection.
        self.assertEqual([a["title"] for a in self.converted["articles"]],
                         [a["title"] for a in self.plain["articles"]])
        self.assertEqual([a["primary_url"] for a in self.converted["articles"]],
                         [a["primary_url"] for a in self.plain["articles"]])
        self.assertEqual([a["section"] for a in self.converted["articles"]],
                         [a["section"] for a in self.plain["articles"]])
        self.assertEqual(self.converted["tlp"], self.plain["tlp"])


class ItisacRealMail(unittest.TestCase):
    def setUp(self):
        message = _load("itisac_newsletter.eml")
        self.plain = _parse(message, "IT-ISAC Open Source News")
        self.converted = _parse(_html_only(message), "IT-ISAC Open Source News")

    def test_articles(self):
        self.assertEqual(len(self.plain["articles"]), 10)
        self.assertEqual(self.plain["report_title"],
                         "[IT-ISAC] Open Source News September 11, 2026")
        self.assertEqual(self.plain["tlp"], "clear")
        for article in self.plain["articles"]:
            self.assertTrue(article["title"])
            self.assertTrue(article["primary_url"].startswith("http"))

    def test_same_articles_from_either_part(self):
        self.assertEqual([a["title"] for a in self.converted["articles"]],
                         [a["title"] for a in self.plain["articles"]])
        self.assertEqual([a["primary_url"] for a in self.converted["articles"]],
                         [a["primary_url"] for a in self.plain["articles"]])


class Decoration(unittest.TestCase):
    """The individual pieces of Markdown that a converted mail brings along."""

    def test_emphasised_fields_still_match(self):
        text = ("Vulnerabilities\n---------------\n\n"
                "### Full Broker Takeover\n\n"
                '"Two critical access-control flaws."\n'
                "*Priority: 2 - Urgent*\n\n*Relevance: General*\n\n"
                "<<https://example.org/rabbitmq>>\n")
        article = newsletter_parsers.parse("ETDA CTI Robot", text)["articles"][0]
        self.assertEqual(article["title"], "Full Broker Takeover")
        self.assertEqual(article["section"], "Vulnerabilities")
        self.assertEqual(article["priority_key"], "urgent")
        self.assertEqual(article["relevance"], "General")
        self.assertEqual(article["primary_url"], "https://example.org/rabbitmq")

    def test_escaped_punctuation_is_undone(self):
        text = ("Malware\n-------\n\n### SleeperGem: Compromised Git\\_credential\\_manager\n\n"
                "Priority: 3 - Important\n\n<https://example.org/gem>\n")
        article = newsletter_parsers.parse("ETDA CTI Robot", text)["articles"][0]
        self.assertEqual(article["title"], "SleeperGem: Compromised Git_credential_manager")


if __name__ == "__main__":
    unittest.main()
