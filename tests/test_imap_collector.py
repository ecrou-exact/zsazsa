"""Tests for the IMAP newsletter collector: reading a body, matching a message
to a source, and the two IMAP commands the collector sends.

    python -m unittest tests.test_imap_collector
"""

import email
import imaplib
import unittest
from unittest import mock

from core import imap_collector


# What a server sends back after storing the flags, as imaplib hands it over.
STORED = f"1 (UID 7 FLAGS (\\Seen {imap_collector.PROCESSED_KEYWORD}))".encode()


class FakeConnection:
    """Just enough imaplib: uid() returns the (typ, data) pairs a server sends."""

    def __init__(self, store_reply=("OK", [STORED])):
        self.store_reply = store_reply
        self.commands = []

    def uid(self, command, *args):
        self.commands.append((command, args))
        if command == "search":
            return "OK", [b"7"]
        if command == "fetch":
            return "OK", [(b"1 (UID 7 BODY[] {12}", b"Subject: x\n\nbody"), b")"]
        return self.store_reply

    def select(self, folder):
        return "OK", [b"1"]

    def close(self):
        pass

    def logout(self):
        pass


def _msg(headers: dict, body: str, subtype: str = "plain") -> email.message.Message:
    raw = "".join(f"{k}: {v}\n" for k, v in headers.items())
    raw += f"Content-Type: text/{subtype}; charset=utf-8\n\n{body}"
    return email.message_from_string(raw)


class ExtractBody(unittest.TestCase):
    def test_plain_text(self):
        m = _msg({"Subject": "Hi"}, "Line one\nLine two")
        self.assertEqual(imap_collector.extract_body(m), "Line one\nLine two")

    def test_html_fallback_to_text(self):
        m = _msg({"Subject": "Hi"}, "<p>Hello <b>world</b></p>", subtype="html")
        body = imap_collector.extract_body(m)
        self.assertIn("Hello", body)
        self.assertNotIn("<p>", body)

    def test_prefers_plain_over_html_in_multipart(self):
        raw = (
            "Subject: Multi\n"
            'Content-Type: multipart/alternative; boundary="b"\n\n'
            "--b\nContent-Type: text/plain; charset=utf-8\n\nPLAIN body\n"
            "--b\nContent-Type: text/html; charset=utf-8\n\n<p>HTML body</p>\n"
            "--b--\n"
        )
        m = email.message_from_string(raw)
        self.assertEqual(imap_collector.extract_body(m).strip(), "PLAIN body")

    def test_strips_gmail_forward_preamble(self):
        body = (
            "---------- Forwarded message ----------\n"
            "From: ETDA <no-reply@etda.or.th>\n"
            "Date: Tue, 1 Jan 2026\n"
            "Subject: CTI Robot\n"
            "To: me@gmail.com\n"
            "\n"
            "Actual newsletter content starts here"
        )
        m = _msg({"Subject": "Fwd: CTI Robot"}, body)
        self.assertEqual(imap_collector.extract_body(m), "Actual newsletter content starts here")

    def test_skips_attachments(self):
        raw = (
            "Subject: WithAttach\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: text/plain; charset=utf-8\n\nReal body\n"
            "--b\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=x.pdf\n\nJVBERi0=\n"
            "--b--\n"
        )
        m = email.message_from_string(raw)
        self.assertEqual(imap_collector.extract_body(m).strip(), "Real body")


class Fetching(unittest.TestCase):
    def test_fetch_does_not_mark_mail_as_read(self):
        # A plain RFC822 fetch sets \Seen on every message read, including mail
        # for no source at all, and the UNSEEN fallback would then skip it.
        conn = FakeConnection()
        with mock.patch.object(imap_collector, "_connect", return_value=conn):
            messages = list(imap_collector.fetch_unprocessed({"folder": "INBOX"}))
        self.assertEqual(len(messages), 1)
        fetched = [args for command, args in conn.commands if command == "fetch"]
        self.assertEqual(fetched, [(b"7", "(BODY.PEEK[])")])


class MarkProcessed(unittest.TestCase):
    """The keyword is what stops a mail being collected twice, so a server that
    does not keep it has to be reported rather than assumed."""

    def test_keyword_accepted(self):
        conn = FakeConnection()
        self.assertTrue(imap_collector.mark_processed(conn, b"7"))
        command, args = conn.commands[0]
        self.assertEqual(command, "store")
        self.assertEqual(args[1], "+FLAGS")
        self.assertIn(imap_collector.PROCESSED_KEYWORD, args[2])

    def test_refused_by_the_server(self):
        conn = FakeConnection(store_reply=("NO", [b"keywords not supported"]))
        self.assertFalse(imap_collector.mark_processed(conn, b"7"))

    def test_accepted_but_not_kept(self):
        # An OK whose flags come back without the keyword: the message would be
        # collected again on every run.
        conn = FakeConnection(store_reply=("OK", [b"1 (UID 7 FLAGS (\\Seen))"]))
        self.assertFalse(imap_collector.mark_processed(conn, b"7"))

    def test_server_that_echoes_nothing_is_believed(self):
        conn = FakeConnection(store_reply=("OK", [None]))
        self.assertTrue(imap_collector.mark_processed(conn, b"7"))

    def test_connection_error(self):
        conn = mock.Mock()
        conn.uid.side_effect = imaplib.IMAP4.error("connection closed")
        self.assertFalse(imap_collector.mark_processed(conn, b"7"))


class Matching(unittest.TestCase):
    def test_subject_match(self):
        m = _msg({"Subject": "Fwd: ETDA CTI Robot", "From": "me@gmail.com"}, "body")
        self.assertTrue(imap_collector.matches(m, ["cti robot"], []))

    def test_sender_match_on_header(self):
        m = _msg({"Subject": "x", "From": "ETDA <no-reply@etda.or.th>"}, "body")
        self.assertTrue(imap_collector.matches(m, [], ["etda.or.th"]))

    def test_sender_match_on_forwarded_original(self):
        # The envelope From is the forwarder; the real sender is in the forwarded
        # preamble, which matching must still see even though parsing strips it.
        body = (
            "---------- Forwarded message ----------\n"
            "From: ETDA <no-reply@etda.or.th>\n"
            "Subject: CTI Robot\n\n"
            "newsletter content"
        )
        m = _msg({"Subject": "Fwd", "From": "me@gmail.com"}, body)
        self.assertTrue(imap_collector.matches(m, [], ["no-reply@etda.or.th"]))
        # And the body handed to the parser has the preamble removed.
        self.assertEqual(imap_collector.extract_body(m), "newsletter content")

    def test_sender_match_on_apple_quoted_forward(self):
        # Apple Mail forwards quote every line with "> "; the original sender
        # still has to be found despite the quote marker.
        body = (
            "> Begin forwarded message:\n"
            "> From: ETDA <no-reply@etda.or.th>\n"
            "> Subject: CTI Robot\n>\n"
            "> newsletter content"
        )
        m = _msg({"Subject": "Fwd", "From": "me@gmail.com"}, body)
        self.assertTrue(imap_collector.matches(m, [], ["no-reply@etda.or.th"]))

    def test_no_criteria_matches_all(self):
        m = _msg({"Subject": "anything", "From": "a@b.c"}, "body")
        self.assertTrue(imap_collector.matches(m, [], []))
        # blank entries count as no criteria too
        self.assertTrue(imap_collector.matches(m, ["", "  "], []))

    def test_no_match(self):
        m = _msg({"Subject": "weekly sales", "From": "sales@shop.com"}, "body")
        self.assertFalse(imap_collector.matches(m, ["etda"], ["etda.or.th"]))


if __name__ == "__main__":
    unittest.main()
