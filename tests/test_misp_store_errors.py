"""Failed MISP writes have to reach the caller.

PyMISP answers a rejected call with a dict holding "errors" instead of raising,
so a delete or an attribute write that silently returned one used to look like a
success: the page flashed "deleted" and the record was still there. Deleting
something that is already gone is the one error worth swallowing.

    python -m unittest tests.test_misp_store_errors
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store

_ERROR = {"errors": (403, {"message": "Could not delete Event."})}
_GONE = {"errors": (404, {"message": "Invalid attribute."})}


class DeleteFailures(unittest.TestCase):
    def setUp(self):
        self.misp = mock.MagicMock()
        patcher = mock.patch.object(misp_store, "_misp", return_value=self.misp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_refused_event_delete_raises(self):
        self.misp.delete_event.return_value = _ERROR
        for delete in (misp_store.delete_pir, misp_store.delete_gir, misp_store.delete_rfi,
                       misp_store.delete_briefing, misp_store.delete_tlr,
                       misp_store.delete_indicator_feed, misp_store.delete_fia,
                       misp_store.delete_vea, misp_store.delete_threat_actor_profile):
            with self.subTest(delete=delete.__name__):
                with self.assertRaises(RuntimeError):
                    delete("u" * 36)

    def test_a_successful_event_delete_is_quiet(self):
        self.misp.delete_event.return_value = {"message": "Event deleted."}
        misp_store.delete_pir("u" * 36)

    def test_a_refused_stakeholder_delete_raises(self):
        self.misp.delete_event.return_value = _ERROR
        with mock.patch.object(misp_store, "_stakeholder_event",
                               return_value=SimpleNamespace(uuid="u" * 36)):
            with self.assertRaises(RuntimeError):
                misp_store.delete_stakeholder("u" * 36)

    def test_a_refused_attribute_delete_raises(self):
        self.misp.delete_attribute.return_value = _ERROR
        with self.assertRaises(RuntimeError):
            misp_store.delete_focus_point("a" * 36)

    def test_an_attribute_that_is_already_gone_is_not_an_error(self):
        # Re-submitting a delete, or a concurrent one, should not fail the page.
        self.misp.delete_attribute.return_value = _GONE
        misp_store.delete_focus_point("a" * 36)
        misp_store.delete_rfi_attachment("a" * 36)
        misp_store.delete_fia_attachment("a" * 36)


class SearchOutages(unittest.TestCase):
    """A MISP that does not answer must not look like a query with no matches.

    The per-server loop keeps going when one server fails, which is right for a
    partial outage, but a total one used to come back as an empty result: the
    page said "no indicators match", and a cached feed wrote that empty answer
    to disk and served it for the rest of its interval.
    """

    def _clients(self, *behaviours):
        clients = []
        for i, raising in enumerate(behaviours):
            client = mock.MagicMock()
            if raising:
                client.search.side_effect = ConnectionError("down")
            else:
                client.search.return_value = [
                    {"type": "ip-dst", "value": f"10.0.0.{i}", "timestamp": "1700000000",
                     "to_ids": True, "Event": {"id": "1", "uuid": "e" * 36, "info": "x",
                                               "date": "2026-01-01", "Orgc": {"name": "ORG"}}}]
            clients.append((f"s{i}", f"S{i}", "https://misp.example", client))
        return clients

    def test_it_raises_when_no_server_answers(self):
        with mock.patch.object(misp_store, "_indicator_feed_clients",
                               return_value=self._clients(True, True)):
            with self.assertRaises(RuntimeError) as caught:
                misp_store.search_indicators({"limit": 10})
        self.assertEqual(str(caught.exception), "no MISP server answered")

    def test_it_raises_when_there_is_no_server_to_ask(self):
        """The analyst reads this reason on the page, and an install with no
        servers yet is a different problem from one that cannot be reached."""
        with mock.patch.object(misp_store, "_indicator_feed_clients", return_value=[]):
            with self.assertRaises(RuntimeError) as caught:
                misp_store.search_indicators({"limit": 10})
        self.assertIn("no MISP server is configured", str(caught.exception))

    def test_one_server_answering_is_still_an_answer(self):
        with mock.patch.object(misp_store, "_indicator_feed_clients",
                               return_value=self._clients(True, False)):
            rows = misp_store.search_indicators({"limit": 10})
        self.assertEqual([r["value"] for r in rows], ["10.0.0.1"])

    def test_the_count_reports_an_outage_rather_than_zero(self):
        with mock.patch.object(misp_store, "_indicator_feed_clients",
                               return_value=self._clients(True, True)):
            with self.assertRaises(RuntimeError):
                misp_store.count_indicators({"limit": 10})

    def test_a_failed_search_keeps_the_feed_out_of_the_cache(self):
        import tempfile
        from pathlib import Path
        from webapp import feed_cache
        from webapp.routes import indicator_feed
        feed = SimpleNamespace(uuid="f" * 36, id="f" * 36, feed_id="FEED-001", name="n",
                               query={"types": ["ip-dst"], "limit": 5}, tlp="clear",
                               cache_interval="daily", cache_anchor="")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")), \
             mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name)), \
             mock.patch.object(feed_cache, "write") as write:
            body = indicator_feed._feed_export(feed, "txt", {})
        self.assertEqual(body, "")
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
