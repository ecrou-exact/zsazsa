"""Pulling an event from MISP gives up on the clock.

_fetch_event_timed runs the two MISP calls in a thread so a server that stops
answering cannot hold a Flask worker for longer than _PULL_TIMEOUT. The
executor used as a context manager waited for that thread on the way out,
which made the timeout no shorter than the call it was there to cut off.

    python -m unittest tests.test_pull_timeout
"""

import threading
import time
import unittest
from types import SimpleNamespace

from webapp.routes.data_collection import _fetch_event_timed


class PullTimeout(unittest.TestCase):
    def test_a_server_that_stops_answering_does_not_hold_the_caller(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stalled(*args, **kwargs):
            release.wait(10)
            return None

        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            _fetch_event_timed(SimpleNamespace(get_event=stalled), "u" * 36, 0.1)
        self.assertLess(time.monotonic() - started, 1)


if __name__ == "__main__":
    unittest.main()
