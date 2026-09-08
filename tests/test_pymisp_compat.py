"""Galaxy clusters as a MISP server sends them stay parseable.

These say what zsazsa needs of PyMISP rather than how it gets it, so they pass
on a release that parses default clusters and on one that only does with the
shim in core/pymisp_compat.py. The stripping itself is exercised directly, so
it stays covered on a PyMISP that never needs it.

    python -m unittest tests.test_pymisp_compat
"""

import unittest

from pymisp import MISPEvent, MISPGalaxyCluster
from pymisp.exceptions import NewGalaxyClusterError

from core import pymisp_compat

pymisp_compat.apply()


def _server_cluster(**over):
    """A cluster from MISP's own galaxy library, in the shape MISP returns it:
    flagged default, and carrying the distribution the server keeps for it."""
    fields = {
        "uuid": "7cdff317-a673-4474-84ec-4f1754947823", "value": "APT28",
        "type": "mitre-intrusion-set",
        "tag_name": 'misp-galaxy:mitre-intrusion-set="APT28 - G0007"',
        "default": True, "distribution": "3", "sharing_group_id": None,
    }
    fields.update(over)
    return fields


class ServerClusters(unittest.TestCase):
    def test_a_default_cluster_parses_with_what_zsazsa_reads_off_it(self):
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**_server_cluster())
        self.assertEqual(cluster.value, "APT28")
        self.assertEqual(cluster.uuid, "7cdff317-a673-4474-84ec-4f1754947823")
        self.assertEqual(cluster.tag_name, 'misp-galaxy:mitre-intrusion-set="APT28 - G0007"')

    def test_a_default_cluster_still_has_a_distribution_attribute(self):
        """Stripping the field does not take the attribute away, because PyMISP
        sets one whether or not the server sent it. The value is not pinned here:
        it is the server's on a release that keeps it and PyMISP's own 0 on one
        where this had to strip it. Nothing here reads it; what matters is that
        no consumer meets an attribute that has gone missing."""
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**_server_cluster())
        self.assertTrue(hasattr(cluster, "distribution"))

    def test_an_event_carrying_one_parses(self):
        """The collection cache pythonifies whole events, so a galaxy tag on any
        of them used to take the whole refresh down."""
        event = MISPEvent()
        event.from_dict(**{"Event": {
            "id": "42", "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
            "info": "Ransomware infrastructure", "date": "2026-01-01",
            "Galaxy": [{"id": "22", "uuid": "c4e851fa-775f-11e7-8163-b774922098cd",
                        "name": "Intrusion Set", "GalaxyCluster": [_server_cluster()]}],
        }})
        self.assertEqual([c.value for c in event.Galaxy[0].clusters], ["APT28"])

    def test_a_cluster_of_our_own_keeps_its_distribution(self):
        """Only the server's own clusters lose it; nothing else is touched."""
        cluster = MISPGalaxyCluster()
        cluster.from_dict(**_server_cluster(default=False))
        self.assertEqual(cluster.distribution, 3)

    def test_an_impossible_distribution_is_still_refused(self):
        cluster = MISPGalaxyCluster()
        with self.assertRaises(NewGalaxyClusterError):
            cluster.from_dict(**_server_cluster(default=False, distribution="9"))

    def test_stripping_leaves_everything_but_the_sharing_metadata(self):
        fields = _server_cluster()
        stripped = pymisp_compat.without_server_sharing(fields)
        self.assertNotIn("distribution", stripped)
        self.assertNotIn("sharing_group_id", stripped)
        self.assertEqual(stripped["value"], "APT28")
        self.assertTrue(stripped["default"])
        # What was handed over is the parsed response, and it is left alone.
        self.assertIn("distribution", fields)
        self.assertIn("sharing_group_id", fields)


if __name__ == "__main__":
    unittest.main()
