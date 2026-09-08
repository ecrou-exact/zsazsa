"""Let PyMISP parse the galaxy clusters a MISP server sends.

PyMISP refuses a distribution or a sharing group on a cluster flagged `default`.
Good for a cluster you build to send, but from_dict also parses what
comes back, and MISP serves every default cluster with a distribution. The check
was dead code until a missing comma was fixed in 2.5.34.2 (MISP/PyMISP#1459),
and since then nothing carrying a galaxy can be pythonified.

Only a PyMISP that refuses them is patched, a fixed release is left alone.
"""

from pymisp import MISPGalaxyCluster
from pymisp.exceptions import NewGalaxyClusterError


def without_server_sharing(fields: dict) -> dict:
    """The cluster fields without the sharing metadata the server owns."""
    stripped = dict(fields)
    stripped.pop("distribution", None)
    stripped.pop("sharing_group_id", None)
    return stripped


def _refuses_server_clusters() -> bool:
    """Whether this PyMISP rejects a default cluster in the shape MISP sends it."""
    try:
        MISPGalaxyCluster().from_dict(
            uuid="00000000-0000-0000-0000-000000000000", value="probe",
            default=True, distribution="3",
        )
    except NewGalaxyClusterError:
        return True
    return False


def _install() -> None:
    """Strip the server's sharing metadata off default clusters on the way in."""
    original = MISPGalaxyCluster.from_dict

    def from_dict(self, **kwargs):
        # A cluster arrives either as the fields themselves or wrapped, and
        # PyMISP unwraps it, so this has to look in both places.
        wrapped = kwargs.get("GalaxyCluster")
        if isinstance(wrapped, dict) and wrapped.get("default"):
            kwargs = dict(kwargs, GalaxyCluster=without_server_sharing(wrapped))
        elif kwargs.get("default"):
            kwargs = without_server_sharing(kwargs)
        # PyMISP sets a distribution whether or not one arrived, so the cluster
        # still has the attribute, holding its 0 rather than the server's value.
        return original(self, **kwargs)

    MISPGalaxyCluster.from_dict = from_dict


# True once this turned out to be needed, for whoever wants to say so in a log.
installed = False


def apply() -> None:
    """Patch PyMISP if this release refuses the clusters. Safe to call twice."""
    global installed
    if not installed and _refuses_server_clusters():
        _install()
        installed = True
