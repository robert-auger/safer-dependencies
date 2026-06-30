"""PyPI artifact-hash helpers shared by the shim and pypi_hashes.py.

The two callers use the PyPI ``/pypi/<pkg>/<version>/json`` response in
different ways — the shim validates user-declared sha256 pins against the
published digests, and the standalone CLI prints ``--hash=sha256:<digest>``
lines suitable for pasting into a ``requirements.txt``. They share the
low-level traversal: walk ``data["urls"]``, pull out each artifact's
``packagetype`` and sha256 digest. Centralising that here keeps the two
copies from drifting if PyPI adds a new artifact type or digest format.
"""


def iter_pypi_artifact_hashes(data):
    """Yield ``(packagetype, sha256)`` for every url entry that has a sha256.

    ``packagetype`` may be an empty string if the response omits it. Entries
    without a sha256 digest are skipped entirely.
    """
    for url in (data or {}).get("urls", []):
        if not isinstance(url, dict):
            continue
        sha = (url.get("digests") or {}).get("sha256", "")
        if sha:
            yield url.get("packagetype", ""), sha
