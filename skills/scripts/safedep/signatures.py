"""Layer 4 — artifact signature / integrity checks.

Used by both the shim (intercept mode) and the manual-mode skill to
answer a single per-ecosystem question: "did the package author sign
this release in a way the registry exposes?"

Different ecosystems have different conventions:

  Maven Central publishes a detached GPG ``.asc`` signature alongside
  every artifact. Maven Central validates these at upload time, so the
  mere presence of the ``.asc`` file at the expected URL is a trust
  signal — we use a HEAD request and check the status code.

  RubyGems packages are ``.gem`` files (a tar archive). When a gem is
  signed, the archive contains ``data.tar.gz.sig`` and
  ``metadata.gz.sig`` entries. Signed gems are rare — LOW warning only
  when unsigned.

  npm has provenance attestations (since 2023) exposed in registry
  metadata under ``dist.attestations``. Separate helper module to be
  added; not covered here.

  PyPI uses ``--require-hashes`` in ``requirements.txt`` instead of
  signed artifacts; validation already lives in the shim.

All helpers fail open: a network failure / timeout / malformed response
returns None (inconclusive). None means "do not emit a signal"; only
explicit True/False should drive Layer 4 output.
"""

from __future__ import annotations

import io
import tarfile
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError



# ────────────────────────────── Maven ──────────────────────────────


def maven_has_signature(group_id: str, artifact_id: str, version: str) -> Optional[bool]:
    """Return True if Maven Central exposes a .asc signature for this artifact.

    Probes
      https://repo1.maven.org/maven2/<groupPath>/<artifactId>/<version>/<artifactId>-<version>.jar.asc

    with a HEAD request. Maven Central validates signatures at upload time,
    so a 200 response means the signature is present and was verified by the
    registry itself. 404 means the artifact was uploaded without a GPG
    signature (unusual — most OSS publishers sign).
    """
    if not (group_id and artifact_id and version):
        return None
    group_path = group_id.replace(".", "/")
    url = (
        f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/"
        f"{version}/{artifact_id}-{version}.jar.asc"
    )
    status = _http_head_status(url)
    if 200 <= status < 300:
        return True
    if status == 404:
        return False
    return None


# ────────────────────────────── RubyGems ──────────────────────────────


def rubygems_has_signature(pkg: str, version: str, *, timeout: int = 20) -> Optional[bool]:
    """Return True if the .gem archive for pkg@version contains signature files.

    Downloads the .gem file from https://rubygems.org/gems/<pkg>-<version>.gem
    and inspects the archive's member names. A signed gem contains one or both
    of:
      - metadata.gz.sig
      - data.tar.gz.sig

    Fails open on network errors, archive-parse errors, or a 404.

    timeout is generous (default 20s) because the .gem file is larger than a
    JSON response and RubyGems CDN latency varies.
    """
    if not (pkg and version):
        return None
    url = f"https://rubygems.org/gems/{pkg}-{version}.gem"
    try:
        req = Request(url, headers={"User-Agent": "safer-dependencies-shim/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None
    if not data:
        return None
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r") as tf:
            members = tf.getnames()
    except Exception:
        return None
    signed = any(name.endswith(".sig") for name in members)
    return signed


# ────────────────────────────── internal ──────────────────────────────


def _http_head_status(url: str, timeout: int = 10) -> int:
    """Issue a HEAD request and return the integer status. 0 on any error.

    Used instead of _http_get_status for signature probes because a HEAD
    avoids downloading the full jar just to check whether a .asc exists.
    """
    try:
        req = Request(
            url,
            method="HEAD",
            headers={"User-Agent": "safer-dependencies-shim/1.0"},
        )
        with urlopen(req, timeout=timeout) as resp:
            return resp.getcode()
    except HTTPError as e:
        return e.code
    except Exception:
        return 0
