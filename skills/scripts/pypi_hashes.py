import json, sys
from safedep.pypi_hashes import iter_pypi_artifact_hashes
try:
    d = json.load(sys.stdin)
    name, version = d['info']['name'], d['info']['version']
    for pkgtype, sha in iter_pypi_artifact_hashes(d):
        if pkgtype in ('bdist_wheel', 'sdist'):
            print(f"{name}=={version} --hash=sha256:{sha}")
except (json.JSONDecodeError, AttributeError, KeyError, TypeError):
    print('ERROR: invalid response')
