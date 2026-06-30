import json, sys
from safedep.registry import _pypi_earliest_upload_time_str
try:
    result = _pypi_earliest_upload_time_str(json.load(sys.stdin))
    print(result if result else 'unknown')
except (json.JSONDecodeError, AttributeError, KeyError):
    print('ERROR: invalid response')
