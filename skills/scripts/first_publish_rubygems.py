import json, sys
from safedep.registry import _rubygems_earliest_created_at_str
try:
    result = _rubygems_earliest_created_at_str(json.load(sys.stdin))
    print(result if result else 'unknown')
except (json.JSONDecodeError, AttributeError):
    print('ERROR: invalid response')
