import json, sys
from safedep.github import created_at_from_repo_data
try:
    ts = created_at_from_repo_data(json.load(sys.stdin))
    print(ts if ts else 'unknown')
except (json.JSONDecodeError, AttributeError):
    print('ERROR: invalid response')
