import json, sys, datetime
from safedep.registry import _maven_docs_earliest_timestamp_ms
try:
    docs = json.load(sys.stdin)['response']['docs']
    ms = _maven_docs_earliest_timestamp_ms(docs)
    if ms is None:
        print('unknown')
    else:
        print(datetime.datetime.fromtimestamp(ms/1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
except (json.JSONDecodeError, AttributeError, KeyError):
    print('ERROR: invalid response')
