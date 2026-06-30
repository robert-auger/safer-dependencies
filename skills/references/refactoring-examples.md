# Refactor scenarios

Illustrative scenarios for the "4. Refactor Code If Needed" step in
`safer-dependencies.md`. Read this file when an `UPDATED:` signal indicates
breaking changes between the old and new versions and you need a concrete
template for the refactor.

**Scenario A: Method signature change**
```python
# Old code (aiohttp 3.8.5)
async with session.get(url) as resp:
    data = await resp.json()

# After update to 3.9.0 (if signature changed)
# Check release notes, refactor if needed
async with session.get(url) as resp:
    data = await resp.json()  # Usually compatible
```

**Scenario B: Removed feature**
```javascript
// Old code (lodash 3.x) — _.pluck was removed in lodash 4.0.0
const names = _.pluck(users, 'name');

// After update to 4.17.21 — use _.map with the property-shorthand replacement
const names = _.map(users, 'name');
```
