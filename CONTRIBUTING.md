# Contributing

Thanks for helping build Context Control Plane.

## What Belongs In Core

Changes are a good fit for `ccp-core` when they make the kernel:

- simpler to understand
- safer by default
- easier to integrate
- more generic and vendor-neutral

If a change feels product-specific, tenant-specific, workflow-heavy, or tied to one company environment, it probably belongs in a downstream pack or integration layer instead of the core.

## Development Rules

- Prefer small, reviewable changes.
- Keep CLI output deterministic and machine-readable.
- Keep public contracts stable and explicit.
- Add or update focused tests for every behavior change.
- Avoid introducing new hidden runtime assumptions.

## Local Workflow

```bash
python3 -m pip install -e .[dev]
python3 -m unittest
```

Use targeted tests while iterating, then run the full public-core suite before opening a change.

## Pull Request Guidance

Please include:

- what changed
- why it belongs in the core
- any contract or behavior impact
- tests added or updated

Small truthful pull requests beat giant heroic ones. Heroic pull requests are how bugs get gym memberships.
