# Gatehouse change-review exercise

Gatehouse is a small authorization service. It accepts requests from authenticated
principals, checks resource policies, enforces per-user quotas, and records every
decision in a hash-chained audit log.

This repository is meant to be explored through its Git history. The tag
`exercise/base` marks a known-good release. Six subsequent changes are tagged
`exercise/change-01` through `exercise/change-06`. Some changes are harmless;
others introduce behavioral regressions.

Your task is not merely to find suspicious-looking lines. Decide whether each
change can make the service behave differently, produce a concrete input (or
sequence of inputs) that demonstrates the difference, and explain what your
method can and cannot conclude.

Start by running the regression suite:

```bash
python3 -m unittest discover -s tests -v
```

Run a scenario from standard input:

```bash
python3 -m gatehouse.cli < examples/basic.json
```

The package uses only the Python standard library and supports Python 3.11+.

## Scenario format

A scenario contains initial service state followed by one or more operations:

```json
{
  "policies": [],
  "sessions": [],
  "operations": [
    {"op": "request", "request": {}},
    {"op": "batch", "atomic": true, "requests": []}
  ]
}
```

The CLI prints canonical JSON so outputs from two revisions can be compared.
Timestamps and identifiers are supplied by the scenario, making runs
deterministic.

## Useful commands

```bash
git log --oneline --decorate --reverse exercise/base..HEAD
git diff exercise/base exercise/change-01
git show exercise/change-03
python3 -m gatehouse.cli < your-scenario.json
```

Do not assume that a passing regression suite proves a change is correct.
