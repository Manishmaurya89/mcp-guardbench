## What this changes and why



## Checklist

- [ ] `make check` passes locally (lint + typecheck + tests)
- [ ] `make test-postgres` passes, if this touches the database layer
- [ ] New behavior has new tests (this project does not accept "tested locally, trust me" for
      anything touching detection, prevention, redaction, or input validation)
- [ ] Docs updated in the same PR if this changes a metric definition, a policy rule, an API route,
      a CLI command, or a documented limitation
- [ ] If this touches fixtures, adapters, or anything that could reach outside the local lab: I've
      read [SECURITY.md](../SECURITY.md) and this stays inside the local-fixture safety boundary

## Anything reviewers should look at closely

