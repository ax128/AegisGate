## Summary

- What changed?
- Why is this change needed?
- Is this behavior change intentional?

## Scope

- Affected modules:
- Affected routes/endpoints:
- Affected tenants/sessions/confirmation flow:

## Security Impact

- [ ] No security-impacting change
- [ ] Security-impacting change (describe below)

### Security details

- New/updated detection signals:
- New/updated block/review/sanitize actions:
- Policy defaults changed:
- Potential false-positive/false-negative impact:

## Confirmation Flow Changes

- [ ] No confirmation flow change
- [ ] Confirmation flow changed

If changed, provide:

- Confirmation message format changes:
- `confirm_id` matching rule changes:
- `action_token`/action-binding changes:
- Pending/executing timeout/recovery changes:
- Cross-session/tenant isolation changes:

## RAG and Poisoning Controls

- [ ] Not related to RAG/poisoning
- [ ] RAG/poisoning logic changed

If changed, provide:

- Ingestion-stage controls:
- Retrieval-stage controls:
- Poison propagation handling:
- Traceback/audit fields added or changed:

## Config and Compatibility

- New env vars:
- Updated defaults:
- Backward compatibility impact:
- Migration steps (if any):

## Testing

### Targeted tests

- Commands run:
- Result:

### Full test suite

- Command run:
- Result:
- Known unrelated failures (if any):

## Observability

- [ ] Logs updated for key decisions/errors
- [ ] Audit event fields updated
- [ ] Metrics/dashboards/alerts impact reviewed

Details:

- New/changed log keys:
- New/changed audit keys:

## Rollback Plan

- How to rollback quickly:
- What data/state may need cleanup:

## Release Notes (copy-ready)

```text
<short user-facing release note>
```

