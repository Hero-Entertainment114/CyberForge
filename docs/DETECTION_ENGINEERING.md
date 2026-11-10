# Detection Engineering — v2.1.0 Official Stable

CyberForge Detection Engineering manages versioned, data-only rules against CyberForge normalized telemetry. It is designed for transparent, reviewable detections, not arbitrary code execution.

## Rule lifecycle

`draft → validate → test → publish → retire`

- **Draft:** create or revise a rule version.
- **Validate:** normalize the definition, check allowlisted fields/operators, bounded lengths, source and ATT&CK ID syntax.
- **Test:** evaluate a bounded set of recent normalized events without publishing or changing events.
- **Publish:** activate a validated version. By default, an operator different from the creator must publish it.
- **Retire:** stop future matches from the active rule.
- **Rollback:** create a new draft from a previously published version. Review, validate and publish that new version through the normal process.

Published versions remain active while a new revision is being drafted and tested. A failed draft does not replace the current active version.

## Supported rule format

Format identifier: `cyberforge.normalized-event-rule.v1`.

Example:

```json
{
  "title": "Wazuh SSH authentication alert",
  "description": "Detect a selected normalized Wazuh rule identifier.",
  "source": "wazuh",
  "severity": "high",
  "tags": ["authentication", "endpoint"],
  "attack_ids": ["T1110"],
  "match": {
    "all": [
      {"field": "source", "op": "equals", "value": "wazuh"},
      {"field": "rule_id", "op": "equals", "value": "5710"}
    ],
    "any": []
  }
}
```

A rule is bounded by 32 KiB, 20 total conditions, 25 values for an `in` condition and 256 characters per scalar value.

### Field allowlist

Top-level fields:

`source`, `observed_at`, `severity`, `category`, `title`, `host`, `node_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `process_name`, `rule_id`.

Selected `details.*` fields:

`details.event_type`, `details.signature_id`, `details.flow_id`, `details.protocol`, `details.vulnerability_id`, `details.package`, `details.finding_type`, `details.priority`, `details.target`, `details.uid`, `details.service`, `details.action`.

### Operators

- `equals`
- `not_equals`
- `contains`
- `starts_with`
- `in`

All conditions in `match.all` must match. If `match.any` is non-empty, at least one condition in that group must also match. Missing fields never match, including `not_equals`.

## RBAC and separation of duties

- `admin`: all detection permissions.
- `operator`: read, manage, publish.
- `analyst`: read and manage drafts/test rules, but cannot publish.
- `viewer`: read only.
- `sensor`: no detection access; only security telemetry ingestion.

`CF_DETECTION_REQUIRE_TWO_PERSON=1` is the default. The publisher must use a different API actor label/token identity from the draft creator. This is a separation-of-token-identities control, **not human identity verification**; an administrator able to create tokens can issue multiple labels. Keep it enabled for shared environments and combine it with your organization's identity provider/process.

## APIs

- `GET /api/v210/detection/overview`
- `GET /api/v210/detection/rules`
- `GET /api/v210/detection/rules/{id}`
- `GET /api/v210/detection/matches`
- `POST /api/v210/detection/rules`
- `POST /api/v210/detection/rules/{id}/draft`
- `POST /api/v210/detection/rules/{id}/validate`
- `POST /api/v210/detection/rules/{id}/test`
- `POST /api/v210/detection/rules/{id}/publish`
- `POST /api/v210/detection/rules/{id}/retire`
- `POST /api/v210/detection/rules/{id}/rollback`

The database records rule ID, version, creator, validator metadata, publisher, timestamps and event match references. Match uniqueness prevents duplicate `(rule, version, event)` records when the same normalized event is ingested again.

## Sigma compatibility

This subsystem is **not a Sigma parser** and does not claim that the CyberForge normalized-event format is directly portable to Sigma. `attack_ids` are analyst annotations whose syntax is checked; they do not prove that the ATT&CK behavior occurred. The release exposes `sigma_compatibility: not_claimed` explicitly.

## Operational guidance

1. Use an analyst token to create and test a draft.
2. Review the rule definition and sample matches.
3. Have a separate operator/admin publish it.
4. Monitor false positives through the Detection Matches page.
5. Create a new draft to change a published rule; use rollback only as a new draft, then validate/test/publish.
6. Back up the database before bulk rule import or large rule lifecycle changes.

Rules evaluate only CyberForge normalized events. They do not independently monitor the host, inspect raw PCAP, scan files, or execute external scanners.
