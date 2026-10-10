# personalized-quantmultx-rules

Quantumult X rules for personal use. The `master` branch is the published branch referenced by the configuration below.

## Core lists

- `OpenAI.list` — ChatGPT, Codex, Sora, OpenAI API and the current official third-party dependencies.
- `Claude.list` — Claude and Anthropic services.
- `HSBC.list` — HSBC and PayMe domains.

## Mirrored general lists

The `Rules/` directory contains a reviewed copy of the general service, media, region and game lists used by the companion configuration. Each mirrored file records the upstream commit and license in its header; provenance is also recorded in [THIRD_PARTY.md](THIRD_PARTY.md).

The mirror deliberately does not include unlock scripts or rewrite scripts. Those scripts can change application responses and require separate, app-specific validation.

## Quantumult X usage

Use raw URLs from the `master` branch in `[filter_remote]`:

```ini
https://raw.githubusercontent.com/vsxd/personalized-quantmultx-rules/master/OpenAI.list, tag=OpenAI, force-policy=OpenAI, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/vsxd/personalized-quantmultx-rules/master/HSBC.list, tag=HSBC, force-policy=HSBC, update-interval=172800, opt-parser=false, enabled=true
```

Keep the service-specific lists before broad `Global`, media and region lists. In Quantumult X, `force-policy` binds every rule in the remote resource to the named policy; it does not make the policy permanently direct. If the policy group is changed to a proxy candidate, the matching traffic follows that candidate.

A `direct` service rule covers only the host/IP request that matches the list. App login, telemetry, challenge, CDN, WebSocket and voice endpoints can be separate connections, so the OpenAI list includes the official non-OpenAI dependencies where they are known. ChatGPT Voice also uses dynamic UDP/3478 addresses and cannot be fully covered by a static hostname list.

## Validation

Run the local syntax/lint check before publishing:

```sh
python3 scripts/validate_rules.py
```

The check catches unsupported rule types, missing fields and invalid CIDRs. It does not prove that a provider endpoint is reachable or that a policy group contains a live node; mirrored upstream files may intentionally contain duplicate entries.

## Upstream choice

`ppmina/Quantumult_X-rules` remains a useful optional source for broad generated `direct`/`proxy`/`reject` sets, but it is not merged into this repository because the current configuration already has region/global sets and service-specific overrides. `sve1r/Rules-For-Quantumult-X` is mirrored selectively for the lists actually used here. This keeps the final match set inspectable and avoids importing unrelated scripts.
