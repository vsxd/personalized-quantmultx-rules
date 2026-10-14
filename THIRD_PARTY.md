# Third-party reference sources

This is an independently maintained personal Quantumult X rules repository. External sources are reviewed references for coverage and corrections. Local category ownership, routing policies, repairs, exclusions, tests, and releases are maintained here; an upstream update never automatically overwrites the published lists.

## sve1r reference baseline

- Repository: https://github.com/sve1r/Rules-For-Quantumult-X
- Historical reference commit: `8061d2ebe160280f25d4b20d6d929d9e03caecbe` (`develop`)
- License: MIT, Copyright (c) 2020 SVE1R
- Full original license: [`LICENSES/sve1r-MIT.txt`](LICENSES/sve1r-MIT.txt)
- Referenced areas: general Apple, Microsoft, Google, Discord, games, media, and region coverage.

These locally maintained lists include material derived from that baseline, with documented repairs and category changes. Attribution is preserved despite local maintenance. `docs/category-partition.json` records category ownership changes; `docs/quarantine.json` records excluded broad or faulty rules. The upstream standalone Bilibili list was the reference for repairing damaged aggregate domains.

The sve1r README contains additional non-commercial wording but expressly states that its LICENSE controls; the retained LICENSE is the original standard MIT text.

## ppmina evaluated reference

`ppmina/Quantumult_X-rules` is evaluated for coverage comparison. Its source repository declares GPL-3.0. No generated ppmina rule file is currently copied into this repository. Its broad direct/proxy/reject sets overlap one another and conflict with service-specific direct exceptions, so they are not imported as additive bundles. Future selected imports require explicit provenance and retention of their applicable license; they must not be mislabeled as MIT-derived content.

## Reproducible provenance

[`upstream-lock.json`](upstream-lock.json) records immutable reference commits, exact input URLs, and SHA-256 hashes. Those hashes identify historical upstream input bytes, not the locally maintained published output. The source references can support reviewed diffs, but do not authorize automatic synchronization.

HSBC, OpenAI, shared OpenAI dependencies, and Claude service lists are maintained separately using their documented service sources and local scope decisions.
