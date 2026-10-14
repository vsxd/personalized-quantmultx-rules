# Third-party reference sources

This repository maintains its own Quantumult X rules, service boundaries, policy choices, tests and releases. External inputs are evidence for selective review; they never automatically overwrite the published corpus. A source appearing in `upstream-lock.json` means its selected reference inputs are pinned, not that its complete classification was adopted.

## Derived rule material

| Source | Immutable reference | License and use |
| --- | --- | --- |
| [sve1r/Rules-For-Quantumult-X](https://github.com/sve1r/Rules-For-Quantumult-X) | `8061d2ebe160280f25d4b20d6d929d9e03caecbe`, `develop` | MIT. Historical domain material remains after corrections, narrowing and independent category changes. Original notice: [sve1r-MIT.txt](LICENSES/sve1r-MIT.txt). |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | `c6adacf29cc4fb05e04651fcf03e00989ef9f797`, `master` | MIT. Selected explicit service domains are used after ownership, overlap and shared-infrastructure review. Original notice: [v2fly-MIT.txt](LICENSES/v2fly-MIT.txt). Includes, attributes and regular expressions are reference evidence, never automatically expanded into the local rules. |

The sve1r README contains additional non-commercial wording but expressly states that its LICENSE controls; the retained LICENSE is the original standard MIT text. Local maintenance does not remove attribution obligations. [docs/corpus-review.json](docs/corpus-review.json) records this revision's corpus decisions; historical first-pass audit material is under `docs/history/2026-10-14-first-pass/` and does not describe the current published layout.

HSBC, OpenAI, OpenAI shared dependencies and Claude also use documented official service sources and independently scoped tenant-specific endpoints. Their headers and coverage evidence identify those sources. Third-party shared dependencies are distinguished from first-party ownership.

## Compared but not imported

| Source | Scope and design evidence | License evidence |
| --- | --- | --- |
| [ppmina/Quantumult_X-rules](https://github.com/ppmina/Quantumult_X-rules) | Selected generated direct/proxy/reject, Apple/iCloud and Telegram IP files from `release`; generator and license from `master`. Broad bundles conflict with service-specific exceptions and are not additive imports. | GPL-3.0; [retained reference license](LICENSES/ppmina-GPL-3.0-reference.txt). |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | Selected **Quantumult X and Surge** service files for AI, platforms, messaging, games and media. Useful for missing endpoints and per-service organization; broad keywords, shared suffixes and historical IPs are not accepted merely because this source contains them. | GPL-2.0; [retained reference license](LICENSES/blackmatrix7-GPL-2.0-reference.txt). |
| [SukkaW/Surge](https://github.com/SukkaW/Surge) | Separate `Source/domainset`, `Source/non_ip` and `Source/ip` structure, selected AI/platform/region/CDN/game-download lists. Domainset exact versus suffix meaning is preserved in comparisons. | AGPL-3.0; [retained reference license](LICENSES/SukkaW-AGPL-3.0-reference.txt). |
| [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) | Selected platform, AI, messaging, developer and China lists; service taxonomy and omissions are compared using their native rule syntax. | CC-BY-SA-4.0 declaration in the pinned README footer, linked to the [license deed](https://creativecommons.org/licenses/by-sa/4.0/). The complete README hash is locked as the license evidence; no separate LICENSE file is invented. |
| [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) | Actual generated `release` DOMAIN-SET and RULE-SET files, plus explicit CIDR references. `master` holds generator/documentation/license, not those generated outputs. Large regional bundles remain comparative evidence. | GPL-3.0; [retained reference license](LICENSES/Loyalsoldier-GPL-3.0-reference.txt). |

No generated file from these five sources is copied into the published rule lists. Their names, taxonomy and candidate endpoints can guide independent verification, but a future derivative import needs its own provenance and license analysis. Retaining a reference license is not a claim that the imported MIT-derived corpus is licensed under that reference's license.

## Offline domain-boundary data

[Public Suffix List](https://publicsuffix.org/) ICANN and PRIVATE sections are included unchanged under **MPL-2.0**, solely to validate public/tenant domain boundaries. The original data header and [complete license](LICENSES/publicsuffix-MPL-2.0.txt) are retained. The IANA root-zone TLD file is a factual delegation snapshot. [data/domain-boundaries/README.md](data/domain-boundaries/README.md) and `snapshot.json` record immutable PSL provenance, download dates and byte hashes. These validator inputs are not routing rules and do not establish service ownership.

## Reproducible comparison and adoption boundaries

[upstream-lock.json](upstream-lock.json) records full reference commits, source/rule/license branches, original file SHA-256 hashes, native formats and discovery subtrees. Baseline hashes describe **external input bytes**, not local output. New service files are detected through Git tree comparisons; v2fly's full reachable include dependency graph is inventoried, including filtered includes, without producing QX rules.

The checker preserves unresolved differences instead of advancing baselines. New or missing domains require official evidence or explicit scope review; a larger upstream list is not evidence of better routing. Shared CDN/cloud suffixes, country-wide TLD catchalls, User-Agent heuristics and stale service IP ranges remain unsuitable default imports. Necessary IP routing requires a separate current authoritative source and review date. See [the maintenance guide](docs/agent-update-guide.md).

## Second line review, 2026-10-14

The same immutable MIT revision of v2fly additionally supplies reviewed LINE, Docker, Python, npm and Notion reference facts; those five files are now explicit update-check inputs. Minecraft and exact media tenant scopes use documented files within the existing immutable include inventory. No source revision was advanced, and no compared GPL/AGPL/CC-BY-SA collection was bulk imported. Official service documents supply the other fresh endpoint facts. Per-file scope, hashes, exact changes and limitations are recorded in [docs/deep-review-2026-10-14.json](docs/deep-review-2026-10-14.json); existing notices remain in every derived leaf and generated bundle.
