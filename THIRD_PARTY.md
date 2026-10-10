# Third-party sources

This repository mirrors a reviewed subset of `sve1r/Rules-For-Quantumult-X` under `Rules/`.

- Source: https://github.com/sve1r/Rules-For-Quantumult-X
- Source commit: `8061d2ebe160280f25d4b20d6d929d9e03caecbe` (the `develop` revision used for the mirror)
- License: MIT, Copyright (c) 2020 SVE1R
- Mirrored paths: `Rules/Services/`, `Rules/Services/SNS/`, `Rules/Games/`, `Rules/Media/`, and `Rules/Region/`

The OpenAI, Claude, and HSBC lists are maintained in this repository as personal, reviewed lists. They are not copied from the upstream repositories.

`ppmina/Quantumult_X-rules` was reviewed but its generated broad `direct`/`proxy` sets are intentionally not copied here. Adding them beside the existing region and global sets would create overlap that is difficult to audit and would not fix service-specific routing.
