```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".internetid.ru" or url.address contains ".internetid.ru.") or (event.dns.request contains ".internetid.ru" or event.dns.request contains ".internetid.ru.")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Utilities RMM Tool Network Activity
id: 568aba5a-6ff8-4af5-8e07-6397a91dae8e
status: experimental
description: |
    Detects potential network activity of Remote Utilities RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname:
            - '*.internetid.ru'
            - '*.internetid.ru.'
    condition: selection
falsepositives:
    - Legitimate use of Remote Utilities
level: medium
```
