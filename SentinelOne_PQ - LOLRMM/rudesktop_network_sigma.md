```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rudesktop.ru" or url.address contains ".rudesktop.ru." or url.address="rudesktop.ru" or url.address="rudesktop.ru.") or (event.dns.request contains ".rudesktop.ru" or event.dns.request contains ".rudesktop.ru." or event.dns.request="rudesktop.ru" or event.dns.request="rudesktop.ru.")))
```


# Original Sigma Rule:
```yaml
title: Potential RuDesktop RMM Tool Network Activity
id: bb51a404-4a69-4faf-a41d-644740ef3cae
status: experimental
description: |
    Detects potential network activity of RuDesktop RMM tool
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
            - '*.rudesktop.ru'
            - '*.rudesktop.ru.'
            - 'rudesktop.ru'
            - 'rudesktop.ru.'
    condition: selection
falsepositives:
    - Legitimate use of RuDesktop
level: medium
```
