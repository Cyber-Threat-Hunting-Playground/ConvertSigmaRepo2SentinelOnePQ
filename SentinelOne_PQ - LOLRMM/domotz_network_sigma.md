```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".cell-1.domotz.com" or url.address contains ".cell-1.domotz.com." or url.address contains ".domotz.co" or url.address contains ".domotz.co." or url.address contains ".domotz.com" or url.address contains ".domotz.com." or url.address="cell-1.domotz.com" or url.address="cell-1.domotz.com." or url.address="domotz.com" or url.address="domotz.com.") or (event.dns.request contains ".cell-1.domotz.com" or event.dns.request contains ".cell-1.domotz.com." or event.dns.request contains ".domotz.co" or event.dns.request contains ".domotz.co." or event.dns.request contains ".domotz.com" or event.dns.request contains ".domotz.com." or event.dns.request="cell-1.domotz.com" or event.dns.request="cell-1.domotz.com." or event.dns.request="domotz.com" or event.dns.request="domotz.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Domotz RMM Tool Network Activity
id: 441ff6b0-0c7d-4378-9b90-11bcb0959a73
status: experimental
description: |
    Detects potential network activity of Domotz RMM tool
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
            - '*.cell-1.domotz.com'
            - '*.cell-1.domotz.com.'
            - '*.domotz.co'
            - '*.domotz.co.'
            - '*.domotz.com'
            - '*.domotz.com.'
            - 'cell-1.domotz.com'
            - 'cell-1.domotz.com.'
            - 'domotz.com'
            - 'domotz.com.'
    condition: selection
falsepositives:
    - Legitimate use of Domotz
level: medium
```
