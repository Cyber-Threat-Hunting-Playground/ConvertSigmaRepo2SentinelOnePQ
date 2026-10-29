```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".pcvisit.de" or url.address contains ".pcvisit.de." or url.address="pcvisit.de" or url.address="pcvisit.de.") or (event.dns.request contains ".pcvisit.de" or event.dns.request contains ".pcvisit.de." or event.dns.request="pcvisit.de" or event.dns.request="pcvisit.de.")))
```


# Original Sigma Rule:
```yaml
title: Potential Pcvisit RMM Tool Network Activity
id: e6f75735-db2c-4b13-8b60-1b103989925a
status: experimental
description: |
    Detects potential network activity of Pcvisit RMM tool
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
            - '*.pcvisit.de'
            - '*.pcvisit.de.'
            - 'pcvisit.de'
            - 'pcvisit.de.'
    condition: selection
falsepositives:
    - Legitimate use of Pcvisit
level: medium
```
