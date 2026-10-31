```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".todesk.com" or url.address contains ".todesk.com." or url.address="todesk.com" or url.address="todesk.com.") or (event.dns.request contains ".todesk.com" or event.dns.request contains ".todesk.com." or event.dns.request="todesk.com" or event.dns.request="todesk.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential ToDesk RMM Tool Network Activity
id: 8c9c2180-ab76-47b7-a82a-1c64c451c851
status: experimental
description: |
    Detects potential network activity of ToDesk RMM tool
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
            - '*.todesk.com'
            - '*.todesk.com.'
            - 'todesk.com'
            - 'todesk.com.'
    condition: selection
falsepositives:
    - Legitimate use of ToDesk
level: medium
```
