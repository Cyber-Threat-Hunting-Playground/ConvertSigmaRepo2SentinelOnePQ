```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".mygreenpc.com" or url.address contains ".mygreenpc.com." or url.address="mygreenpc.com" or url.address="mygreenpc.com.") or (event.dns.request contains ".mygreenpc.com" or event.dns.request contains ".mygreenpc.com." or event.dns.request="mygreenpc.com" or event.dns.request="mygreenpc.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential MyGreenPC RMM Tool Network Activity
id: 4a0e9fb7-f29b-42bc-922b-c0ca30a4550b
status: experimental
description: |
    Detects potential network activity of MyGreenPC RMM tool
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
            - '*.mygreenpc.com'
            - '*.mygreenpc.com.'
            - 'mygreenpc.com'
            - 'mygreenpc.com.'
    condition: selection
falsepositives:
    - Legitimate use of MyGreenPC
level: medium
```
