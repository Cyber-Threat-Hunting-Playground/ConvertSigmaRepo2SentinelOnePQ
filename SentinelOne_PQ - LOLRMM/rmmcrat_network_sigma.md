```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".softbymade.top" or url.address contains ".softbymade.top." or url.address="softbymade.top" or url.address="softbymade.top.") or (event.dns.request contains ".softbymade.top" or event.dns.request contains ".softbymade.top." or event.dns.request="softbymade.top" or event.dns.request="softbymade.top.")))
```


# Original Sigma Rule:
```yaml
title: Potential RMMCRAT RMM Tool Network Activity
id: b1ef1490-6fd4-5f3e-9ff5-6f92a8d0b1a7
status: experimental
description: |
    Detects potential network activity of RMMCRAT RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
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
            - '*.softbymade.top'
            - '*.softbymade.top.'
            - 'softbymade.top'
            - 'softbymade.top.'
    condition: selection
falsepositives:
    - Legitimate use of RMMCRAT
level: medium
```
