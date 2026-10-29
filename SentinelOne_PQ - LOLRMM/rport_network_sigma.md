```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rport.io" or url.address contains ".rport.io." or url.address="rport.io" or url.address="rport.io.") or (event.dns.request contains ".rport.io" or event.dns.request contains ".rport.io." or event.dns.request="rport.io" or event.dns.request="rport.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential RPort RMM Tool Network Activity
id: b958832e-79f5-406d-832a-d3da5ea9163a
status: experimental
description: |
    Detects potential network activity of RPort RMM tool
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
            - '*.rport.io'
            - '*.rport.io.'
            - 'rport.io'
            - 'rport.io.'
    condition: selection
falsepositives:
    - Legitimate use of RPort
level: medium
```
