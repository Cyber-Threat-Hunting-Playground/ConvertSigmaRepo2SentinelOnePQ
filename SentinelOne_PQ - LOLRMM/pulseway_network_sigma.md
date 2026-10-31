```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".pulseway.com" or url.address contains ".pulseway.com." or url.address="pulseway.com" or url.address="pulseway.com.") or (event.dns.request contains ".pulseway.com" or event.dns.request contains ".pulseway.com." or event.dns.request="pulseway.com" or event.dns.request="pulseway.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Pulseway RMM Tool Network Activity
id: 7fcd5e3b-db33-4acc-b432-de03c31105b5
status: experimental
description: |
    Detects potential network activity of Pulseway RMM tool
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
            - '*.pulseway.com'
            - '*.pulseway.com.'
            - 'pulseway.com'
            - 'pulseway.com.'
    condition: selection
falsepositives:
    - Legitimate use of Pulseway
level: medium
```
