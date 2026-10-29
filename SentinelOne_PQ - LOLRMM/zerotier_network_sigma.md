```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".zerotier.com" or url.address contains ".zerotier.com." or url.address="zerotier.com" or url.address="zerotier.com.") or (event.dns.request contains ".zerotier.com" or event.dns.request contains ".zerotier.com." or event.dns.request="zerotier.com" or event.dns.request="zerotier.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential ZeroTier RMM Tool Network Activity
id: 13a878f9-2674-401d-9b1b-f2028c440910
status: experimental
description: |
    Detects potential network activity of ZeroTier RMM tool
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
            - '*.zerotier.com'
            - '*.zerotier.com.'
            - 'zerotier.com'
            - 'zerotier.com.'
    condition: selection
falsepositives:
    - Legitimate use of ZeroTier
level: medium
```
