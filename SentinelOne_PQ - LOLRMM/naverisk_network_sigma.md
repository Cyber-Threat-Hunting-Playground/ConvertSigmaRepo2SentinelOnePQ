```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".naverisk.com" or url.address contains ".naverisk.com." or url.address="naverisk.com" or url.address="naverisk.com.") or (event.dns.request contains ".naverisk.com" or event.dns.request contains ".naverisk.com." or event.dns.request="naverisk.com" or event.dns.request="naverisk.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Naverisk RMM Tool Network Activity
id: d7052972-17c6-441e-aeb1-23a29bf9897f
status: experimental
description: |
    Detects potential network activity of Naverisk RMM tool
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
            - '*.naverisk.com'
            - '*.naverisk.com.'
            - 'naverisk.com'
            - 'naverisk.com.'
    condition: selection
falsepositives:
    - Legitimate use of Naverisk
level: medium
```
