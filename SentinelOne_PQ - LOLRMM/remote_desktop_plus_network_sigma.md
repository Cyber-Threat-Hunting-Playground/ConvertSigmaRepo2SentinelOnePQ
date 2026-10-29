```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".donkz.nl" or url.address contains ".donkz.nl." or url.address="donkz.nl" or url.address="donkz.nl.") or (event.dns.request contains ".donkz.nl" or event.dns.request contains ".donkz.nl." or event.dns.request="donkz.nl" or event.dns.request="donkz.nl.")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Desktop Plus RMM Tool Network Activity
id: 97b1200b-aaa8-4202-b99c-778ae2b6daba
status: experimental
description: |
    Detects potential network activity of Remote Desktop Plus RMM tool
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
            - '*.donkz.nl'
            - '*.donkz.nl.'
            - 'donkz.nl'
            - 'donkz.nl.'
    condition: selection
falsepositives:
    - Legitimate use of Remote Desktop Plus
level: medium
```
