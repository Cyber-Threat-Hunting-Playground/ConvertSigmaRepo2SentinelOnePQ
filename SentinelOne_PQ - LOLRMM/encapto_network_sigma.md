```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".encapto.com" or url.address contains ".encapto.com." or url.address="encapto.com" or url.address="encapto.com.") or (event.dns.request contains ".encapto.com" or event.dns.request contains ".encapto.com." or event.dns.request="encapto.com" or event.dns.request="encapto.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Encapto RMM Tool Network Activity
id: e4ebc834-c565-481c-9738-403e98cf56ff
status: experimental
description: |
    Detects potential network activity of Encapto RMM tool
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
            - '*.encapto.com'
            - '*.encapto.com.'
            - 'encapto.com'
            - 'encapto.com.'
    condition: selection
falsepositives:
    - Legitimate use of Encapto
level: medium
```
