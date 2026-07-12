```sql
// Translated content (automatically translated on 12-07-2026 01:41:57):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".netviewer.com" or url.address contains "netviewer.com") or (event.dns.request contains ".netviewer.com" or event.dns.request contains "netviewer.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer (GoToMeet) RMM Tool Network Activity
id: fa883dea-2d61-5bae-8ed0-3f6a0b6f3a8b
status: experimental
description: |
    Detects potential network activity of Netviewer (GoToMeet) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.netviewer.com'
            - 'netviewer.com'
    condition: selection
falsepositives:
    - Legitimate use of Netviewer (GoToMeet)
level: medium
```
