```sql
// Translated content (automatically translated on 30-06-2026 02:11:43):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".heartbeatrm.com" or url.address contains "heartbeatrm.com") or (event.dns.request contains ".heartbeatrm.com" or event.dns.request contains "heartbeatrm.com")))
```


# Original Sigma Rule:
```yaml
title: Potential HeartbeatRM RMM Tool Network Activity
id: 6bf78314-f722-50d4-9a80-b0537b72dd9d
status: experimental
description: |
    Detects potential network activity of HeartbeatRM RMM tool
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
            - '*.heartbeatrm.com'
            - 'heartbeatrm.com'
    condition: selection
falsepositives:
    - Legitimate use of HeartbeatRM
level: medium
```
