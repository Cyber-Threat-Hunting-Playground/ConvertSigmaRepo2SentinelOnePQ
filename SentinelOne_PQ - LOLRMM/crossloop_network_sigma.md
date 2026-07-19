```sql
// Translated content (automatically translated on 19-07-2026 01:28:51):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".crossloop.com" or url.address contains "crossloop.en.softonic.com") or (event.dns.request contains ".crossloop.com" or event.dns.request contains "crossloop.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential CrossLoop RMM Tool Network Activity
id: 40f7000c-d0eb-45a0-9203-f6db301528de
status: experimental
description: |
    Detects potential network activity of CrossLoop RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.crossloop.com'
            - 'crossloop.en.softonic.com'
    condition: selection
falsepositives:
    - Legitimate use of CrossLoop
level: medium
```
