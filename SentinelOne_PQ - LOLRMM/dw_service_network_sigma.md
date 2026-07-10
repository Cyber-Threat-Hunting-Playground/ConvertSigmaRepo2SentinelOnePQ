```sql
// Translated content (automatically translated on 10-07-2026 01:50:42):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".dwservice.net" or event.dns.request contains ".dwservice.net"))
```


# Original Sigma Rule:
```yaml
title: Potential DW Service RMM Tool Network Activity
id: ac97424e-1da4-4940-9535-19a8d20c992a
status: experimental
description: |
    Detects potential network activity of DW Service RMM tool
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
        DestinationHostname|endswith: '*.dwservice.net'
    condition: selection
falsepositives:
    - Legitimate use of DW Service
level: medium
```
