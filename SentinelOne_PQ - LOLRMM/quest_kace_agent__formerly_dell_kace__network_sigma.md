```sql
// Translated content (automatically translated on 04-07-2026 01:51:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".kace.com" or event.dns.request contains ".kace.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Quest KACE Agent (formerly Dell KACE) RMM Tool Network Activity
id: 81230670-0030-48a1-a02f-cba632fae825
status: experimental
description: |
    Detects potential network activity of Quest KACE Agent (formerly Dell KACE) RMM tool
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
        DestinationHostname|endswith: '*.kace.com'
    condition: selection
falsepositives:
    - Legitimate use of Quest KACE Agent (formerly Dell KACE)
level: medium
```
