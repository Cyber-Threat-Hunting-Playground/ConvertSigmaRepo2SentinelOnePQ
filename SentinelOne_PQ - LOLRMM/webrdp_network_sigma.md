```sql
// Translated content (automatically translated on 28-06-2026 02:27:59):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential WebRDP RMM Tool Network Activity
id: d6cf8756-43e2-4fa0-adfa-31a51dbf7602
status: experimental
description: |
    Detects potential network activity of WebRDP RMM tool
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
        DestinationHostname|endswith: 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of WebRDP
level: medium
```
