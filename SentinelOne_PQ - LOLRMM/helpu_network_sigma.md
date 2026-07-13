```sql
// Translated content (automatically translated on 13-07-2026 01:46:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "helpu.co.kr" or url.address contains ".helpu.co.kr") or (event.dns.request contains "helpu.co.kr" or event.dns.request contains ".helpu.co.kr")))
```


# Original Sigma Rule:
```yaml
title: Potential HelpU RMM Tool Network Activity
id: 85125665-6aba-478b-8d22-614dbfd48625
status: experimental
description: |
    Detects potential network activity of HelpU RMM tool
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
            - 'helpu.co.kr'
            - '*.helpu.co.kr'
    condition: selection
falsepositives:
    - Legitimate use of HelpU
level: medium
```
