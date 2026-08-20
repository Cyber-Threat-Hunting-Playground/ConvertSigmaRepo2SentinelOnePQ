```sql
// Translated content (automatically translated on 20-08-2026 00:35:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "demo.controlr.app" or event.dns.request contains "demo.controlr.app"))
```


# Original Sigma Rule:
```yaml
title: Potential ControlR RMM Tool Network Activity
id: d5f41f3f-bca5-5e61-b06b-fd3793f47752
status: experimental
description: |
    Detects potential network activity of ControlR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: 'demo.controlr.app'
    condition: selection
falsepositives:
    - Legitimate use of ControlR
level: medium
```
