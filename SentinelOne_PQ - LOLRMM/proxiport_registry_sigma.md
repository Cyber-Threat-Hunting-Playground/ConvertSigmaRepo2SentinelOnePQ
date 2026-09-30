```sql
// Translated content (automatically translated on 30-09-2026 02:52:21):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\proxiport")
```


# Original Sigma Rule:
```yaml
title: Potential ProxiPort RMM Tool Registry Activity
id: f5dd4b31-3d31-57ce-90ad-886f628aa843
status: experimental
description: |
    Detects potential registry activity of ProxiPort RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-29
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services\proxiport'
    condition: selection
falsepositives:
    - Legitimate use of ProxiPort
level: medium
```
