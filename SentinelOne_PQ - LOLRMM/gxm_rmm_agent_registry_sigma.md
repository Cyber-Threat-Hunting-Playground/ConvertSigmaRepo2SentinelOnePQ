```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\GxMAgent")
```


# Original Sigma Rule:
```yaml
title: Potential GxM RMM Agent RMM Tool Registry Activity
id: 9c957529-a372-5848-a6bc-03c6714dac74
status: experimental
description: |
    Detects potential registry activity of GxM RMM Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services\GxMAgent'
    condition: selection
falsepositives:
    - Legitimate use of GxM RMM Agent
level: medium
```
