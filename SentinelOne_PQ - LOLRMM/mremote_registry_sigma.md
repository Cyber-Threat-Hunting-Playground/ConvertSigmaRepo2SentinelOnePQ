```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MremoteAgent")
```


# Original Sigma Rule:
```yaml
title: Potential Mremote RMM Tool Registry Activity
id: 37dca935-dfa5-5475-970c-19bb3a60c453
status: experimental
description: |
    Detects potential registry activity of Mremote RMM tool
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
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services\MremoteAgent'
    condition: selection
falsepositives:
    - Legitimate use of Mremote
level: medium
```
