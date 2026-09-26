```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\Allocentra\\Agent" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AllocentraAgent"))
```


# Original Sigma Rule:
```yaml
title: Potential Allocentra RMM Tool Registry Activity
id: cb6f9833-269d-5455-bdb7-dacdf993d530
status: experimental
description: |
    Detects potential registry activity of Allocentra RMM tool
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
        TargetObject|contains:
            - 'HKLM\SOFTWARE\Allocentra\Agent'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\AllocentraAgent'
    condition: selection
falsepositives:
    - Legitimate use of Allocentra
level: medium
```
