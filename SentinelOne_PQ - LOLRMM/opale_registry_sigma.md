```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Opale-Agent")
```


# Original Sigma Rule:
```yaml
title: Potential Opale RMM Tool Registry Activity
id: 00cf7da0-fa7b-5d2a-b320-4e9944488b9f
status: experimental
description: |
    Detects potential registry activity of Opale RMM tool
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
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services\Opale-Agent'
    condition: selection
falsepositives:
    - Legitimate use of Opale
level: medium
```
