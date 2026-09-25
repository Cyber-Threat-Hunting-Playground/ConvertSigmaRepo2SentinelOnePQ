```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\RG Systemes\\RG Supervision" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\RG Systemes\\RG Supervision" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RG-Supervision"))
```


# Original Sigma Rule:
```yaml
title: Potential RG System (RG Supervision) RMM Tool Registry Activity
id: b947e352-2dee-5ea0-9b98-875e04c0388c
status: experimental
description: |
    Detects potential registry activity of RG System (RG Supervision) RMM tool
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
            - 'HKLM\SOFTWARE\RG Systemes\RG Supervision'
            - 'HKLM\SOFTWARE\WOW6432Node\RG Systemes\RG Supervision'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\RG-Supervision'
    condition: selection
falsepositives:
    - Legitimate use of RG System (RG Supervision)
level: medium
```
