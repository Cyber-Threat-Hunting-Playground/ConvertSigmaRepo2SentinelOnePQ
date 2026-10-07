```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\netmaster")
```


# Original Sigma Rule:
```yaml
title: Potential NetMaster RMM Tool Registry Activity
id: 116a7c25-8544-5989-8361-b9dc9793aac9
status: experimental
description: |
    Detects potential registry activity of NetMaster RMM tool
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
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services\netmaster'
    condition: selection
falsepositives:
    - Legitimate use of NetMaster
level: medium
```
