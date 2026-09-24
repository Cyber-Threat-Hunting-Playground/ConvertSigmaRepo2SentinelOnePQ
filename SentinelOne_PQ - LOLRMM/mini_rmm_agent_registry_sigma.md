```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MiniRMMAgent" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MiniRmmAgent"))
```


# Original Sigma Rule:
```yaml
title: Potential Mini RMM Agent RMM Tool Registry Activity
id: 038409f9-5157-5bb7-be9e-e378a89ebc28
status: experimental
description: |
    Detects potential registry activity of Mini RMM Agent RMM tool
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
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MiniRMMAgent'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\MiniRmmAgent'
    condition: selection
falsepositives:
    - Legitimate use of Mini RMM Agent
level: medium
```
