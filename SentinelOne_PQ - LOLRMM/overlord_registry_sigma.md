```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OverlordAgent-" or registry.keyPath contains "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OverlordAgent"))
```


# Original Sigma Rule:
```yaml
title: Potential Overlord RMM Tool Registry Activity
id: 8eec3aff-7e17-546a-b25e-ce377c17b54d
status: experimental
description: |
    Detects potential registry activity of Overlord RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OverlordAgent-*'
            - 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OverlordAgent'
    condition: selection
falsepositives:
    - Legitimate use of Overlord
level: medium
```
