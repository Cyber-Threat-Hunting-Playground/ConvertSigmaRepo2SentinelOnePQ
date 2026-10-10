```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RustDesk" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\RustDesk"))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool Registry Activity
id: 8e3d6649-5228-588b-9979-f837b8e3e286
status: experimental
description: |
    Detects potential registry activity of RustDesk RMM tool
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
            - 'HKLM\SYSTEM\CurrentControlSet\Services\RustDesk'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RustDesk'
    condition: selection
falsepositives:
    - Legitimate use of RustDesk
level: medium
```
