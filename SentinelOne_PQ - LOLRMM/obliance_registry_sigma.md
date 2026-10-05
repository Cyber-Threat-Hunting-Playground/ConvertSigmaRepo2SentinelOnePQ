```sql
// Translated content (automatically translated on 05-10-2026 02:53:59):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\OblianceAgent" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OblianceTray" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\OblianceAgent" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\OblianceAgent"))
```


# Original Sigma Rule:
```yaml
title: Potential Obliance RMM Tool Registry Activity
id: 99ef5b94-139b-5625-8511-598ebd7cb9ca
status: experimental
description: |
    Detects potential registry activity of Obliance RMM tool
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
        TargetObject|contains:
            - 'HKLM\SOFTWARE\OblianceAgent'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OblianceTray'
            - 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\OblianceAgent'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\OblianceAgent'
    condition: selection
falsepositives:
    - Legitimate use of Obliance
level: medium
```
