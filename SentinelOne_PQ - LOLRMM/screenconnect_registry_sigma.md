```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath="*HKLM\\System\\CurrentControlSet\\Services\\ScreenConnect Client (*)\\ImagePath*" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages" or registry.keyPath contains "HKLM\\SOFTWARE\\Classes\\CLSID\\{6FF59A85-BC37-4CD4-C175-070CC4814204}" or registry.keyPath="*HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect Client (*)*"))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Registry Activity
id: a1b2217d-8ce8-5ce7-bf40-d41f9a365180
status: experimental
description: |
    Detects potential registry activity of ScreenConnect RMM tool
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
            - 'HKLM\System\CurrentControlSet\Services\ScreenConnect Client (*)\ImagePath'
            - 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages'
            - 'HKLM\SOFTWARE\Classes\CLSID\{6FF59A85-BC37-4CD4-C175-070CC4814204}'
            - 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (*)'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: medium
```
