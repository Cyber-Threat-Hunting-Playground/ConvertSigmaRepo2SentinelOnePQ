```sql
// Translated content (automatically translated on 28-10-2026 02:56:19):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\NSecsoft\\Debug" or registry.keyPath contains "HKLM\\SOFTWARE\\NSecsoft\\NSecAgent" or registry.keyPath contains "HKLM\\SOFTWARE\\WOW6432Node\\NSecsoft\\NSecAgent"))
```


# Original Sigma Rule:
```yaml
title: Potential Ping32 RMM Tool Registry Activity
id: 58f4f810-6362-5452-89b2-a2c2871f23d2
status: experimental
description: |
    Detects potential registry activity of Ping32 RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-19
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'HKLM\SOFTWARE\NSecsoft\Debug'
            - 'HKLM\SOFTWARE\NSecsoft\NSecAgent'
            - 'HKLM\SOFTWARE\WOW6432Node\NSecsoft\NSecAgent'
    condition: selection
falsepositives:
    - Legitimate use of Ping32
level: medium
```
