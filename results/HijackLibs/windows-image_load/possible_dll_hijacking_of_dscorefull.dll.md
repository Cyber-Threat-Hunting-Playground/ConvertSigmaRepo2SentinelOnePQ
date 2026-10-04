```sql
// Translated content (automatically translated on 04-10-2026 04:51:36):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dscorefull.dll" and (not module.path="c:\\programdata\\Microsoft\\Windows Defender\\Platform\\*\\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dscorefull.dll
id: 4675681b-5476-48a3-2908-5b9ff8905212
status: experimental
description: Detects possible DLL hijacking of dscorefull.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dscorefull.html
author: "Ivan CF"
date: 2026-09-18
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dscorefull.dll'
    filter:
        ImageLoaded:
            - 'c:\programdata\Microsoft\Windows Defender\Platform\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
