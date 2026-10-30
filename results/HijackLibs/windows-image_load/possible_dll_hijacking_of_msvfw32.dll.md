```sql
// Translated content (automatically translated on 30-10-2026 04:51:08):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\msvfw32.dll" and (not (module.path contains "c:\\windows\\syswow64\\" or module.path contains "c:\\windows\\system32\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msvfw32.dll
id: 6616391b-5812-48a3-7097-5b9ff8750140
status: experimental
description: Detects possible DLL hijacking of msvfw32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msvfw32.html
author: "Tim Sword - HuntressLabs"
date: 2026-10-23
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msvfw32.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\syswow64\\*'
            - 'c:\windows\system32\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
