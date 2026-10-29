```sql
// Translated content (automatically translated on 29-10-2026 04:51:26):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\blkscrdl.dll" and (not module.path="c:\\windows\\system32\\rserver*\\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of blkscrdl.dll
id: 9657001b-9354-48a3-1039-5b9ff8867836
status: experimental
description: Detects possible DLL hijacking of blkscrdl.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/famatech/blkscrdl.html
author: "Jose Enrique Hernandez"
date: 2026-10-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\blkscrdl.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\rserver*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
