```sql
// Translated content (automatically translated on 05-10-2026 04:39:29):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\ceiinfolog.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ceiinfolog.dll
id: 2847261b-3801-48a3-5206-5b9ff8544728
status: experimental
description: Detects possible DLL hijacking of ceiinfolog.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/canon/ceiinfolog.html
author: "Liran Ravich"
date: 2026-10-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ceiinfolog.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
