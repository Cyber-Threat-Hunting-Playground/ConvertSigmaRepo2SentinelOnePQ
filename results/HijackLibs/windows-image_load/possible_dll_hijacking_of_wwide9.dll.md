```sql
// Translated content (automatically translated on 30-10-2026 04:51:08):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\wwide9.dll" and (not (module.path="c:\\program files\\IBM\\SPSS\\Statistics\\*\\*" or module.path="c:\\program files (x86)\\IBM\\SPSS\\Statistics\\*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wwide9.dll
id: 3190461b-5716-48a3-7286-5b9ff8368962
status: experimental
description: Detects possible DLL hijacking of wwide9.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/ibm/wwide9.html
author: "Jose Enrique Hernandez"
date: 2026-10-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wwide9.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\IBM\SPSS\Statistics\\*\\*'
            - 'c:\program files (x86)\IBM\SPSS\Statistics\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
