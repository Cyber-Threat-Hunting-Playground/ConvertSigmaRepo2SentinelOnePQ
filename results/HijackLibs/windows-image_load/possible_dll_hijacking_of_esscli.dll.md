```sql
// Translated content (automatically translated on 08-10-2026 05:04:48):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\esscli.dll" and (not module.path contains "c:\\windows\\system32\\wbem\\")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of esscli.dll
id: 5842141b-5476-48a3-2908-5b9ff8659418
status: experimental
description: Detects possible DLL hijacking of esscli.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/esscli.html
author: "Iván Cabrera"
date: 2026-09-18
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\esscli.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\wbem\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
