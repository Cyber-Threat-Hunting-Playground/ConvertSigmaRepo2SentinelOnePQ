```sql
// Translated content (automatically translated on 10-10-2026 04:53:31):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\deploy.dll" and (not (module.path="c:\\program files\\Java\\*\\bin\\*" or module.path="c:\\program files (x86)\\Java\\*\\bin\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of deploy.dll
id: 4710671b-3801-48a3-5206-5b9ff8527656
status: experimental
description: Detects possible DLL hijacking of deploy.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/oracle/deploy.html
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
        ImageLoaded: '*\deploy.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Java\\*\bin\\*'
            - 'c:\program files (x86)\Java\\*\bin\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
