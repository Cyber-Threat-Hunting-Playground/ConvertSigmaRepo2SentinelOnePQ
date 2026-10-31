```sql
// Translated content (automatically translated on 31-10-2026 04:36:54):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\eztwain4.dll" and (not (module.path="c:\\program files\\Nitro\\PDF Pro\\*\\*" or module.path="c:\\program files (x86)\\Nitro\\PDF Pro\\*\\*" or module.path="c:\\program files\\Nitro\\Pro *\\*" or module.path="c:\\program files (x86)\\Nitro\\Pro *\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of eztwain4.dll
id: 6065471b-9354-48a3-1039-5b9ff8146942
status: experimental
description: Detects possible DLL hijacking of eztwain4.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/atalasoft/eztwain4.html
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
        ImageLoaded: '*\eztwain4.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Nitro\PDF Pro\\*\\*'
            - 'c:\program files (x86)\Nitro\PDF Pro\\*\\*'
            - 'c:\program files\Nitro\Pro *\\*'
            - 'c:\program files (x86)\Nitro\Pro *\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
