```sql
// Translated content (automatically translated on 05-10-2026 04:39:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vim64.dll" and (not (module.path contains "c:\\program files\\Vim\\" or module.path contains "c:\\program files (x86)\\Vim\\" or module.path="c:\\program files\\Vim\\vim*\\*" or module.path="c:\\program files (x86)\\Vim\\vim*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vim64.dll
id: 7261471b-1982-48a3-5760-5b9ff8224953
status: experimental
description: Detects possible DLL hijacking of vim64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vim/vim64.html
author: "Daniel Koifman"
date: 2026-09-29
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vim64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Vim\\*'
            - 'c:\program files (x86)\Vim\\*'
            - 'c:\program files\Vim\vim*\\*'
            - 'c:\program files (x86)\Vim\vim*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
