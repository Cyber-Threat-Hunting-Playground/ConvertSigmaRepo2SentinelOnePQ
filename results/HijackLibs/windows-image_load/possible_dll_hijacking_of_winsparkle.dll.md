```sql
// Translated content (automatically translated on 09-10-2026 05:07:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\winsparkle.dll" and (not (module.path contains "c:\\program files\\Poedit\\" or module.path contains "c:\\program files (x86)\\Poedit\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of winsparkle.dll
id: 7811741b-1982-48a3-5760-5b9ff8388588
status: experimental
description: Detects possible DLL hijacking of winsparkle.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/winsparkle/winsparkle.html
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
        ImageLoaded: '*\winsparkle.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Poedit\\*'
            - 'c:\program files (x86)\Poedit\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
