```sql
// Translated content (automatically translated on 05-10-2026 04:39:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\deelevator64.dll" and (not (module.path contains "c:\\program files\\Stardock\\Start11\\" or module.path contains "c:\\program files (x86)\\Stardock\\Start11\\" or module.path contains "c:\\program files\\Stardock\\Fences\\" or module.path contains "c:\\program files (x86)\\Stardock\\Fences\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of deelevator64.dll
id: 4348501b-3801-48a3-5206-5b9ff8566686
status: experimental
description: Detects possible DLL hijacking of deelevator64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/stardock/deelevator64.html
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
        ImageLoaded: '*\deelevator64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Stardock\Start11\\*'
            - 'c:\program files (x86)\Stardock\Start11\\*'
            - 'c:\program files\Stardock\Fences\\*'
            - 'c:\program files (x86)\Stardock\Fences\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
