```sql
// Translated content (automatically translated on 10-10-2026 04:53:31):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\windowspackagemanager.dll" and (not (module.path="c:\\program files\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\*" or module.path="c:\\program files (x86)\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of windowspackagemanager.dll
id: 2593001b-5476-48a3-2908-5b9ff8728377
status: experimental
description: Detects possible DLL hijacking of windowspackagemanager.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/windowspackagemanager.html
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
        ImageLoaded: '*\windowspackagemanager.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\*'
            - 'c:\program files (x86)\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
