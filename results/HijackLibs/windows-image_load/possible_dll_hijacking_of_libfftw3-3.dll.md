```sql
// Translated content (automatically translated on 31-10-2026 04:36:54):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libfftw3-3.dll" and (not (module.path="c:\\program files\\Blue Iris *\\*" or module.path="c:\\program files (x86)\\Blue Iris *\\*" or module.path contains "c:\\program files\\Blue Iris\\" or module.path contains "c:\\program files (x86)\\Blue Iris\\" or module.path contains "C:\\BlueIris\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libfftw3-3.dll
id: 6628731b-5716-48a3-7286-5b9ff8986277
status: experimental
description: Detects possible DLL hijacking of libfftw3-3.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/fftw/libfftw3-3.html
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
        ImageLoaded: '*\libfftw3-3.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Blue Iris *\\*'
            - 'c:\program files (x86)\Blue Iris *\\*'
            - 'c:\program files\Blue Iris\\*'
            - 'c:\program files (x86)\Blue Iris\\*'
            - 'C:\BlueIris\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
