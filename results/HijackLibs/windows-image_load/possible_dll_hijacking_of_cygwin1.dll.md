```sql
// Translated content (automatically translated on 28-11-2026 06:49:41):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\cygwin1.dll" and (not module.path contains "C:\\cygwin\\bin\\")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cygwin1.dll
id: 3964861b-2270-48a3-6472-5b9ff8124220
status: experimental
description: Detects possible DLL hijacking of cygwin1.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/cygwin/cygwin1.html
author: "Liran Ravich"
date: 2026-10-29
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cygwin1.dll'
    filter:
        ImageLoaded:
            - 'C:\cygwin\bin\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
