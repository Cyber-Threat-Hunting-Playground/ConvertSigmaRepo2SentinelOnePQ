```sql
// Translated content (automatically translated on 30-10-2026 04:51:08):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\frameworkbase.dll" and (not (module.path="c:\\program files\\n-Track\\n-Track Studio *\\*" or module.path="c:\\program files (x86)\\n-Track\\n-Track Studio *\\*" or module.path="c:\\program files\\n-Track\\n-Track Studio *\\nBridge32\\*" or module.path="c:\\program files (x86)\\n-Track\\n-Track Studio *\\nBridge32\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of frameworkbase.dll
id: 9950931b-9402-48a3-1427-5b9ff8474781
status: experimental
description: Detects possible DLL hijacking of frameworkbase.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/n-track/frameworkbase.html
author: "Liran Ravich"
date: 2026-10-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\frameworkbase.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\n-Track\n-Track Studio *\\*'
            - 'c:\program files (x86)\n-Track\n-Track Studio *\\*'
            - 'c:\program files\n-Track\n-Track Studio *\nBridge32\\*'
            - 'c:\program files (x86)\n-Track\n-Track Studio *\nBridge32\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
