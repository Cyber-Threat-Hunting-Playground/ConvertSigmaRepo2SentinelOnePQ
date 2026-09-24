```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "UniRMM.exe" or tgt.file.path contains "UniRMM.msi"))
```


# Original Sigma Rule:
```yaml
title: Potential UniSystem RMM RMM Tool File Activity
id: 50e94813-df2a-5281-8062-d95b4c95da83
status: experimental
description: |
    Detects potential files activity of UniSystem RMM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-23
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'UniRMM.exe'
            - 'UniRMM.msi'
    condition: selection
falsepositives:
    - Legitimate use of UniSystem RMM
level: medium
```
