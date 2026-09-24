```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\AppData\\Roaming\\Mremote\\agent.exe" or tgt.file.path contains "\\AppData\\Roaming\\Mremote\\agent.log" or tgt.file.path contains "\\AppData\\Roaming\\Mremote\\enrolled.json" or tgt.file.path contains "\\AppData\\Roaming\\Mremote\\consent.ok"))
```


# Original Sigma Rule:
```yaml
title: Potential Mremote RMM Tool File Activity
id: e56b0e00-3ffc-57a4-85ce-e93654c164ef
status: experimental
description: |
    Detects potential files activity of Mremote RMM tool
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
            - '*\AppData\Roaming\Mremote\agent.exe'
            - '*\AppData\Roaming\Mremote\agent.log'
            - '*\AppData\Roaming\Mremote\enrolled.json'
            - '*\AppData\Roaming\Mremote\consent.ok'
    condition: selection
falsepositives:
    - Legitimate use of Mremote
level: medium
```
