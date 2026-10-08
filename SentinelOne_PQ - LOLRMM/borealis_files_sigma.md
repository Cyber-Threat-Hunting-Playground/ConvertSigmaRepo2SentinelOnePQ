```sql
// Translated content (automatically translated on 08-10-2026 03:27:06):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Borealis\\Agent.exe" or tgt.file.path contains "C:\\Borealis\\agent.json" or tgt.file.path contains "C:\\Borealis\\Logs\\Agent\\agent.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Borealis RMM Tool File Activity
id: b162288b-eb95-598d-9ec8-e2f1f0999596
status: experimental
description: |
    Detects potential files activity of Borealis RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-29
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Borealis\Agent.exe'
            - 'C:\Borealis\agent.json'
            - 'C:\Borealis\Logs\Agent\agent.log'
    condition: selection
falsepositives:
    - Legitimate use of Borealis
level: medium
```
