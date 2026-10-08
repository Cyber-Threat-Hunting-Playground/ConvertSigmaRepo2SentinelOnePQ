```sql
// Translated content (automatically translated on 08-10-2026 03:27:06):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Msp Agent\\msp-agent-core.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential N-able N-central RMM Tool File Activity
id: 92a2f904-ce77-5cdb-93c6-aab275cfa702
status: experimental
description: |
    Detects potential files activity of N-able N-central RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\agent.exe'
            - 'C:\Program Files (x86)\Msp Agent\msp-agent-core.exe'
    condition: selection
falsepositives:
    - Legitimate use of N-able N-central
level: medium
```
