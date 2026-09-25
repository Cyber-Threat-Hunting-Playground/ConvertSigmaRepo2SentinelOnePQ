```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Mesh Agent\\MeshAgent.exe" or tgt.file.path contains "C:\\Program Files\\Mesh Agent\\MeshAgent.msh"))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool File Activity
id: 1bb123a1-a6df-4f6f-88ac-35881e1ba861
status: experimental
description: |
    Detects potential files activity of MeshCentral RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-22
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files\Mesh Agent\MeshAgent.exe'
            - 'C:\Program Files\Mesh Agent\MeshAgent.msh'
    condition: selection
falsepositives:
    - Legitimate use of MeshCentral
level: medium
```
