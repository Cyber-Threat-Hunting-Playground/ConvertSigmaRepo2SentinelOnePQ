```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\MiniRMM\\MiniRmmAgent.exe" or tgt.file.path contains "C:\\ProgramData\\MiniRMM\\SmartScreenTest.ps1" or tgt.file.path contains "C:\\ProgramData\\MiniRMM\\Invoke-AVExclusions.ps1"))
```


# Original Sigma Rule:
```yaml
title: Potential Mini RMM Agent RMM Tool File Activity
id: 958d2d2e-392f-56e2-a877-574fd6c51a49
status: experimental
description: |
    Detects potential files activity of Mini RMM Agent RMM tool
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
            - 'C:\Program Files\MiniRMM\MiniRmmAgent.exe'
            - 'C:\ProgramData\MiniRMM\SmartScreenTest.ps1'
            - 'C:\ProgramData\MiniRMM\Invoke-AVExclusions.ps1'
    condition: selection
falsepositives:
    - Legitimate use of Mini RMM Agent
level: medium
```
