```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "\\LightRmmAgent\\LightRmmAgentService.exe" or tgt.file.path contains "C:\\ProgramData\\LightRmmAgent\\machine.id" or tgt.file.path contains "C:\\Windows\\Temp\\MonitoringPanel.msi"))
```


# Original Sigma Rule:
```yaml
title: Potential LightRmmAgent RMM Tool File Activity
id: a7f115e5-3f72-5f21-8423-97f3ec218e6f
status: experimental
description: |
    Detects potential files activity of LightRmmAgent RMM tool
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
            - '*\LightRmmAgent\LightRmmAgentService.exe'
            - 'C:\ProgramData\LightRmmAgent\machine.id'
            - 'C:\Windows\Temp\MonitoringPanel.msi'
    condition: selection
falsepositives:
    - Legitimate use of LightRmmAgent
level: medium
```
