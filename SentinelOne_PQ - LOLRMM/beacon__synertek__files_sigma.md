```sql
// Translated content (automatically translated on 07-10-2026 03:11:23):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Beacon\\beacon-agent.exe" or tgt.file.path contains "C:\\ProgramData\\Beacon\\credential.json" or tgt.file.path contains "C:\\ProgramData\\Beacon\\agent.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Beacon (Synertek) RMM Tool File Activity
id: 20255254-534d-5a25-93ed-cfc8ffd15310
status: experimental
description: |
    Detects potential files activity of Beacon (Synertek) RMM tool
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
            - 'C:\Program Files\Beacon\beacon-agent.exe'
            - 'C:\ProgramData\Beacon\credential.json'
            - 'C:\ProgramData\Beacon\agent.log'
    condition: selection
falsepositives:
    - Legitimate use of Beacon (Synertek)
level: medium
```
