```sql
// Translated content (automatically translated on 24-09-2026 02:05:20):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\nezha\\nezha-agent.exe" or tgt.file.path contains "C:\\nezha\\config.yml"))
```


# Original Sigma Rule:
```yaml
title: Potential Nezha RMM Tool File Activity
id: 839c690f-219f-5c91-ba0c-d0f5a62a7052
status: experimental
description: |
    Detects potential files activity of Nezha RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - 'C:\nezha\nezha-agent.exe'
            - 'C:\nezha\config.yml'
    condition: selection
falsepositives:
    - Legitimate use of Nezha
level: medium
```
