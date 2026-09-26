```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "ITAgentRMMSender.exe" or tgt.file.path contains "ITAgentRMMSenderSL.exe" or tgt.file.path contains "ITAgentRMMSenderUpdater.exe" or tgt.file.path contains "ITAgentSender.aiui"))
```


# Original Sigma Rule:
```yaml
title: Potential IT Agent RMM Tool File Activity
id: 79a54348-2e28-59bd-bbb9-5288b4f3f4d5
status: experimental
description: |
    Detects potential files activity of IT Agent RMM tool
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
            - 'ITAgentRMMSender.exe'
            - 'ITAgentRMMSenderSL.exe'
            - 'ITAgentRMMSenderUpdater.exe'
            - 'ITAgentSender.aiui'
    condition: selection
falsepositives:
    - Legitimate use of IT Agent
level: medium
```
