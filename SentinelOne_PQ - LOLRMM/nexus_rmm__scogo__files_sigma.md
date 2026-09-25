```sql
// Translated content (automatically translated on 25-09-2026 02:22:27):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "nexusrmm.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Nexus RMM (Scogo) RMM Tool File Activity
id: 6dde03de-e70b-5afd-922c-50e020d2ee5c
status: experimental
description: |
    Detects potential files activity of Nexus RMM (Scogo) RMM tool
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
        TargetFilename|endswith: 'nexusrmm.exe'
    condition: selection
falsepositives:
    - Legitimate use of Nexus RMM (Scogo)
level: medium
```
