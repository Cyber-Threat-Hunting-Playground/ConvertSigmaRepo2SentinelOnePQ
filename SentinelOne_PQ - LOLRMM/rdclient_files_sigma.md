```sql
// Translated content (automatically translated on 27-05-2026 02:14:02):
event.category="file" and (endpoint.os="windows" and tgt.file.path contains "%APPDATA%\\RdClient\*")
```


# Original Sigma Rule:
```yaml
title: Potential RdClient RMM Tool File Activity
id: 1d1198cd-d001-553c-9bce-3548b350a292
status: experimental
description: |
    Detects potential files activity of RdClient RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '%APPDATA%\RdClient\*'
    condition: selection
falsepositives:
    - Legitimate use of RdClient
level: medium
```
