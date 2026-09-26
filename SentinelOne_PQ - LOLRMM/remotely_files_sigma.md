```sql
// Translated content (automatically translated on 26-09-2026 02:26:26):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Remotely\\Remotely_Agent.exe" or tgt.file.path contains "C:\\Program Files\\Remotely\\Desktop\\Remotely_Desktop.exe" or tgt.file.path contains "C:\\Program Files\\Remotely\\ConnectionInfo.json" or tgt.file.path contains "C:\\Program Files\\Remotely\\etag.txt" or tgt.file.path contains "%TEMP%\\Remotely_Install.txt"))
```


# Original Sigma Rule:
```yaml
title: Potential Remotely RMM Tool File Activity
id: 814ead76-7a18-55cb-9d7c-1c2c81ea32eb
status: experimental
description: |
    Detects potential files activity of Remotely RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-06-15
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
            - 'C:\Program Files\Remotely\Remotely_Agent.exe'
            - 'C:\Program Files\Remotely\Desktop\Remotely_Desktop.exe'
            - 'C:\Program Files\Remotely\ConnectionInfo.json'
            - 'C:\Program Files\Remotely\etag.txt'
            - '%TEMP%\Remotely_Install.txt'
    condition: selection
falsepositives:
    - Legitimate use of Remotely
level: medium
```
