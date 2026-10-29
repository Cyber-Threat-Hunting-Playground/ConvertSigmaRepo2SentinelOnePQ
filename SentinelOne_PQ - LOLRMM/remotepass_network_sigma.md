```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remotepass.com" or url.address contains ".remotepass.com." or url.address="remotepass.com" or url.address="remotepass.com.") or (event.dns.request contains ".remotepass.com" or event.dns.request contains ".remotepass.com." or event.dns.request="remotepass.com" or event.dns.request="remotepass.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePass RMM Tool Network Activity
id: f4461751-f222-4de0-9993-9f6b7c4a2e8b
status: experimental
description: |
    Detects potential network activity of RemotePass RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname:
            - '*.remotepass.com'
            - '*.remotepass.com.'
            - 'remotepass.com'
            - 'remotepass.com.'
    condition: selection
falsepositives:
    - Legitimate use of RemotePass
level: medium
```
