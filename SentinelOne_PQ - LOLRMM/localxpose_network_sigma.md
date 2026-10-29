```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.localxpose.io" or url.address contains ".api.localxpose.io." or url.address contains ".localxpose.io" or url.address contains ".localxpose.io." or url.address="api.localxpose.io" or url.address="api.localxpose.io." or url.address="localxpose.io" or url.address="localxpose.io.") or (event.dns.request contains ".api.localxpose.io" or event.dns.request contains ".api.localxpose.io." or event.dns.request contains ".localxpose.io" or event.dns.request contains ".localxpose.io." or event.dns.request="api.localxpose.io" or event.dns.request="api.localxpose.io." or event.dns.request="localxpose.io" or event.dns.request="localxpose.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential LocalXpose RMM Tool Network Activity
id: 27712df3-c4c3-5bb2-bef5-5d2dc5555615
status: experimental
description: |
    Detects potential network activity of LocalXpose RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '*.api.localxpose.io'
            - '*.api.localxpose.io.'
            - '*.localxpose.io'
            - '*.localxpose.io.'
            - 'api.localxpose.io'
            - 'api.localxpose.io.'
            - 'localxpose.io'
            - 'localxpose.io.'
    condition: selection
falsepositives:
    - Legitimate use of LocalXpose
level: medium
```
