```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.rmmmax.com" or url.address contains ".api.rmmmax.com." or url.address="api.rmmmax.com" or url.address="api.rmmmax.com.") or (event.dns.request contains ".api.rmmmax.com" or event.dns.request contains ".api.rmmmax.com." or event.dns.request="api.rmmmax.com" or event.dns.request="api.rmmmax.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential RMMmax RMM Tool Network Activity
id: 0efaeaaa-f697-51c8-aa87-fe73094209e0
status: experimental
description: |
    Detects potential network activity of RMMmax RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-09
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
            - '*.api.rmmmax.com'
            - '*.api.rmmmax.com.'
            - 'api.rmmmax.com'
            - 'api.rmmmax.com.'
    condition: selection
falsepositives:
    - Legitimate use of RMMmax
level: medium
```
