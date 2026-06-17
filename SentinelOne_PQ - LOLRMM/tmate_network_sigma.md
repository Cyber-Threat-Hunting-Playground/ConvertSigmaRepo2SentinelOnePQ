```sql
// Translated content (automatically translated on 17-06-2026 02:38:58):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "tmate.io" or url.address contains ".tmate.io") or (event.dns.request contains "tmate.io" or event.dns.request contains ".tmate.io")))
```


# Original Sigma Rule:
```yaml
title: Potential tmate RMM Tool Network Activity
id: ae1b648e-5cd4-50b6-931f-5f162038354b
status: experimental
description: |
    Detects potential network activity of tmate RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'tmate.io'
            - '*.tmate.io'
    condition: selection
falsepositives:
    - Legitimate use of tmate
level: medium
```
