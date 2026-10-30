```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".spyanywhere.com" or url.address contains ".spyanywhere.com." or url.address contains ".spytech-web.com" or url.address contains ".spytech-web.com." or url.address="spyanywhere.com" or url.address="spyanywhere.com.") or (event.dns.request contains ".spyanywhere.com" or event.dns.request contains ".spyanywhere.com." or event.dns.request contains ".spytech-web.com" or event.dns.request contains ".spytech-web.com." or event.dns.request="spyanywhere.com" or event.dns.request="spyanywhere.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential SpyAnywhere RMM Tool Network Activity
id: 45151543-012c-4875-b809-cd3878b63def
status: experimental
description: |
    Detects potential network activity of SpyAnywhere RMM tool
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
            - '*.spyanywhere.com'
            - '*.spyanywhere.com.'
            - '*.spytech-web.com'
            - '*.spytech-web.com.'
            - 'spyanywhere.com'
            - 'spyanywhere.com.'
    condition: selection
falsepositives:
    - Legitimate use of SpyAnywhere
level: medium
```
