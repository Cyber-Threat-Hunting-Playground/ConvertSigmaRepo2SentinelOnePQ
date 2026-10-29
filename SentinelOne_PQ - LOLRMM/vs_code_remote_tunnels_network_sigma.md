```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".global.rel.tunnels.api.visualstudio.com" or url.address contains ".global.rel.tunnels.api.visualstudio.com." or url.address="global.rel.tunnels.api.visualstudio.com" or url.address="global.rel.tunnels.api.visualstudio.com.") or (event.dns.request contains ".global.rel.tunnels.api.visualstudio.com" or event.dns.request contains ".global.rel.tunnels.api.visualstudio.com." or event.dns.request="global.rel.tunnels.api.visualstudio.com" or event.dns.request="global.rel.tunnels.api.visualstudio.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential VS Code Remote Tunnels RMM Tool Network Activity
id: ce5264b9-0a03-5738-9b97-2171bfdbe395
status: experimental
description: |
    Detects potential network activity of VS Code Remote Tunnels RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-20
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
            - '*.global.rel.tunnels.api.visualstudio.com'
            - '*.global.rel.tunnels.api.visualstudio.com.'
            - 'global.rel.tunnels.api.visualstudio.com'
            - 'global.rel.tunnels.api.visualstudio.com.'
    condition: selection
falsepositives:
    - Legitimate use of VS Code Remote Tunnels
level: medium
```
