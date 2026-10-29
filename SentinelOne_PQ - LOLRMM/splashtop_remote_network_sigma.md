```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.splashtop.com" or url.address contains ".api.splashtop.com." or url.address contains ".api.splashtop.eu" or url.address contains ".api.splashtop.eu." or url.address contains ".relay.splashtop.com" or url.address contains ".relay.splashtop.com." or url.address contains ".splashtop.com" or url.address contains ".splashtop.com." or url.address="splashtop.com" or url.address="splashtop.com.") or (event.dns.request contains ".api.splashtop.com" or event.dns.request contains ".api.splashtop.com." or event.dns.request contains ".api.splashtop.eu" or event.dns.request contains ".api.splashtop.eu." or event.dns.request contains ".relay.splashtop.com" or event.dns.request contains ".relay.splashtop.com." or event.dns.request contains ".splashtop.com" or event.dns.request contains ".splashtop.com." or event.dns.request="splashtop.com" or event.dns.request="splashtop.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop Remote RMM Tool Network Activity
id: 95772d6f-0c1d-4515-9779-85824ee59269
status: experimental
description: |
    Detects potential network activity of Splashtop Remote RMM tool
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
            - '*.api.splashtop.com'
            - '*.api.splashtop.com.'
            - '*.api.splashtop.eu'
            - '*.api.splashtop.eu.'
            - '*.relay.splashtop.com'
            - '*.relay.splashtop.com.'
            - '*.splashtop.com'
            - '*.splashtop.com.'
            - 'splashtop.com'
            - 'splashtop.com.'
    condition: selection
falsepositives:
    - Legitimate use of Splashtop Remote
level: medium
```
