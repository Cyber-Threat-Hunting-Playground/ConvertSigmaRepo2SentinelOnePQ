```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".kickidler.com" or url.address contains ".kickidler.com." or url.address contains ".my.kickidler.com" or url.address contains ".my.kickidler.com." or url.address="kickidler.com" or url.address="kickidler.com." or url.address="my.kickidler.com" or url.address="my.kickidler.com.") or (event.dns.request contains ".kickidler.com" or event.dns.request contains ".kickidler.com." or event.dns.request contains ".my.kickidler.com" or event.dns.request contains ".my.kickidler.com." or event.dns.request="kickidler.com" or event.dns.request="kickidler.com." or event.dns.request="my.kickidler.com" or event.dns.request="my.kickidler.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential KickIdler RMM Tool Network Activity
id: 7ebb5c84-5afb-4681-93eb-a021f4c2afd8
status: experimental
description: |
    Detects potential network activity of KickIdler RMM tool
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
            - '*.kickidler.com'
            - '*.kickidler.com.'
            - '*.my.kickidler.com'
            - '*.my.kickidler.com.'
            - 'kickidler.com'
            - 'kickidler.com.'
            - 'my.kickidler.com'
            - 'my.kickidler.com.'
    condition: selection
falsepositives:
    - Legitimate use of KickIdler
level: medium
```
