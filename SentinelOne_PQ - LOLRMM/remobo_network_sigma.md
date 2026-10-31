```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remobo.en.softonic.com" or url.address contains ".remobo.en.softonic.com." or url.address="remobo.en.softonic.com" or url.address="remobo.en.softonic.com.") or (event.dns.request contains ".remobo.en.softonic.com" or event.dns.request contains ".remobo.en.softonic.com." or event.dns.request="remobo.en.softonic.com" or event.dns.request="remobo.en.softonic.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Remobo RMM Tool Network Activity
id: 346c9a37-5f2b-4fc8-90eb-7a547780a29d
status: experimental
description: |
    Detects potential network activity of Remobo RMM tool
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
            - '*.remobo.en.softonic.com'
            - '*.remobo.en.softonic.com.'
            - 'remobo.en.softonic.com'
            - 'remobo.en.softonic.com.'
    condition: selection
falsepositives:
    - Legitimate use of Remobo
level: medium
```
