```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".tele-desk.com" or url.address contains ".tele-desk.com." or url.address="tele-desk.com" or url.address="tele-desk.com.") or (event.dns.request contains ".tele-desk.com" or event.dns.request contains ".tele-desk.com." or event.dns.request="tele-desk.com" or event.dns.request="tele-desk.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential TeleDesktop RMM Tool Network Activity
id: 6d77f583-7194-495b-af7c-9190730aaa31
status: experimental
description: |
    Detects potential network activity of TeleDesktop RMM tool
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
            - '*.tele-desk.com'
            - '*.tele-desk.com.'
            - 'tele-desk.com'
            - 'tele-desk.com.'
    condition: selection
falsepositives:
    - Legitimate use of TeleDesktop
level: medium
```
