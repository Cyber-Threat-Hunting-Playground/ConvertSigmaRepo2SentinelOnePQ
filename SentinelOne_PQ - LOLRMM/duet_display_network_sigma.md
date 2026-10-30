```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".duetdisplay.com" or url.address contains ".duetdisplay.com." or url.address contains ".itagent.com" or url.address contains ".itagent.com." or url.address contains ".rdp.duetdisplay.com" or url.address contains ".rdp.duetdisplay.com." or url.address="duetdisplay.com" or url.address="duetdisplay.com." or url.address="itagent.com" or url.address="itagent.com." or url.address="rdp.duetdisplay.com" or url.address="rdp.duetdisplay.com.") or (event.dns.request contains ".duetdisplay.com" or event.dns.request contains ".duetdisplay.com." or event.dns.request contains ".itagent.com" or event.dns.request contains ".itagent.com." or event.dns.request contains ".rdp.duetdisplay.com" or event.dns.request contains ".rdp.duetdisplay.com." or event.dns.request="duetdisplay.com" or event.dns.request="duetdisplay.com." or event.dns.request="itagent.com" or event.dns.request="itagent.com." or event.dns.request="rdp.duetdisplay.com" or event.dns.request="rdp.duetdisplay.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Duet Display RMM Tool Network Activity
id: f35b39c2-45b7-5beb-87f4-9586f5ec4374
status: experimental
description: |
    Detects potential network activity of Duet Display RMM tool
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
            - '*.duetdisplay.com'
            - '*.duetdisplay.com.'
            - '*.itagent.com'
            - '*.itagent.com.'
            - '*.rdp.duetdisplay.com'
            - '*.rdp.duetdisplay.com.'
            - 'duetdisplay.com'
            - 'duetdisplay.com.'
            - 'itagent.com'
            - 'itagent.com.'
            - 'rdp.duetdisplay.com'
            - 'rdp.duetdisplay.com.'
    condition: selection
falsepositives:
    - Legitimate use of Duet Display
level: medium
```
