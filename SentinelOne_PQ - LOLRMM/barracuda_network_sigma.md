```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".barracudamsp.com" or url.address contains ".barracudamsp.com." or url.address contains ".islonline.net" or url.address contains ".islonline.net." or url.address contains ".rmm.barracudamsp.com" or url.address contains ".rmm.barracudamsp.com." or url.address="barracudamsp.com" or url.address="barracudamsp.com." or url.address="rmm.barracudamsp.com" or url.address="rmm.barracudamsp.com.") or (event.dns.request contains ".barracudamsp.com" or event.dns.request contains ".barracudamsp.com." or event.dns.request contains ".islonline.net" or event.dns.request contains ".islonline.net." or event.dns.request contains ".rmm.barracudamsp.com" or event.dns.request contains ".rmm.barracudamsp.com." or event.dns.request="barracudamsp.com" or event.dns.request="barracudamsp.com." or event.dns.request="rmm.barracudamsp.com" or event.dns.request="rmm.barracudamsp.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Barracuda RMM Tool Network Activity
id: f15d23a0-b1aa-4e74-afe5-4c500848a66d
status: experimental
description: |
    Detects potential network activity of Barracuda RMM tool
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
            - '*.barracudamsp.com'
            - '*.barracudamsp.com.'
            - '*.islonline.net'
            - '*.islonline.net.'
            - '*.rmm.barracudamsp.com'
            - '*.rmm.barracudamsp.com.'
            - 'barracudamsp.com'
            - 'barracudamsp.com.'
            - 'rmm.barracudamsp.com'
            - 'rmm.barracudamsp.com.'
    condition: selection
falsepositives:
    - Legitimate use of Barracuda
level: medium
```
