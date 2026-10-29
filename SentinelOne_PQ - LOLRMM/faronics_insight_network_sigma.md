```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".docs.faronics.com" or url.address contains ".docs.faronics.com." or url.address contains ".faronics.com" or url.address contains ".faronics.com." or url.address contains ".support.faronics.com" or url.address contains ".support.faronics.com." or url.address contains ".www.faronics.com" or url.address contains ".www.faronics.com." or url.address="docs.faronics.com" or url.address="docs.faronics.com." or url.address="faronics.com" or url.address="faronics.com." or url.address="support.faronics.com" or url.address="support.faronics.com." or url.address="www.faronics.com" or url.address="www.faronics.com.") or (event.dns.request contains ".docs.faronics.com" or event.dns.request contains ".docs.faronics.com." or event.dns.request contains ".faronics.com" or event.dns.request contains ".faronics.com." or event.dns.request contains ".support.faronics.com" or event.dns.request contains ".support.faronics.com." or event.dns.request contains ".www.faronics.com" or event.dns.request contains ".www.faronics.com." or event.dns.request="docs.faronics.com" or event.dns.request="docs.faronics.com." or event.dns.request="faronics.com" or event.dns.request="faronics.com." or event.dns.request="support.faronics.com" or event.dns.request="support.faronics.com." or event.dns.request="www.faronics.com" or event.dns.request="www.faronics.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Insight RMM Tool Network Activity
id: 20f936fa-bbd5-5d5f-adc5-1df7d6342ea0
status: experimental
description: |
    Detects potential network activity of Faronics Insight RMM tool
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
            - '*.docs.faronics.com'
            - '*.docs.faronics.com.'
            - '*.faronics.com'
            - '*.faronics.com.'
            - '*.support.faronics.com'
            - '*.support.faronics.com.'
            - '*.www.faronics.com'
            - '*.www.faronics.com.'
            - 'docs.faronics.com'
            - 'docs.faronics.com.'
            - 'faronics.com'
            - 'faronics.com.'
            - 'support.faronics.com'
            - 'support.faronics.com.'
            - 'www.faronics.com'
            - 'www.faronics.com.'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Insight
level: medium
```
