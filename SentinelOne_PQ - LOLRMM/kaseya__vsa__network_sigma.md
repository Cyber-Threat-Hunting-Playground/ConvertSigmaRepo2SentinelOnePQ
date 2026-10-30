```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".deploy01.kaseya.com" or url.address contains ".deploy01.kaseya.com." or url.address contains ".kaseya.com" or url.address contains ".kaseya.com." or url.address contains ".kaseya.net" or url.address contains ".kaseya.net." or url.address contains ".managedsupport.kaseya.net" or url.address contains ".managedsupport.kaseya.net." or url.address="deploy01.kaseya.com" or url.address="deploy01.kaseya.com." or url.address="kaseya.com" or url.address="kaseya.com." or url.address="managedsupport.kaseya.net" or url.address="managedsupport.kaseya.net.") or (event.dns.request contains ".deploy01.kaseya.com" or event.dns.request contains ".deploy01.kaseya.com." or event.dns.request contains ".kaseya.com" or event.dns.request contains ".kaseya.com." or event.dns.request contains ".kaseya.net" or event.dns.request contains ".kaseya.net." or event.dns.request contains ".managedsupport.kaseya.net" or event.dns.request contains ".managedsupport.kaseya.net." or event.dns.request="deploy01.kaseya.com" or event.dns.request="deploy01.kaseya.com." or event.dns.request="kaseya.com" or event.dns.request="kaseya.com." or event.dns.request="managedsupport.kaseya.net" or event.dns.request="managedsupport.kaseya.net.")))
```


# Original Sigma Rule:
```yaml
title: Potential Kaseya (VSA) RMM Tool Network Activity
id: b50291cd-fc39-4416-af8e-e53be7c6eb51
status: experimental
description: |
    Detects potential network activity of Kaseya (VSA) RMM tool
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
            - '*.deploy01.kaseya.com'
            - '*.deploy01.kaseya.com.'
            - '*.kaseya.com'
            - '*.kaseya.com.'
            - '*.kaseya.net'
            - '*.kaseya.net.'
            - '*.managedsupport.kaseya.net'
            - '*.managedsupport.kaseya.net.'
            - 'deploy01.kaseya.com'
            - 'deploy01.kaseya.com.'
            - 'kaseya.com'
            - 'kaseya.com.'
            - 'managedsupport.kaseya.net'
            - 'managedsupport.kaseya.net.'
    condition: selection
falsepositives:
    - Legitimate use of Kaseya (VSA)
level: medium
```
