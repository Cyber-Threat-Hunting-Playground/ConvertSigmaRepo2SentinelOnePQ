```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".cdn.getgo.com" or url.address contains ".cdn.getgo.com." or url.address contains ".desktopstreaming.com" or url.address contains ".desktopstreaming.com." or url.address contains ".fastsupport.com" or url.address contains ".fastsupport.com." or url.address contains ".getgo.com" or url.address contains ".getgo.com." or url.address contains ".goto.com" or url.address contains ".goto.com." or url.address contains ".gotoassist.at" or url.address contains ".gotoassist.at." or url.address contains ".gotoassist.com" or url.address contains ".gotoassist.com." or url.address contains ".gotoassist.me" or url.address contains ".gotoassist.me." or url.address contains ".helpme.net" or url.address contains ".helpme.net." or url.address="goto.com" or url.address="goto.com." or url.address="helpme.net" or url.address="helpme.net.") or (event.dns.request contains ".cdn.getgo.com" or event.dns.request contains ".cdn.getgo.com." or event.dns.request contains ".desktopstreaming.com" or event.dns.request contains ".desktopstreaming.com." or event.dns.request contains ".fastsupport.com" or event.dns.request contains ".fastsupport.com." or event.dns.request contains ".getgo.com" or event.dns.request contains ".getgo.com." or event.dns.request contains ".goto.com" or event.dns.request contains ".goto.com." or event.dns.request contains ".gotoassist.at" or event.dns.request contains ".gotoassist.at." or event.dns.request contains ".gotoassist.com" or event.dns.request contains ".gotoassist.com." or event.dns.request contains ".gotoassist.me" or event.dns.request contains ".gotoassist.me." or event.dns.request contains ".helpme.net" or event.dns.request contains ".helpme.net." or event.dns.request="goto.com" or event.dns.request="goto.com." or event.dns.request="helpme.net" or event.dns.request="helpme.net.")))
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist RMM Tool Network Activity
id: db374856-a793-461e-a33a-648ee4468d7e
status: experimental
description: |
    Detects potential network activity of GoToAssist RMM tool
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
            - '*.cdn.getgo.com'
            - '*.cdn.getgo.com.'
            - '*.desktopstreaming.com'
            - '*.desktopstreaming.com.'
            - '*.fastsupport.com'
            - '*.fastsupport.com.'
            - '*.getgo.com'
            - '*.getgo.com.'
            - '*.goto.com'
            - '*.goto.com.'
            - '*.gotoassist.at'
            - '*.gotoassist.at.'
            - '*.gotoassist.com'
            - '*.gotoassist.com.'
            - '*.gotoassist.me'
            - '*.gotoassist.me.'
            - '*.helpme.net'
            - '*.helpme.net.'
            - 'goto.com'
            - 'goto.com.'
            - 'helpme.net'
            - 'helpme.net.'
    condition: selection
falsepositives:
    - Legitimate use of GoToAssist
level: medium
```
