```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".agent.tiflux.com" or url.address contains ".agent.tiflux.com." or url.address="agent.tiflux.com" or url.address="agent.tiflux.com." or url.address contains ".app.tiflux.com" or url.address contains ".app.tiflux.com." or url.address="app.tiflux.com" or url.address="app.tiflux.com." or url.address contains ".tiflux.com" or url.address contains ".tiflux.com." or url.address contains ".tiflux.com.br" or url.address contains ".tiflux.com.br." or url.address contains ".www.tiflux.com" or url.address contains ".www.tiflux.com." or url.address contains ".www.tiflux.com.br" or url.address contains ".www.tiflux.com.br." or url.address="tiflux.com" or url.address="tiflux.com." or url.address="tiflux.com.br" or url.address="tiflux.com.br." or url.address="www.tiflux.com" or url.address="www.tiflux.com." or url.address="www.tiflux.com.br" or url.address="www.tiflux.com.br." or url.address contains ".my.splashtop.com" or url.address contains ".my.splashtop.com." or url.address="my.splashtop.com" or url.address="my.splashtop.com.") or (event.dns.request contains ".agent.tiflux.com" or event.dns.request contains ".agent.tiflux.com." or event.dns.request="agent.tiflux.com" or event.dns.request="agent.tiflux.com." or event.dns.request contains ".app.tiflux.com" or event.dns.request contains ".app.tiflux.com." or event.dns.request="app.tiflux.com" or event.dns.request="app.tiflux.com." or event.dns.request contains ".tiflux.com" or event.dns.request contains ".tiflux.com." or event.dns.request contains ".tiflux.com.br" or event.dns.request contains ".tiflux.com.br." or event.dns.request contains ".www.tiflux.com" or event.dns.request contains ".www.tiflux.com." or event.dns.request contains ".www.tiflux.com.br" or event.dns.request contains ".www.tiflux.com.br." or event.dns.request="tiflux.com" or event.dns.request="tiflux.com." or event.dns.request="tiflux.com.br" or event.dns.request="tiflux.com.br." or event.dns.request="www.tiflux.com" or event.dns.request="www.tiflux.com." or event.dns.request="www.tiflux.com.br" or event.dns.request="www.tiflux.com.br." or event.dns.request contains ".my.splashtop.com" or event.dns.request contains ".my.splashtop.com." or event.dns.request="my.splashtop.com" or event.dns.request="my.splashtop.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential TiFLUX RMM Tool Network Activity
id: 52e259fb-2a86-54a9-84ff-db733436e65a
status: experimental
description: |
    Detects potential network activity of TiFLUX RMM tool
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
            - '*.agent.tiflux.com'
            - '*.agent.tiflux.com.'
            - 'agent.tiflux.com'
            - 'agent.tiflux.com.'
            - '*.app.tiflux.com'
            - '*.app.tiflux.com.'
            - 'app.tiflux.com'
            - 'app.tiflux.com.'
            - '*.tiflux.com'
            - '*.tiflux.com.'
            - '*.tiflux.com.br'
            - '*.tiflux.com.br.'
            - '*.www.tiflux.com'
            - '*.www.tiflux.com.'
            - '*.www.tiflux.com.br'
            - '*.www.tiflux.com.br.'
            - 'tiflux.com'
            - 'tiflux.com.'
            - 'tiflux.com.br'
            - 'tiflux.com.br.'
            - 'www.tiflux.com'
            - 'www.tiflux.com.'
            - 'www.tiflux.com.br'
            - 'www.tiflux.com.br.'
            - '*.my.splashtop.com'
            - '*.my.splashtop.com.'
            - 'my.splashtop.com'
            - 'my.splashtop.com.'
    condition: selection
falsepositives:
    - Legitimate use of TiFLUX
level: medium
```
