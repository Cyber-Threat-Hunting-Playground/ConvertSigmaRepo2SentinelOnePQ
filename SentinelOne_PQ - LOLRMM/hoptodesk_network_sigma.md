```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.hoptodesk.com" or url.address contains ".api.hoptodesk.com." or url.address contains ".download.hoptodesk.com" or url.address contains ".download.hoptodesk.com." or url.address contains ".hoptodesk.com" or url.address contains ".hoptodesk.com." or url.address contains ".signal.hoptodesk.com" or url.address contains ".signal.hoptodesk.com." or url.address contains ".turn.hoptodesk.com" or url.address contains ".turn.hoptodesk.com." or url.address contains ".www.hoptodesk.com" or url.address contains ".www.hoptodesk.com." or url.address="api.hoptodesk.com" or url.address="api.hoptodesk.com." or url.address="download.hoptodesk.com" or url.address="download.hoptodesk.com." or url.address="hoptodesk.com" or url.address="hoptodesk.com." or url.address="signal.hoptodesk.com" or url.address="signal.hoptodesk.com." or url.address="turn.hoptodesk.com" or url.address="turn.hoptodesk.com." or url.address="www.hoptodesk.com" or url.address="www.hoptodesk.com.") or (event.dns.request contains ".api.hoptodesk.com" or event.dns.request contains ".api.hoptodesk.com." or event.dns.request contains ".download.hoptodesk.com" or event.dns.request contains ".download.hoptodesk.com." or event.dns.request contains ".hoptodesk.com" or event.dns.request contains ".hoptodesk.com." or event.dns.request contains ".signal.hoptodesk.com" or event.dns.request contains ".signal.hoptodesk.com." or event.dns.request contains ".turn.hoptodesk.com" or event.dns.request contains ".turn.hoptodesk.com." or event.dns.request contains ".www.hoptodesk.com" or event.dns.request contains ".www.hoptodesk.com." or event.dns.request="api.hoptodesk.com" or event.dns.request="api.hoptodesk.com." or event.dns.request="download.hoptodesk.com" or event.dns.request="download.hoptodesk.com." or event.dns.request="hoptodesk.com" or event.dns.request="hoptodesk.com." or event.dns.request="signal.hoptodesk.com" or event.dns.request="signal.hoptodesk.com." or event.dns.request="turn.hoptodesk.com" or event.dns.request="turn.hoptodesk.com." or event.dns.request="www.hoptodesk.com" or event.dns.request="www.hoptodesk.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Network Activity
id: 68fd1e88-4536-42ee-8517-cd8fbc3df925
status: experimental
description: |
    Detects potential network activity of HopToDesk RMM tool
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
            - '*.api.hoptodesk.com'
            - '*.api.hoptodesk.com.'
            - '*.download.hoptodesk.com'
            - '*.download.hoptodesk.com.'
            - '*.hoptodesk.com'
            - '*.hoptodesk.com.'
            - '*.signal.hoptodesk.com'
            - '*.signal.hoptodesk.com.'
            - '*.turn.hoptodesk.com'
            - '*.turn.hoptodesk.com.'
            - '*.www.hoptodesk.com'
            - '*.www.hoptodesk.com.'
            - 'api.hoptodesk.com'
            - 'api.hoptodesk.com.'
            - 'download.hoptodesk.com'
            - 'download.hoptodesk.com.'
            - 'hoptodesk.com'
            - 'hoptodesk.com.'
            - 'signal.hoptodesk.com'
            - 'signal.hoptodesk.com.'
            - 'turn.hoptodesk.com'
            - 'turn.hoptodesk.com.'
            - 'www.hoptodesk.com'
            - 'www.hoptodesk.com.'
    condition: selection
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
