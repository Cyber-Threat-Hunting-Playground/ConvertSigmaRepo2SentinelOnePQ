```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".agents.addigy.com" or url.address contains ".agents.addigy.com." or url.address contains ".grtmprod.addigy.com" or url.address contains ".grtmprod.addigy.com." or url.address contains ".prod.addigy.com" or url.address contains ".prod.addigy.com." or url.address="agents.addigy.com" or url.address="agents.addigy.com." or url.address="grtmprod.addigy.com" or url.address="grtmprod.addigy.com." or url.address="prod.addigy.com" or url.address="prod.addigy.com.") or (event.dns.request contains ".agents.addigy.com" or event.dns.request contains ".agents.addigy.com." or event.dns.request contains ".grtmprod.addigy.com" or event.dns.request contains ".grtmprod.addigy.com." or event.dns.request contains ".prod.addigy.com" or event.dns.request contains ".prod.addigy.com." or event.dns.request="agents.addigy.com" or event.dns.request="agents.addigy.com." or event.dns.request="grtmprod.addigy.com" or event.dns.request="grtmprod.addigy.com." or event.dns.request="prod.addigy.com" or event.dns.request="prod.addigy.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Addigy RMM Tool Network Activity
id: 43757bb8-b54f-41be-9e96-8099c0dc9a16
status: experimental
description: |
    Detects potential network activity of Addigy RMM tool
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
            - '*.agents.addigy.com'
            - '*.agents.addigy.com.'
            - '*.grtmprod.addigy.com'
            - '*.grtmprod.addigy.com.'
            - '*.prod.addigy.com'
            - '*.prod.addigy.com.'
            - 'agents.addigy.com'
            - 'agents.addigy.com.'
            - 'grtmprod.addigy.com'
            - 'grtmprod.addigy.com.'
            - 'prod.addigy.com'
            - 'prod.addigy.com.'
    condition: selection
falsepositives:
    - Legitimate use of Addigy
level: medium
```
