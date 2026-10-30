```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".agents.level.io" or url.address contains ".agents.level.io." or url.address contains ".builds.level.io" or url.address contains ".builds.level.io." or url.address contains ".downloads.level.io" or url.address contains ".downloads.level.io." or url.address contains ".level.io" or url.address contains ".level.io." or url.address contains ".online.level.io" or url.address contains ".online.level.io." or url.address="agents.level.io" or url.address="agents.level.io." or url.address="builds.level.io" or url.address="builds.level.io." or url.address="downloads.level.io" or url.address="downloads.level.io." or url.address="level.io" or url.address="level.io." or url.address="online.level.io" or url.address="online.level.io.") or (event.dns.request contains ".agents.level.io" or event.dns.request contains ".agents.level.io." or event.dns.request contains ".builds.level.io" or event.dns.request contains ".builds.level.io." or event.dns.request contains ".downloads.level.io" or event.dns.request contains ".downloads.level.io." or event.dns.request contains ".level.io" or event.dns.request contains ".level.io." or event.dns.request contains ".online.level.io" or event.dns.request contains ".online.level.io." or event.dns.request="agents.level.io" or event.dns.request="agents.level.io." or event.dns.request="builds.level.io" or event.dns.request="builds.level.io." or event.dns.request="downloads.level.io" or event.dns.request="downloads.level.io." or event.dns.request="level.io" or event.dns.request="level.io." or event.dns.request="online.level.io" or event.dns.request="online.level.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential Level RMM Tool Network Activity
id: ed6be521-b6af-47df-b0c9-7474d10f328f
status: experimental
description: |
    Detects potential network activity of Level RMM tool
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
            - '*.agents.level.io'
            - '*.agents.level.io.'
            - '*.builds.level.io'
            - '*.builds.level.io.'
            - '*.downloads.level.io'
            - '*.downloads.level.io.'
            - '*.level.io'
            - '*.level.io.'
            - '*.online.level.io'
            - '*.online.level.io.'
            - 'agents.level.io'
            - 'agents.level.io.'
            - 'builds.level.io'
            - 'builds.level.io.'
            - 'downloads.level.io'
            - 'downloads.level.io.'
            - 'level.io'
            - 'level.io.'
            - 'online.level.io'
            - 'online.level.io.'
    condition: selection
falsepositives:
    - Legitimate use of Level
level: medium
```
