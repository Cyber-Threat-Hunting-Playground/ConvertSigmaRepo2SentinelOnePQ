```sql
// Translated content (automatically translated on 07-06-2026 02:30:44):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "github.com" or url.address contains "raw.githubusercontent.com" or url.address contains "ghcr.io" or url.address contains "komari-document.pages.dev" or url.address contains "www.komari.wiki" or url.address contains "raw.githubusercontent.com") or (event.dns.request contains "github.com" or event.dns.request contains "raw.githubusercontent.com" or event.dns.request contains "ghcr.io" or event.dns.request contains "komari-document.pages.dev" or event.dns.request contains "www.komari.wiki" or event.dns.request contains "raw.githubusercontent.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Komari RMM Tool Network Activity
id: 4bc4fbf6-fbfa-53cb-a960-184e2be9c2d1
status: experimental
description: |
    Detects potential network activity of Komari RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'github.com'
            - 'raw.githubusercontent.com'
            - 'ghcr.io'
            - 'komari-document.pages.dev'
            - 'www.komari.wiki'
            - 'raw.githubusercontent.com'
    condition: selection
falsepositives:
    - Legitimate use of Komari
level: medium
```
