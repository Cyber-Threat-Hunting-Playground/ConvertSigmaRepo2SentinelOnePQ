```sql
// Translated content (automatically translated on 09-10-2026 03:32:42):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ngrok-free.app" or url.address contains ".ngrok.app" or url.address contains ".ngrok.io" or url.address contains ".ngrok.com" or url.address contains "pandoramods.top" or url.address contains "savaliyapriyal874-code.github.io") or (event.dns.request contains ".ngrok-free.app" or event.dns.request contains ".ngrok.app" or event.dns.request contains ".ngrok.io" or event.dns.request contains ".ngrok.com" or event.dns.request contains "pandoramods.top" or event.dns.request contains "savaliyapriyal874-code.github.io")))
```


# Original Sigma Rule:
```yaml
title: Potential Overlord RMM Tool Network Activity
id: eff8029d-8a19-59fa-b6d1-e0d62a6458ef
status: experimental
description: |
    Detects potential network activity of Overlord RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.ngrok-free.app'
            - '*.ngrok.app'
            - '*.ngrok.io'
            - '*.ngrok.com'
            - 'pandoramods.top'
            - 'savaliyapriyal874-code.github.io'
    condition: selection
falsepositives:
    - Legitimate use of Overlord
level: medium
```
