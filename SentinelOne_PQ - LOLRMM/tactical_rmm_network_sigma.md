```sql
// Translated content (automatically translated on 30-10-2026 03:23:35):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".docs.tacticalrmm.com" or url.address contains ".docs.tacticalrmm.com." or url.address contains ".login.tailscale.com" or url.address contains ".login.tailscale.com." or url.address="docs.tacticalrmm.com" or url.address="docs.tacticalrmm.com." or url.address="login.tailscale.com" or url.address="login.tailscale.com.") or (event.dns.request contains ".docs.tacticalrmm.com" or event.dns.request contains ".docs.tacticalrmm.com." or event.dns.request contains ".login.tailscale.com" or event.dns.request contains ".login.tailscale.com." or event.dns.request="docs.tacticalrmm.com" or event.dns.request="docs.tacticalrmm.com." or event.dns.request="login.tailscale.com" or event.dns.request="login.tailscale.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Tactical RMM RMM Tool Network Activity
id: 1bd55201-587b-4d91-8c96-aac7b71b4086
status: experimental
description: |
    Detects potential network activity of Tactical RMM RMM tool
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
            - '*.docs.tacticalrmm.com'
            - '*.docs.tacticalrmm.com.'
            - '*.login.tailscale.com'
            - '*.login.tailscale.com.'
            - 'docs.tacticalrmm.com'
            - 'docs.tacticalrmm.com.'
            - 'login.tailscale.com'
            - 'login.tailscale.com.'
    condition: selection
falsepositives:
    - Legitimate use of Tactical RMM
level: medium
```
