```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".iperius-rs.com" or url.address contains ".iperius-rs.com." or url.address contains ".iperius.com" or url.address contains ".iperius.com." or url.address contains ".iperiusremote.com" or url.address contains ".iperiusremote.com." or url.address="iperiusremote.com" or url.address="iperiusremote.com.") or (event.dns.request contains ".iperius-rs.com" or event.dns.request contains ".iperius-rs.com." or event.dns.request contains ".iperius.com" or event.dns.request contains ".iperius.com." or event.dns.request contains ".iperiusremote.com" or event.dns.request contains ".iperiusremote.com." or event.dns.request="iperiusremote.com" or event.dns.request="iperiusremote.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Iperius Remote RMM Tool Network Activity
id: ae72a6f3-4916-4519-89e7-f372c5626a87
status: experimental
description: |
    Detects potential network activity of Iperius Remote RMM tool
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
            - '*.iperius-rs.com'
            - '*.iperius-rs.com.'
            - '*.iperius.com'
            - '*.iperius.com.'
            - '*.iperiusremote.com'
            - '*.iperiusremote.com.'
            - 'iperiusremote.com'
            - 'iperiusremote.com.'
    condition: selection
falsepositives:
    - Legitimate use of Iperius Remote
level: medium
```
