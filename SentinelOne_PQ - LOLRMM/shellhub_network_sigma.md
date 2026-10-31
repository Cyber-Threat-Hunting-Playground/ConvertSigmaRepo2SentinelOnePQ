```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".cloud.shellhub.io" or url.address contains ".cloud.shellhub.io." or url.address contains ".shellhub.io" or url.address contains ".shellhub.io." or url.address contains ".www.shellhub.io" or url.address contains ".www.shellhub.io." or url.address="cloud.shellhub.io" or url.address="cloud.shellhub.io." or url.address="shellhub.io" or url.address="shellhub.io." or url.address="www.shellhub.io" or url.address="www.shellhub.io.") or (event.dns.request contains ".cloud.shellhub.io" or event.dns.request contains ".cloud.shellhub.io." or event.dns.request contains ".shellhub.io" or event.dns.request contains ".shellhub.io." or event.dns.request contains ".www.shellhub.io" or event.dns.request contains ".www.shellhub.io." or event.dns.request="cloud.shellhub.io" or event.dns.request="cloud.shellhub.io." or event.dns.request="shellhub.io" or event.dns.request="shellhub.io." or event.dns.request="www.shellhub.io" or event.dns.request="www.shellhub.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential ShellHub RMM Tool Network Activity
id: cd489200-7036-55b8-8188-24c1469a8a0a
status: experimental
description: |
    Detects potential network activity of ShellHub RMM tool
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
            - '*.cloud.shellhub.io'
            - '*.cloud.shellhub.io.'
            - '*.shellhub.io'
            - '*.shellhub.io.'
            - '*.www.shellhub.io'
            - '*.www.shellhub.io.'
            - 'cloud.shellhub.io'
            - 'cloud.shellhub.io.'
            - 'shellhub.io'
            - 'shellhub.io.'
            - 'www.shellhub.io'
            - 'www.shellhub.io.'
    condition: selection
falsepositives:
    - Legitimate use of ShellHub
level: medium
```
