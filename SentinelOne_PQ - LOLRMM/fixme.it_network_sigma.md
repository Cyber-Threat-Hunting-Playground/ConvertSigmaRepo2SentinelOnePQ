```sql
// Translated content (automatically translated on 29-06-2026 02:28:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fixme.it" or url.address contains ".techinline.net" or url.address contains "fixme.it" or url.address contains "set.me" or url.address contains ".set.me" or url.address contains "setme.net" or url.address contains ".setme.net") or (event.dns.request contains ".fixme.it" or event.dns.request contains ".techinline.net" or event.dns.request contains "fixme.it" or event.dns.request contains "set.me" or event.dns.request contains ".set.me" or event.dns.request contains "setme.net" or event.dns.request contains ".setme.net")))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe.it RMM Tool Network Activity
id: 5546797c-7d0f-4799-8252-b3c155a6d042
status: experimental
description: |
    Detects potential network activity of FixMe.it RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.fixme.it'
            - '*.techinline.net'
            - 'fixme.it'
            - 'set.me'
            - '*.set.me'
            - 'setme.net'
            - '*.setme.net'
    condition: selection
falsepositives:
    - Legitimate use of FixMe.it
level: medium
```
