```sql
// Translated content (automatically translated on 09-10-2026 03:32:42):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "connect.ngrok-agent.com" or url.address contains "connect.us.ngrok-agent.com" or url.address contains "connect.eu.ngrok-agent.com" or url.address contains "connect.ap.ngrok-agent.com" or url.address contains "connect.au.ngrok-agent.com" or url.address contains "connect.sa.ngrok-agent.com" or url.address contains "connect.jp.ngrok-agent.com" or url.address contains "connect.in.ngrok-agent.com" or url.address contains "ngrok.com" or url.address contains ".ngrok-free.app" or url.address contains ".ngrok.app" or url.address contains ".ngrok.io" or url.address contains ".ngrok.dev" or url.address contains ".ngrok.pro" or url.address contains ".ngrok.pizza") or (event.dns.request contains "connect.ngrok-agent.com" or event.dns.request contains "connect.us.ngrok-agent.com" or event.dns.request contains "connect.eu.ngrok-agent.com" or event.dns.request contains "connect.ap.ngrok-agent.com" or event.dns.request contains "connect.au.ngrok-agent.com" or event.dns.request contains "connect.sa.ngrok-agent.com" or event.dns.request contains "connect.jp.ngrok-agent.com" or event.dns.request contains "connect.in.ngrok-agent.com" or event.dns.request contains "ngrok.com" or event.dns.request contains ".ngrok-free.app" or event.dns.request contains ".ngrok.app" or event.dns.request contains ".ngrok.io" or event.dns.request contains ".ngrok.dev" or event.dns.request contains ".ngrok.pro" or event.dns.request contains ".ngrok.pizza")))
```


# Original Sigma Rule:
```yaml
title: Potential ngrok RMM Tool Network Activity
id: 36b3490a-8cac-4611-bfad-82f3f4c74ad6
status: experimental
description: |
    Detects potential network activity of ngrok RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-10-05
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'connect.ngrok-agent.com'
            - 'connect.us.ngrok-agent.com'
            - 'connect.eu.ngrok-agent.com'
            - 'connect.ap.ngrok-agent.com'
            - 'connect.au.ngrok-agent.com'
            - 'connect.sa.ngrok-agent.com'
            - 'connect.jp.ngrok-agent.com'
            - 'connect.in.ngrok-agent.com'
            - 'ngrok.com'
            - '*.ngrok-free.app'
            - '*.ngrok.app'
            - '*.ngrok.io'
            - '*.ngrok.dev'
            - '*.ngrok.pro'
            - '*.ngrok.pizza'
    condition: selection
falsepositives:
    - Legitimate use of ngrok
level: medium
```
