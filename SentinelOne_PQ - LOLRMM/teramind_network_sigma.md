```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".teramind.co" or url.address contains ".teramind.co." or url.address contains ".www.teramind.co" or url.address contains ".www.teramind.co." or url.address="teramind.co" or url.address="teramind.co." or url.address="www.teramind.co" or url.address="www.teramind.co." or url.address contains ".rt.teramind.co" or url.address contains ".rt.teramind.co." or url.address="rt.teramind.co" or url.address="rt.teramind.co." or url.address contains ".sentry.dev.teramind.co" or url.address contains ".sentry.dev.teramind.co." or url.address="sentry.dev.teramind.co" or url.address="sentry.dev.teramind.co.") or (event.dns.request contains ".teramind.co" or event.dns.request contains ".teramind.co." or event.dns.request contains ".www.teramind.co" or event.dns.request contains ".www.teramind.co." or event.dns.request="teramind.co" or event.dns.request="teramind.co." or event.dns.request="www.teramind.co" or event.dns.request="www.teramind.co." or event.dns.request contains ".rt.teramind.co" or event.dns.request contains ".rt.teramind.co." or event.dns.request="rt.teramind.co" or event.dns.request="rt.teramind.co." or event.dns.request contains ".sentry.dev.teramind.co" or event.dns.request contains ".sentry.dev.teramind.co." or event.dns.request="sentry.dev.teramind.co" or event.dns.request="sentry.dev.teramind.co.")))
```


# Original Sigma Rule:
```yaml
title: Potential Teramind RMM Tool Network Activity
id: 6eeb9f4e-b360-5446-8544-aea7b7e0721e
status: experimental
description: |
    Detects potential network activity of Teramind RMM tool
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
            - '*.teramind.co'
            - '*.teramind.co.'
            - '*.www.teramind.co'
            - '*.www.teramind.co.'
            - 'teramind.co'
            - 'teramind.co.'
            - 'www.teramind.co'
            - 'www.teramind.co.'
            - '*.rt.teramind.co'
            - '*.rt.teramind.co.'
            - 'rt.teramind.co'
            - 'rt.teramind.co.'
            - '*.sentry.dev.teramind.co'
            - '*.sentry.dev.teramind.co.'
            - 'sentry.dev.teramind.co'
            - 'sentry.dev.teramind.co.'
    condition: selection
falsepositives:
    - Legitimate use of Teramind
level: medium
```
