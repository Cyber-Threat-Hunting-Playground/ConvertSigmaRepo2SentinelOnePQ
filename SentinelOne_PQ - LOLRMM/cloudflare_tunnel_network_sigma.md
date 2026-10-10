```sql
// Translated content (automatically translated on 10-10-2026 03:12:59):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "region1.v2.argotunnel.com" or url.address contains "region2.v2.argotunnel.com" or url.address contains "us-region1.v2.argotunnel.com" or url.address contains "us-region2.v2.argotunnel.com" or url.address contains "_v2-origintunneld._tcp.argotunnel.com" or url.address contains "cftunnel.com" or url.address contains "h2.cftunnel.com" or url.address contains "quic.cftunnel.com" or url.address contains ".cfargotunnel.com" or url.address contains ".trycloudflare.com" or url.address contains "update.argotunnel.com" or url.address contains "api.cloudflare.com") or (event.dns.request contains "region1.v2.argotunnel.com" or event.dns.request contains "region2.v2.argotunnel.com" or event.dns.request contains "us-region1.v2.argotunnel.com" or event.dns.request contains "us-region2.v2.argotunnel.com" or event.dns.request contains "_v2-origintunneld._tcp.argotunnel.com" or event.dns.request contains "cftunnel.com" or event.dns.request contains "h2.cftunnel.com" or event.dns.request contains "quic.cftunnel.com" or event.dns.request contains ".cfargotunnel.com" or event.dns.request contains ".trycloudflare.com" or event.dns.request contains "update.argotunnel.com" or event.dns.request contains "api.cloudflare.com")))
```


# Original Sigma Rule:
```yaml
title: Potential CloudFlare Tunnel RMM Tool Network Activity
id: 75494e1e-0ddc-5086-966d-475c6ef35243
status: experimental
description: |
    Detects potential network activity of CloudFlare Tunnel RMM tool
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
            - 'region1.v2.argotunnel.com'
            - 'region2.v2.argotunnel.com'
            - 'us-region1.v2.argotunnel.com'
            - 'us-region2.v2.argotunnel.com'
            - '_v2-origintunneld._tcp.argotunnel.com'
            - 'cftunnel.com'
            - 'h2.cftunnel.com'
            - 'quic.cftunnel.com'
            - '*.cfargotunnel.com'
            - '*.trycloudflare.com'
            - 'update.argotunnel.com'
            - 'api.cloudflare.com'
    condition: selection
falsepositives:
    - Legitimate use of CloudFlare Tunnel
level: medium
```
