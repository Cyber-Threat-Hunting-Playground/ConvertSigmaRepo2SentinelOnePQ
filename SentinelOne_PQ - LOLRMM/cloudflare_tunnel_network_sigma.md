```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "._v2-origintunneld._tcp.argotunnel.com" or url.address contains "._v2-origintunneld._tcp.argotunnel.com." or url.address contains ".cftunnel.com" or url.address contains ".cftunnel.com." or url.address contains ".h2.cftunnel.com" or url.address contains ".h2.cftunnel.com." or url.address contains ".quic.cftunnel.com" or url.address contains ".quic.cftunnel.com." or url.address contains ".region1.v2.argotunnel.com" or url.address contains ".region1.v2.argotunnel.com." or url.address contains ".region2.v2.argotunnel.com" or url.address contains ".region2.v2.argotunnel.com." or url.address contains ".us-region1.v2.argotunnel.com" or url.address contains ".us-region1.v2.argotunnel.com." or url.address contains ".us-region2.v2.argotunnel.com" or url.address contains ".us-region2.v2.argotunnel.com." or url.address="_v2-origintunneld._tcp.argotunnel.com" or url.address="_v2-origintunneld._tcp.argotunnel.com." or url.address="cftunnel.com" or url.address="cftunnel.com." or url.address="h2.cftunnel.com" or url.address="h2.cftunnel.com." or url.address="quic.cftunnel.com" or url.address="quic.cftunnel.com." or url.address="region1.v2.argotunnel.com" or url.address="region1.v2.argotunnel.com." or url.address="region2.v2.argotunnel.com" or url.address="region2.v2.argotunnel.com." or url.address="us-region1.v2.argotunnel.com" or url.address="us-region1.v2.argotunnel.com." or url.address="us-region2.v2.argotunnel.com" or url.address="us-region2.v2.argotunnel.com." or url.address contains ".cfargotunnel.com" or url.address contains ".cfargotunnel.com." or url.address contains ".trycloudflare.com" or url.address contains ".trycloudflare.com." or url.address contains ".update.argotunnel.com" or url.address contains ".update.argotunnel.com." or url.address="update.argotunnel.com" or url.address="update.argotunnel.com.") or (event.dns.request contains "._v2-origintunneld._tcp.argotunnel.com" or event.dns.request contains "._v2-origintunneld._tcp.argotunnel.com." or event.dns.request contains ".cftunnel.com" or event.dns.request contains ".cftunnel.com." or event.dns.request contains ".h2.cftunnel.com" or event.dns.request contains ".h2.cftunnel.com." or event.dns.request contains ".quic.cftunnel.com" or event.dns.request contains ".quic.cftunnel.com." or event.dns.request contains ".region1.v2.argotunnel.com" or event.dns.request contains ".region1.v2.argotunnel.com." or event.dns.request contains ".region2.v2.argotunnel.com" or event.dns.request contains ".region2.v2.argotunnel.com." or event.dns.request contains ".us-region1.v2.argotunnel.com" or event.dns.request contains ".us-region1.v2.argotunnel.com." or event.dns.request contains ".us-region2.v2.argotunnel.com" or event.dns.request contains ".us-region2.v2.argotunnel.com." or event.dns.request="_v2-origintunneld._tcp.argotunnel.com" or event.dns.request="_v2-origintunneld._tcp.argotunnel.com." or event.dns.request="cftunnel.com" or event.dns.request="cftunnel.com." or event.dns.request="h2.cftunnel.com" or event.dns.request="h2.cftunnel.com." or event.dns.request="quic.cftunnel.com" or event.dns.request="quic.cftunnel.com." or event.dns.request="region1.v2.argotunnel.com" or event.dns.request="region1.v2.argotunnel.com." or event.dns.request="region2.v2.argotunnel.com" or event.dns.request="region2.v2.argotunnel.com." or event.dns.request="us-region1.v2.argotunnel.com" or event.dns.request="us-region1.v2.argotunnel.com." or event.dns.request="us-region2.v2.argotunnel.com" or event.dns.request="us-region2.v2.argotunnel.com." or event.dns.request contains ".cfargotunnel.com" or event.dns.request contains ".cfargotunnel.com." or event.dns.request contains ".trycloudflare.com" or event.dns.request contains ".trycloudflare.com." or event.dns.request contains ".update.argotunnel.com" or event.dns.request contains ".update.argotunnel.com." or event.dns.request="update.argotunnel.com" or event.dns.request="update.argotunnel.com.")))
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
            - '*._v2-origintunneld._tcp.argotunnel.com'
            - '*._v2-origintunneld._tcp.argotunnel.com.'
            - '*.cftunnel.com'
            - '*.cftunnel.com.'
            - '*.h2.cftunnel.com'
            - '*.h2.cftunnel.com.'
            - '*.quic.cftunnel.com'
            - '*.quic.cftunnel.com.'
            - '*.region1.v2.argotunnel.com'
            - '*.region1.v2.argotunnel.com.'
            - '*.region2.v2.argotunnel.com'
            - '*.region2.v2.argotunnel.com.'
            - '*.us-region1.v2.argotunnel.com'
            - '*.us-region1.v2.argotunnel.com.'
            - '*.us-region2.v2.argotunnel.com'
            - '*.us-region2.v2.argotunnel.com.'
            - '_v2-origintunneld._tcp.argotunnel.com'
            - '_v2-origintunneld._tcp.argotunnel.com.'
            - 'cftunnel.com'
            - 'cftunnel.com.'
            - 'h2.cftunnel.com'
            - 'h2.cftunnel.com.'
            - 'quic.cftunnel.com'
            - 'quic.cftunnel.com.'
            - 'region1.v2.argotunnel.com'
            - 'region1.v2.argotunnel.com.'
            - 'region2.v2.argotunnel.com'
            - 'region2.v2.argotunnel.com.'
            - 'us-region1.v2.argotunnel.com'
            - 'us-region1.v2.argotunnel.com.'
            - 'us-region2.v2.argotunnel.com'
            - 'us-region2.v2.argotunnel.com.'
            - '*.cfargotunnel.com'
            - '*.cfargotunnel.com.'
            - '*.trycloudflare.com'
            - '*.trycloudflare.com.'
            - '*.update.argotunnel.com'
            - '*.update.argotunnel.com.'
            - 'update.argotunnel.com'
            - 'update.argotunnel.com.'
    condition: selection
falsepositives:
    - Legitimate use of CloudFlare Tunnel
level: medium
```
