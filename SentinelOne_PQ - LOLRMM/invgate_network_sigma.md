```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".invgate.com" or url.address contains ".invgate.com." or url.address contains ".www.invgate.com" or url.address contains ".www.invgate.com." or url.address="invgate.com" or url.address="invgate.com." or url.address="www.invgate.com" or url.address="www.invgate.com." or url.address contains ".invgate.net" or url.address contains ".invgate.net." or url.address="invgate.net" or url.address="invgate.net." or url.address contains ".lb-insight-001.invgate.net" or url.address contains ".lb-insight-001.invgate.net." or url.address="lb-insight-001.invgate.net" or url.address="lb-insight-001.invgate.net." or url.address contains ".trust-access.invgate.com" or url.address contains ".trust-access.invgate.com." or url.address contains ".trust.invgate.com" or url.address contains ".trust.invgate.com." or url.address="trust-access.invgate.com" or url.address="trust-access.invgate.com." or url.address="trust.invgate.com" or url.address="trust.invgate.com." or url.address contains ".instances-info.invgate.com" or url.address contains ".instances-info.invgate.com." or url.address contains ".instances-list.invgate.com" or url.address contains ".instances-list.invgate.com." or url.address="instances-info.invgate.com" or url.address="instances-info.invgate.com." or url.address="instances-list.invgate.com" or url.address="instances-list.invgate.com." or url.address contains ".docs.invgate.net" or url.address contains ".docs.invgate.net." or url.address contains ".help.invgate.com" or url.address contains ".help.invgate.com." or url.address contains ".releases.invgate.com" or url.address contains ".releases.invgate.com." or url.address="docs.invgate.net" or url.address="docs.invgate.net." or url.address="help.invgate.com" or url.address="help.invgate.com." or url.address="releases.invgate.com" or url.address="releases.invgate.com.") or (event.dns.request contains ".invgate.com" or event.dns.request contains ".invgate.com." or event.dns.request contains ".www.invgate.com" or event.dns.request contains ".www.invgate.com." or event.dns.request="invgate.com" or event.dns.request="invgate.com." or event.dns.request="www.invgate.com" or event.dns.request="www.invgate.com." or event.dns.request contains ".invgate.net" or event.dns.request contains ".invgate.net." or event.dns.request="invgate.net" or event.dns.request="invgate.net." or event.dns.request contains ".lb-insight-001.invgate.net" or event.dns.request contains ".lb-insight-001.invgate.net." or event.dns.request="lb-insight-001.invgate.net" or event.dns.request="lb-insight-001.invgate.net." or event.dns.request contains ".trust-access.invgate.com" or event.dns.request contains ".trust-access.invgate.com." or event.dns.request contains ".trust.invgate.com" or event.dns.request contains ".trust.invgate.com." or event.dns.request="trust-access.invgate.com" or event.dns.request="trust-access.invgate.com." or event.dns.request="trust.invgate.com" or event.dns.request="trust.invgate.com." or event.dns.request contains ".instances-info.invgate.com" or event.dns.request contains ".instances-info.invgate.com." or event.dns.request contains ".instances-list.invgate.com" or event.dns.request contains ".instances-list.invgate.com." or event.dns.request="instances-info.invgate.com" or event.dns.request="instances-info.invgate.com." or event.dns.request="instances-list.invgate.com" or event.dns.request="instances-list.invgate.com." or event.dns.request contains ".docs.invgate.net" or event.dns.request contains ".docs.invgate.net." or event.dns.request contains ".help.invgate.com" or event.dns.request contains ".help.invgate.com." or event.dns.request contains ".releases.invgate.com" or event.dns.request contains ".releases.invgate.com." or event.dns.request="docs.invgate.net" or event.dns.request="docs.invgate.net." or event.dns.request="help.invgate.com" or event.dns.request="help.invgate.com." or event.dns.request="releases.invgate.com" or event.dns.request="releases.invgate.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential InvGate RMM Tool Network Activity
id: ad2f855c-8c85-570a-be35-49110974af92
status: experimental
description: |
    Detects potential network activity of InvGate RMM tool
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
            - '*.invgate.com'
            - '*.invgate.com.'
            - '*.www.invgate.com'
            - '*.www.invgate.com.'
            - 'invgate.com'
            - 'invgate.com.'
            - 'www.invgate.com'
            - 'www.invgate.com.'
            - '*.invgate.net'
            - '*.invgate.net.'
            - 'invgate.net'
            - 'invgate.net.'
            - '*.lb-insight-001.invgate.net'
            - '*.lb-insight-001.invgate.net.'
            - 'lb-insight-001.invgate.net'
            - 'lb-insight-001.invgate.net.'
            - '*.trust-access.invgate.com'
            - '*.trust-access.invgate.com.'
            - '*.trust.invgate.com'
            - '*.trust.invgate.com.'
            - 'trust-access.invgate.com'
            - 'trust-access.invgate.com.'
            - 'trust.invgate.com'
            - 'trust.invgate.com.'
            - '*.instances-info.invgate.com'
            - '*.instances-info.invgate.com.'
            - '*.instances-list.invgate.com'
            - '*.instances-list.invgate.com.'
            - 'instances-info.invgate.com'
            - 'instances-info.invgate.com.'
            - 'instances-list.invgate.com'
            - 'instances-list.invgate.com.'
            - '*.docs.invgate.net'
            - '*.docs.invgate.net.'
            - '*.help.invgate.com'
            - '*.help.invgate.com.'
            - '*.releases.invgate.com'
            - '*.releases.invgate.com.'
            - 'docs.invgate.net'
            - 'docs.invgate.net.'
            - 'help.invgate.com'
            - 'help.invgate.com.'
            - 'releases.invgate.com'
            - 'releases.invgate.com.'
    condition: selection
falsepositives:
    - Legitimate use of InvGate
level: medium
```
