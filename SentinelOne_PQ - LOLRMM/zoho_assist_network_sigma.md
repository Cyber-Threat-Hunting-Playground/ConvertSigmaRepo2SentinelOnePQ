```sql
// Translated content (automatically translated on 31-10-2026 03:08:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".assist.zoho.com" or url.address contains ".assist.zoho.com." or url.address contains ".downloads.zohocdn.com" or url.address contains ".downloads.zohocdn.com." or url.address contains ".downloads.zohodl.com.cn" or url.address contains ".downloads.zohodl.com.cn." or url.address contains ".gateway.zohoassist.com" or url.address contains ".gateway.zohoassist.com." or url.address contains ".zoho.com" or url.address contains ".zoho.com." or url.address contains ".zoho.com.au" or url.address contains ".zoho.com.au." or url.address contains ".zoho.com.cn" or url.address contains ".zoho.com.cn." or url.address contains ".zoho.eu" or url.address contains ".zoho.eu." or url.address contains ".zoho.in" or url.address contains ".zoho.in." or url.address contains ".zohoassist.com" or url.address contains ".zohoassist.com." or url.address contains ".zohoassist.com.cn" or url.address contains ".zohoassist.com.cn." or url.address contains ".zohoassist.jp" or url.address contains ".zohoassist.jp." or url.address="assist.zoho.com" or url.address="assist.zoho.com." or url.address="downloads.zohocdn.com" or url.address="downloads.zohocdn.com." or url.address="downloads.zohodl.com.cn" or url.address="downloads.zohodl.com.cn." or url.address="gateway.zohoassist.com" or url.address="gateway.zohoassist.com.") or (event.dns.request contains ".assist.zoho.com" or event.dns.request contains ".assist.zoho.com." or event.dns.request contains ".downloads.zohocdn.com" or event.dns.request contains ".downloads.zohocdn.com." or event.dns.request contains ".downloads.zohodl.com.cn" or event.dns.request contains ".downloads.zohodl.com.cn." or event.dns.request contains ".gateway.zohoassist.com" or event.dns.request contains ".gateway.zohoassist.com." or event.dns.request contains ".zoho.com" or event.dns.request contains ".zoho.com." or event.dns.request contains ".zoho.com.au" or event.dns.request contains ".zoho.com.au." or event.dns.request contains ".zoho.com.cn" or event.dns.request contains ".zoho.com.cn." or event.dns.request contains ".zoho.eu" or event.dns.request contains ".zoho.eu." or event.dns.request contains ".zoho.in" or event.dns.request contains ".zoho.in." or event.dns.request contains ".zohoassist.com" or event.dns.request contains ".zohoassist.com." or event.dns.request contains ".zohoassist.com.cn" or event.dns.request contains ".zohoassist.com.cn." or event.dns.request contains ".zohoassist.jp" or event.dns.request contains ".zohoassist.jp." or event.dns.request="assist.zoho.com" or event.dns.request="assist.zoho.com." or event.dns.request="downloads.zohocdn.com" or event.dns.request="downloads.zohocdn.com." or event.dns.request="downloads.zohodl.com.cn" or event.dns.request="downloads.zohodl.com.cn." or event.dns.request="gateway.zohoassist.com" or event.dns.request="gateway.zohoassist.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential Zoho Assist RMM Tool Network Activity
id: 3ae241e0-ab8f-4e0a-8d6b-02f6687866cd
status: experimental
description: |
    Detects potential network activity of Zoho Assist RMM tool
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
            - '*.assist.zoho.com'
            - '*.assist.zoho.com.'
            - '*.downloads.zohocdn.com'
            - '*.downloads.zohocdn.com.'
            - '*.downloads.zohodl.com.cn'
            - '*.downloads.zohodl.com.cn.'
            - '*.gateway.zohoassist.com'
            - '*.gateway.zohoassist.com.'
            - '*.zoho.com'
            - '*.zoho.com.'
            - '*.zoho.com.au'
            - '*.zoho.com.au.'
            - '*.zoho.com.cn'
            - '*.zoho.com.cn.'
            - '*.zoho.eu'
            - '*.zoho.eu.'
            - '*.zoho.in'
            - '*.zoho.in.'
            - '*.zohoassist.com'
            - '*.zohoassist.com.'
            - '*.zohoassist.com.cn'
            - '*.zohoassist.com.cn.'
            - '*.zohoassist.jp'
            - '*.zohoassist.jp.'
            - 'assist.zoho.com'
            - 'assist.zoho.com.'
            - 'downloads.zohocdn.com'
            - 'downloads.zohocdn.com.'
            - 'downloads.zohodl.com.cn'
            - 'downloads.zohodl.com.cn.'
            - 'gateway.zohoassist.com'
            - 'gateway.zohoassist.com.'
    condition: selection
falsepositives:
    - Legitimate use of Zoho Assist
level: medium
```
