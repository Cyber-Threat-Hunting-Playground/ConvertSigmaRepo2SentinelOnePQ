```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rdviewer.oss-cn-hangzhou.aliyuncs.com" or url.address contains ".rdviewer.oss-cn-hangzhou.aliyuncs.com." or url.address="rdviewer.oss-cn-hangzhou.aliyuncs.com" or url.address="rdviewer.oss-cn-hangzhou.aliyuncs.com.") or (event.dns.request contains ".rdviewer.oss-cn-hangzhou.aliyuncs.com" or event.dns.request contains ".rdviewer.oss-cn-hangzhou.aliyuncs.com." or event.dns.request="rdviewer.oss-cn-hangzhou.aliyuncs.com" or event.dns.request="rdviewer.oss-cn-hangzhou.aliyuncs.com.")))
```


# Original Sigma Rule:
```yaml
title: Potential RdViewer RMM Tool Network Activity
id: 1db95471-9fd9-5ded-8d8c-0a5eb4574084
status: experimental
description: |
    Detects potential network activity of RdViewer RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-10-28
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname:
            - '*.rdviewer.oss-cn-hangzhou.aliyuncs.com'
            - '*.rdviewer.oss-cn-hangzhou.aliyuncs.com.'
            - 'rdviewer.oss-cn-hangzhou.aliyuncs.com'
            - 'rdviewer.oss-cn-hangzhou.aliyuncs.com.'
    condition: selection
falsepositives:
    - Legitimate use of RdViewer
level: medium
```
