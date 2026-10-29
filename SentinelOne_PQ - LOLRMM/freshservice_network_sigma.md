```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fstools.freshservice.com" or url.address contains ".fstools.freshservice.com." or url.address="fstools.freshservice.com" or url.address="fstools.freshservice.com." or url.address contains ".freshservice.com" or url.address contains ".freshservice.com." or url.address contains ".www.freshservice.com" or url.address contains ".www.freshservice.com." or url.address="freshservice.com" or url.address="freshservice.com." or url.address="www.freshservice.com" or url.address="www.freshservice.com." or url.address contains ".freshasset.com" or url.address contains ".freshasset.com." or url.address contains ".fstools.freshasset.com" or url.address contains ".fstools.freshasset.com." or url.address="freshasset.com" or url.address="freshasset.com." or url.address="fstools.freshasset.com" or url.address="fstools.freshasset.com." or url.address contains ".freshworks.com" or url.address contains ".freshworks.com." or url.address contains ".freshworksapi.com" or url.address contains ".freshworksapi.com." or url.address contains ".myfreshworks.com" or url.address contains ".myfreshworks.com." or url.address contains ".api.fdcollab.com" or url.address contains ".api.fdcollab.com." or url.address contains ".fdcollab.com" or url.address contains ".fdcollab.com." or url.address contains ".freshconnect.io" or url.address contains ".freshconnect.io." or url.address="api.fdcollab.com" or url.address="api.fdcollab.com." or url.address contains ".apicdn-wchat.freshchat.com" or url.address contains ".apicdn-wchat.freshchat.com." or url.address contains ".freshchat.com" or url.address contains ".freshchat.com." or url.address contains ".rtschannel.com" or url.address contains ".rtschannel.com." or url.address contains ".webpush.freshchat.com" or url.address contains ".webpush.freshchat.com." or url.address="apicdn-wchat.freshchat.com" or url.address="apicdn-wchat.freshchat.com." or url.address contains ".freshcloud.io" or url.address contains ".freshcloud.io." or url.address contains ".freshdev.io" or url.address contains ".freshdev.io." or url.address contains ".in-freshbots.ai" or url.address contains ".in-freshbots.ai." or url.address contains ".static.freshdev.io" or url.address contains ".static.freshdev.io." or url.address="static.freshdev.io" or url.address="static.freshdev.io.") or (event.dns.request contains ".fstools.freshservice.com" or event.dns.request contains ".fstools.freshservice.com." or event.dns.request="fstools.freshservice.com" or event.dns.request="fstools.freshservice.com." or event.dns.request contains ".freshservice.com" or event.dns.request contains ".freshservice.com." or event.dns.request contains ".www.freshservice.com" or event.dns.request contains ".www.freshservice.com." or event.dns.request="freshservice.com" or event.dns.request="freshservice.com." or event.dns.request="www.freshservice.com" or event.dns.request="www.freshservice.com." or event.dns.request contains ".freshasset.com" or event.dns.request contains ".freshasset.com." or event.dns.request contains ".fstools.freshasset.com" or event.dns.request contains ".fstools.freshasset.com." or event.dns.request="freshasset.com" or event.dns.request="freshasset.com." or event.dns.request="fstools.freshasset.com" or event.dns.request="fstools.freshasset.com." or event.dns.request contains ".freshworks.com" or event.dns.request contains ".freshworks.com." or event.dns.request contains ".freshworksapi.com" or event.dns.request contains ".freshworksapi.com." or event.dns.request contains ".myfreshworks.com" or event.dns.request contains ".myfreshworks.com." or event.dns.request contains ".api.fdcollab.com" or event.dns.request contains ".api.fdcollab.com." or event.dns.request contains ".fdcollab.com" or event.dns.request contains ".fdcollab.com." or event.dns.request contains ".freshconnect.io" or event.dns.request contains ".freshconnect.io." or event.dns.request="api.fdcollab.com" or event.dns.request="api.fdcollab.com." or event.dns.request contains ".apicdn-wchat.freshchat.com" or event.dns.request contains ".apicdn-wchat.freshchat.com." or event.dns.request contains ".freshchat.com" or event.dns.request contains ".freshchat.com." or event.dns.request contains ".rtschannel.com" or event.dns.request contains ".rtschannel.com." or event.dns.request contains ".webpush.freshchat.com" or event.dns.request contains ".webpush.freshchat.com." or event.dns.request="apicdn-wchat.freshchat.com" or event.dns.request="apicdn-wchat.freshchat.com." or event.dns.request contains ".freshcloud.io" or event.dns.request contains ".freshcloud.io." or event.dns.request contains ".freshdev.io" or event.dns.request contains ".freshdev.io." or event.dns.request contains ".in-freshbots.ai" or event.dns.request contains ".in-freshbots.ai." or event.dns.request contains ".static.freshdev.io" or event.dns.request contains ".static.freshdev.io." or event.dns.request="static.freshdev.io" or event.dns.request="static.freshdev.io.")))
```


# Original Sigma Rule:
```yaml
title: Potential Freshservice RMM Tool Network Activity
id: 759d870d-2a70-59bd-875c-ff1dfb85574a
status: experimental
description: |
    Detects potential network activity of Freshservice RMM tool
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
            - '*.fstools.freshservice.com'
            - '*.fstools.freshservice.com.'
            - 'fstools.freshservice.com'
            - 'fstools.freshservice.com.'
            - '*.freshservice.com'
            - '*.freshservice.com.'
            - '*.www.freshservice.com'
            - '*.www.freshservice.com.'
            - 'freshservice.com'
            - 'freshservice.com.'
            - 'www.freshservice.com'
            - 'www.freshservice.com.'
            - '*.freshasset.com'
            - '*.freshasset.com.'
            - '*.fstools.freshasset.com'
            - '*.fstools.freshasset.com.'
            - 'freshasset.com'
            - 'freshasset.com.'
            - 'fstools.freshasset.com'
            - 'fstools.freshasset.com.'
            - '*.freshworks.com'
            - '*.freshworks.com.'
            - '*.freshworksapi.com'
            - '*.freshworksapi.com.'
            - '*.myfreshworks.com'
            - '*.myfreshworks.com.'
            - '*.api.fdcollab.com'
            - '*.api.fdcollab.com.'
            - '*.fdcollab.com'
            - '*.fdcollab.com.'
            - '*.freshconnect.io'
            - '*.freshconnect.io.'
            - 'api.fdcollab.com'
            - 'api.fdcollab.com.'
            - '*.apicdn-wchat.freshchat.com'
            - '*.apicdn-wchat.freshchat.com.'
            - '*.freshchat.com'
            - '*.freshchat.com.'
            - '*.rtschannel.com'
            - '*.rtschannel.com.'
            - '*.webpush.freshchat.com'
            - '*.webpush.freshchat.com.'
            - 'apicdn-wchat.freshchat.com'
            - 'apicdn-wchat.freshchat.com.'
            - '*.freshcloud.io'
            - '*.freshcloud.io.'
            - '*.freshdev.io'
            - '*.freshdev.io.'
            - '*.in-freshbots.ai'
            - '*.in-freshbots.ai.'
            - '*.static.freshdev.io'
            - '*.static.freshdev.io.'
            - 'static.freshdev.io'
            - 'static.freshdev.io.'
    condition: selection
falsepositives:
    - Legitimate use of Freshservice
level: medium
```
