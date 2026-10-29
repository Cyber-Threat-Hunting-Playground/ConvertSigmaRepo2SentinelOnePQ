```sql
// Translated content (automatically translated on 29-10-2026 03:21:48):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.netbird.io" or url.address contains ".api.netbird.io." or url.address contains ".app.netbird.io" or url.address contains ".app.netbird.io." or url.address contains ".login.netbird.io" or url.address contains ".login.netbird.io." or url.address contains ".netbird.io" or url.address contains ".netbird.io." or url.address contains ".pkgs.netbird.io" or url.address contains ".pkgs.netbird.io." or url.address contains ".relay.netbird.io" or url.address contains ".relay.netbird.io." or url.address contains ".signal.netbird.io" or url.address contains ".signal.netbird.io." or url.address="api.netbird.io" or url.address="api.netbird.io." or url.address="app.netbird.io" or url.address="app.netbird.io." or url.address="login.netbird.io" or url.address="login.netbird.io." or url.address="netbird.io" or url.address="netbird.io." or url.address="pkgs.netbird.io" or url.address="pkgs.netbird.io." or url.address="relay.netbird.io" or url.address="relay.netbird.io." or url.address="signal.netbird.io" or url.address="signal.netbird.io." or url.address contains ".cloud-233f9.firebaseapp.com" or url.address contains ".cloud-233f9.firebaseapp.com." or url.address contains ".cloud-ed980.firebaseapp.com" or url.address contains ".cloud-ed980.firebaseapp.com." or url.address contains ".googl-165a0.web.app" or url.address contains ".googl-165a0.web.app." or url.address contains ".googl-6c11f.firebaseapp.com" or url.address contains ".googl-6c11f.firebaseapp.com." or url.address contains ".googl-6c11f.web.app" or url.address contains ".googl-6c11f.web.app." or url.address contains ".my-sharepoint-inc.com" or url.address contains ".my-sharepoint-inc.com." or url.address contains ".my1cloudlive.com" or url.address contains ".my1cloudlive.com." or url.address contains ".my2cloudlive.com" or url.address contains ".my2cloudlive.com." or url.address contains ".web-16fe.app" or url.address contains ".web-16fe.app." or url.address="cloud-233f9.firebaseapp.com" or url.address="cloud-233f9.firebaseapp.com." or url.address="cloud-ed980.firebaseapp.com" or url.address="cloud-ed980.firebaseapp.com." or url.address="googl-165a0.web.app" or url.address="googl-165a0.web.app." or url.address="googl-6c11f.firebaseapp.com" or url.address="googl-6c11f.firebaseapp.com." or url.address="googl-6c11f.web.app" or url.address="googl-6c11f.web.app." or url.address="my-sharepoint-inc.com" or url.address="my-sharepoint-inc.com." or url.address="my1cloudlive.com" or url.address="my1cloudlive.com." or url.address="my2cloudlive.com" or url.address="my2cloudlive.com." or url.address="web-16fe.app" or url.address="web-16fe.app.") or (event.dns.request contains ".api.netbird.io" or event.dns.request contains ".api.netbird.io." or event.dns.request contains ".app.netbird.io" or event.dns.request contains ".app.netbird.io." or event.dns.request contains ".login.netbird.io" or event.dns.request contains ".login.netbird.io." or event.dns.request contains ".netbird.io" or event.dns.request contains ".netbird.io." or event.dns.request contains ".pkgs.netbird.io" or event.dns.request contains ".pkgs.netbird.io." or event.dns.request contains ".relay.netbird.io" or event.dns.request contains ".relay.netbird.io." or event.dns.request contains ".signal.netbird.io" or event.dns.request contains ".signal.netbird.io." or event.dns.request="api.netbird.io" or event.dns.request="api.netbird.io." or event.dns.request="app.netbird.io" or event.dns.request="app.netbird.io." or event.dns.request="login.netbird.io" or event.dns.request="login.netbird.io." or event.dns.request="netbird.io" or event.dns.request="netbird.io." or event.dns.request="pkgs.netbird.io" or event.dns.request="pkgs.netbird.io." or event.dns.request="relay.netbird.io" or event.dns.request="relay.netbird.io." or event.dns.request="signal.netbird.io" or event.dns.request="signal.netbird.io." or event.dns.request contains ".cloud-233f9.firebaseapp.com" or event.dns.request contains ".cloud-233f9.firebaseapp.com." or event.dns.request contains ".cloud-ed980.firebaseapp.com" or event.dns.request contains ".cloud-ed980.firebaseapp.com." or event.dns.request contains ".googl-165a0.web.app" or event.dns.request contains ".googl-165a0.web.app." or event.dns.request contains ".googl-6c11f.firebaseapp.com" or event.dns.request contains ".googl-6c11f.firebaseapp.com." or event.dns.request contains ".googl-6c11f.web.app" or event.dns.request contains ".googl-6c11f.web.app." or event.dns.request contains ".my-sharepoint-inc.com" or event.dns.request contains ".my-sharepoint-inc.com." or event.dns.request contains ".my1cloudlive.com" or event.dns.request contains ".my1cloudlive.com." or event.dns.request contains ".my2cloudlive.com" or event.dns.request contains ".my2cloudlive.com." or event.dns.request contains ".web-16fe.app" or event.dns.request contains ".web-16fe.app." or event.dns.request="cloud-233f9.firebaseapp.com" or event.dns.request="cloud-233f9.firebaseapp.com." or event.dns.request="cloud-ed980.firebaseapp.com" or event.dns.request="cloud-ed980.firebaseapp.com." or event.dns.request="googl-165a0.web.app" or event.dns.request="googl-165a0.web.app." or event.dns.request="googl-6c11f.firebaseapp.com" or event.dns.request="googl-6c11f.firebaseapp.com." or event.dns.request="googl-6c11f.web.app" or event.dns.request="googl-6c11f.web.app." or event.dns.request="my-sharepoint-inc.com" or event.dns.request="my-sharepoint-inc.com." or event.dns.request="my1cloudlive.com" or event.dns.request="my1cloudlive.com." or event.dns.request="my2cloudlive.com" or event.dns.request="my2cloudlive.com." or event.dns.request="web-16fe.app" or event.dns.request="web-16fe.app.")))
```


# Original Sigma Rule:
```yaml
title: Potential NetBird RMM Tool Network Activity
id: b185f048-8668-5dba-a8fa-09e8d9fd2097
status: experimental
description: |
    Detects potential network activity of NetBird RMM tool
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
            - '*.api.netbird.io'
            - '*.api.netbird.io.'
            - '*.app.netbird.io'
            - '*.app.netbird.io.'
            - '*.login.netbird.io'
            - '*.login.netbird.io.'
            - '*.netbird.io'
            - '*.netbird.io.'
            - '*.pkgs.netbird.io'
            - '*.pkgs.netbird.io.'
            - '*.relay.netbird.io'
            - '*.relay.netbird.io.'
            - '*.signal.netbird.io'
            - '*.signal.netbird.io.'
            - 'api.netbird.io'
            - 'api.netbird.io.'
            - 'app.netbird.io'
            - 'app.netbird.io.'
            - 'login.netbird.io'
            - 'login.netbird.io.'
            - 'netbird.io'
            - 'netbird.io.'
            - 'pkgs.netbird.io'
            - 'pkgs.netbird.io.'
            - 'relay.netbird.io'
            - 'relay.netbird.io.'
            - 'signal.netbird.io'
            - 'signal.netbird.io.'
            - '*.cloud-233f9.firebaseapp.com'
            - '*.cloud-233f9.firebaseapp.com.'
            - '*.cloud-ed980.firebaseapp.com'
            - '*.cloud-ed980.firebaseapp.com.'
            - '*.googl-165a0.web.app'
            - '*.googl-165a0.web.app.'
            - '*.googl-6c11f.firebaseapp.com'
            - '*.googl-6c11f.firebaseapp.com.'
            - '*.googl-6c11f.web.app'
            - '*.googl-6c11f.web.app.'
            - '*.my-sharepoint-inc.com'
            - '*.my-sharepoint-inc.com.'
            - '*.my1cloudlive.com'
            - '*.my1cloudlive.com.'
            - '*.my2cloudlive.com'
            - '*.my2cloudlive.com.'
            - '*.web-16fe.app'
            - '*.web-16fe.app.'
            - 'cloud-233f9.firebaseapp.com'
            - 'cloud-233f9.firebaseapp.com.'
            - 'cloud-ed980.firebaseapp.com'
            - 'cloud-ed980.firebaseapp.com.'
            - 'googl-165a0.web.app'
            - 'googl-165a0.web.app.'
            - 'googl-6c11f.firebaseapp.com'
            - 'googl-6c11f.firebaseapp.com.'
            - 'googl-6c11f.web.app'
            - 'googl-6c11f.web.app.'
            - 'my-sharepoint-inc.com'
            - 'my-sharepoint-inc.com.'
            - 'my1cloudlive.com'
            - 'my1cloudlive.com.'
            - 'my2cloudlive.com'
            - 'my2cloudlive.com.'
            - 'web-16fe.app'
            - 'web-16fe.app.'
    condition: selection
falsepositives:
    - Legitimate use of NetBird
level: medium
```
