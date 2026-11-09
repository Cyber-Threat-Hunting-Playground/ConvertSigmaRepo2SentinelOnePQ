```sql
// Translated content (automatically translated on 09-11-2026 03:41:38):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/groups" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/ed" or tgt.process.image.path contains "/emacs" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/makemap" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/sqlite3" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/vi" or tgt.process.image.path contains "/vim") and (tgt.process.cmdline contains "group" or tgt.process.cmdline contains "gshadow")) or (tgt.process.image.path contains "/getent" and (tgt.process.cmdline contains " group" or tgt.process.cmdline contains " gshadow")) or (tgt.process.image.path contains "/ypcat" and tgt.process.cmdline contains "group")))
```


# Original Sigma Rule:
```yaml
title: Local Groups Discovery Attempt - Linux
id: 676381a6-15ca-4d73-a9c8-6a22e970b90d
status: test
description: |
    Detects attempts to enumerate local groups and group membership via common Linux utilities and sensitive file access.
    Adversaries may read files such as /etc/group and /etc/gshadow, or use tools like getent and groups to identify
    group memberships and privilege assignments on a compromised system.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md
    - https://man7.org/linux/man-pages/man1/getent.1.html
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-10-11
modified: 2026-11-03
tags:
    - attack.discovery
    - attack.t1069.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_groups:
        Image|endswith: '/groups'
    selection_read_utilities:
        Image|endswith:
            - '/cat'
            - '/ed'
            - '/emacs'
            - '/head'
            - '/less'
            - '/makemap'
            - '/more'
            - '/nano'
            - '/sqlite3'
            - '/tail'
            - '/vi'
            - '/vim'
        CommandLine|contains:
            - 'group'
            - 'gshadow'
    selection_getent:
        Image|endswith: '/getent'
        CommandLine|contains:
            - ' group'
            - ' gshadow'
    selection_ypcat:
        Image|endswith: '/ypcat'
        CommandLine|contains: 'group'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: low
```
