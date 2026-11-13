```sql
// Translated content (automatically translated on 13-11-2026 04:06:52):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/lastlog" or tgt.process.image.path contains "/last" or tgt.process.image.path contains "/lastb") or tgt.process.cmdline contains "x:0:" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/ed" or tgt.process.image.path contains "/emacs" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/makemap" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/sqlite3" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/vi" or tgt.process.image.path contains "/vim") and (tgt.process.cmdline contains "/etc/passwd" or tgt.process.cmdline contains "/etc/shadow" or tgt.process.cmdline contains "/etc/sudoers" or tgt.process.cmdline contains "master.passwd" or tgt.process.cmdline contains "pwd.db")) or tgt.process.image.path contains "/id" or (tgt.process.image.path contains "/lsof" and tgt.process.cmdline contains "-u") or (tgt.process.image.path contains "/getent" and (tgt.process.cmdline contains " passwd" or tgt.process.cmdline contains " shadow")) or (tgt.process.image.path contains "/finger" or tgt.process.image.path contains "/users" or tgt.process.image.path contains "/w" or tgt.process.image.path contains "/who") or (tgt.process.image.path contains "/ypcat" and tgt.process.cmdline contains "passwd")) and (not (src.process.cmdline contains "/usr/bin/landscape-sysinfo" and tgt.process.image.path contains "/who"))))
```


# Original Sigma Rule:
```yaml
title: Local System Accounts Discovery Attempt - Linux
id: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
status: test
description: |
    Detects attempts to enumerate local user accounts via common Linux utilities and sensitive file access.
    Adversaries may read files such as /etc/passwd, /etc/shadow, and /etc/sudoers, or use tools like getent,
    id, who, and finger to identify accounts and privilege levels on a compromised system.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
    - https://my.f5.com/manage/s/article/K589
    - https://man.freebsd.org/cgi/man.cgi?pwd_mkdb
    - https://man7.org/linux/man-pages/man1/getent.1.html
    - https://linux.die.net/man/1/finger
author: Alejandro Ortuno, oscd.community, CheraghiMilad
date: 2020-10-08
modified: 2026-11-03
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_lastlog:
        Image|endswith:
            - '/lastlog'
            - '/last'
            - '/lastb'
    selection_root_string:
        CommandLine|contains: 'x:0:'
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
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
            - 'master.passwd'
            - 'pwd.db'
    selection_id:
        Image|endswith: '/id'
    selection_lsof:
        Image|endswith: '/lsof'
        CommandLine|contains: '-u'
    selection_getent:
        Image|endswith: '/getent'
        CommandLine|contains:
            - ' passwd'
            - ' shadow'
    selection_who:
        Image|endswith:
            - '/finger'
            - '/users'
            - '/w'
            - '/who'
    selection_ypcat:
        Image|endswith: '/ypcat'
        CommandLine|contains: 'passwd'
    filter_optional_landscape_sysinfo:
        ParentCommandLine|contains: '/usr/bin/landscape-sysinfo'
        Image|endswith: '/who'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate administration activities
level: low
```
