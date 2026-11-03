#CTF 

Event Viewer Command Prompt Registry Editor BTL1 T1562.001
# Context
Microsoft Defender Antivirus has been there for over a decade now. It provides security against known threats until it has not been tampered with. However, it is not easy to tamper as admin privilege will be required to do so. But the logs can be used as footprints to investigate in case of a compromise.
# Questions
Q1) What is the ‘Log Path’ for Windows Defender logs? (Format: log\path\directory\file.evtx) _(4 points)_
```shell
%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx
# Default paths for defender logs weren't being accepted
# had to navigate to the actual windows defender file itself and see properties in operational
```
Q2) What are the extensions excluded in Windows Defender? (Format: extension1, extension2) _(4 points)_
```shell
.bat,.ps1
# The attacker may have excluded these so they don't get scanned.
```
> [!warning] Extensions excluded from Defender AV
> When a file extension is excluded from [Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview), ==the security program completely skips scanning any file ending with that specific file type anywhere on your computer==
>
 > The key is located at:
 > HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions


 Q3) What is the excluded directory, when was the event logged? (Format: drive:\path\directory, M/DD/YYYY h:mm:ss am/pm) (4 points) 
```shell
C:\Windows\Temp, 07/16/2021 7:11:53
# EventID 5007 corresponded to changes in the config file.
```
> [!info] MS defender EventID lists
> https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#microsoft-defender-antivirus-event-ids
![[Pasted image 20261103112743.png]]
Q4) Is controlled folder access enabled? What mode is it in? (Format: XxxxxXxxx) _(4 points)_
```shell
AuditMode
# Checke
```
Q5) What is the symbolic name for the Event ID 5001? (Format: symbolic_name) _(4 points)_
```shell
MALWAREPROTECTION_RTP_DISABLED
# 
```

Q7) What registry key is modified when script scanning is disabled for Microsoft Defender Antivirus? (Format: path\to\registry) _(5 points)_
```shell
SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
# This is the actual registry key. It wouldn't accept `computer\HKLM\....`
```

Q10) What is the processID and ThreadID that disabled IOAV protection in Microsoft Defender Antivirus? (Format: processID, threadID) _(5 points)_
```shell
7072, 6948

```
# ScratchPad
# Workflow


| Source(File system, URL History, registry) | Timestamp | Summary |
| ------------------------------------------ | --------- | ------- |
|                                            |           |         |
|                                            |           |         |

| Kill Chain Phase              | Adversary Objective                                                                                                       | CTF Evidence / Attacker Actions |
| :---------------------------- | :------------------------------------------------------------------------------------------------------------------------ | :------------------------------ |
| **1. Reconnaissance**         | Gathering intelligence on the target (e.g., port scanning, directory enumeration, OSINT).                                 | *[Leave blank for notes]*       |
| **2. Weaponization**          | Creating the malicious payload (e.g., packing shellcode, building the Gzip/Base64 dropper).                               | *[Leave blank for notes]*       |
| **3. Delivery**               | Transmitting the weapon to the target (e.g., phishing email, malicious web request, USB).                                 | *[Leave blank for notes]*       |
| **4. Exploitation**           | Triggering the weapon's code on the victim system (e.g., exploiting a vulnerability to execute code).                     | *[Leave blank for notes]*       |
| **5. Installation**           | Establishing persistence on the victim system (e.g., scheduled tasks, registry run keys, dropping secondary executables). | *[Leave blank for notes]*       |
| **6. Command & Control (C2)** | Opening a two-way communication channel for remote manipulation (e.g., beaconing out to an external IP).                  | *[Leave blank for notes]*       |
| **7. Actions on Objectives**  | Achieving the ultimate goal (e.g., data exfiltration, ransomware encryption, lateral movement).                           | *[Leave blank for notes]*       |


# Big learning curves
