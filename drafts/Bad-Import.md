#CTF #MediumCTF #Splunk #Masquerading #TimeStomping
# Context

# Questions
## 1. Which workstation first contact the attacker's command-and-control server? Provide the Workstation, the destination IP, and the destination port _(4 points)_
```shell
 DEV-WKS-01, 142.11.206.73, 8000
# Finally thank fuck 
# Osint looked up the IP addresses and found the malicious one
```
[Service contacting c2 server on the workstation](images/BTLO_BadImport_Prod-c2.png)
## 2. From which working directory did the attacker's first payload execute on the workstation? _(5 points)_
```shell
Same as Question 3
```

## 3. The attacker placed a renamed Windows binary in a non-standard location. What is the actual file? As per description. _(1 points)_
```shell
index=* earliest="03/31/2026:00:45:23" host="DEV-WKS-01" (EventID="4688" OR EventID="1") | sort + UtcTime?
# Had to use the description
# Windows powershell
```
## 4.What is the full path of the script file the attacker dropped on the workstation as the first stage of execution? _(2 points)_
```shell
C:\Users\jcarter\AppData\Local\Temp\6202033.ps1
```

## 5.A persistence mechanism was established by the Attacker? Provide the registry path written, and the value content. _(3 points)_
```shell
index=main Channel="Microsoft-Windows-Sysmon/Operational" EventID=13 User="MERIDIAN\\jcarter"
# Discovered modified run keys.
# HKU\S-1-5-21-1004336348-1177238915-682003330-1001\Software\Microsoft\Windows\CurrentVersion\Run\WindowsTerminalUpdate, C:\ProgramData\.run.bat
```
[Persistence Mechanism in the Runkeys](images/BTLO_BadImport_WKS-persistence-.run.png)
## 6. The attacker collected several files containing user credentials and secrets from the workstation. Provide the file name (in alphabetical order)(Dot file being the first). _(2 points)_
```shell
index=* earliest="03/31/2026:00:45:23" host="DEV-WKS-01" EventID="11" | sort + UtcTime
# .tmp, a, h, k, ld, n
# These are the answers but they don't enter
```
## 7. Attacker then laterally moved to next machine. What is the machine and which account was used? _(3 points)_
```shell
INDEX=* earliest="03/31/2026:00:45:23" host="DEV-WKS-01" EventID=4648
#BUILD-01, svc_jenkinsdeploy
# eventcode 4648 targets logon with explicit credentials
```

## 8.At what date and time did the attacker Logged into the next machine? _(5 points)_
```shell
Same SPL query as question 7
# 2026-04-02, 19:35:48
```
## 9. On the recently compromised host, the attacker planted a file and modified an existing build script in the Jenkins workspace. To lower the suspicion they forged a creation timestamp on one of them, what fake timestamp value was applied? _(2 points)_
```shell
index=* sourcetype=_json host=BUILD-01 EventID=2
| table _time, TargetFilename, CreationUtcTime, PreviousCreationUtcTime, Image
| sort _time
# Shows CreationUtcTime and PreviousUtcCreation time

``` 
## 10.A new file appeared under the customer-portal application's plugins folder. Provide its full path? _(5 points)_
```shell
index=main Computer="BUILD-01.meridian.local" "C:\\\\Jenkins\\\\*\\\\\plugins*"

```
## 11.
```shell
index=* sourcetype=_json EventCode="3" host="BUILD-01" DestinationHostname="SRV-APP-01.meridian.local"
# Used to identify the SMB transfer via robocopy of telemetry.js
```
## 12. The attacker escalated privileges on the production server. Provide the full path of the binary used for the escalation, and the named pipe associated with the abuse. _(5 points)_
```shell

``` 
## 13. The attacker achieved persistence on the production server. Provide the name of used/registered for that. _(5 points)_
```shell
index=main (EventCode=17 OR EventCode=18)
# Used to discover the named pipe
``` 

# Workflow
```shell
index=main Channel="Microsoft-Windows-Sysmon/Operational"   Computer="DEV-WKS-01.meridian.local" EventID="1" CommandLine IN ("*-enc*", "*hidden*", "*bypass*") earliest="03/31/2026:00:45:22"| sort + UtcTime
```

```shell
index=main Channel="Microsoft-Windows-Sysmon/Operational" EventID="3"   User="MERIDIAN\\jcarter" | sort + UtcTime | eventstats count by DestinationPort| table UtcTime, DestinationPort, count, DestinationIp, DestinationHostName
# Being used to get counts of destination ports while displaying certain fields in the table with it.
```

```shell
index=main (CommandLine="*C:\\Users\\jcarter\\AppData\\Local\\Temp\\*" OR ParentCommandLine="*C:\\Users\\jcarter\\AppData\\Local\\Temp\\*" OR CurrentDirectory="*C:\\Users\\jcarter\\AppData\\Local\\Temp\\*")| table _time, User, CommandLine, ParentCommandLine, CurrentDirectory
```
```shell
index=main Computer="BUILD-01.meridian.local" earliest="03/31/2026:00:45:23" (EventCode="1" OR EventCode="4688")  Image="C:\\Windows\\System32\\cmd.exe" CommandLine="C:\\Windows\\system32\\cmd.exe /c type C:\\Jenkins\\workspace\\customer-portal\\build.bat" User="MERIDIAN\\svc_jenkinsdeploy"
# Used to find 
```

- 

# Items

| Hostname                  | IP            | Summary                               |
| ------------------------- | ------------- | ------------------------------------- |
| SRV-APP-01.meridian.local | 10.20.5.41    |                                       |
| BUILD-01.meridian.local   | 10.20.5.22    | MERIDIAN\<br>kins                     |
|                           | 10.20.4.51    |                                       |
| sfrlak.com                | 142.11.206.73 | Proven Malicious on virustotal lookup |


# Indicators

| TYPE                           | Summary                                                                                                                                                                                                                                                         | Timestamp           | Mitre ATT&CK code |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----------------- |
| Persistence                    | C:\Program Files\nodejs\node.exe on  DEV-WKS-01.meridian.local modified WindowsTerminalUpdate run key ` HKU\S-1-5-21-1004336348-1177238915-682003330-1001\Software\Microsoft\Windows\CurrentVersion\Run\WindowsTerminalUpdate`                                  | 2026-03-31 00:45:22 | T1105             |
| Registry key modified          | DEV-WKS-01.meridian.local  10.20.4.51 with image  C:\ProgramData\wt.exe making outbound connections to public IP  sfrclak.com, 142.11.206.73:8000 on account jcarter                                                                                            |                     | T1041             |
| Powershell execution           | `"C:\ProgramData\wt.exe" -NoProfile -ep Bypass -File C:\Users\jcarter\AppData\Local\Temp\6202033.ps1` with ParentCommandLine` C:\Windows\system32\cmd.exe /c "C:\ProgramData\.run.bat"`                                                                         | 2026-04-02 13:31:32 | T1059.001         |
| Malicious file creation        | `C:\Users\jcarter\AppData\Local\Temp\6202033.ps1` created by  `C:\Program Files\nodejs\node.exe`                                                                                                                                                                | 2026-03-31 00:45:22 |                   |
| Lateral Movement               | jcarter uses WinRM (port 5985) from `DEV-WKS-01.meridian.local` to `BUILD-01.meridian.local` 10.20.5.22                                                                                                                                                         | 2026-04-02 19:35:47 | T1021.006         |
| Enumeration of Remote Services | Reg query performed on `"HKCU\Software\SimonTatham\PuTTY\Sessions"`                                                                                                                                                                                             | 2026-04-01 19:27:22 | T1021.004         |
| Staging data                   | The .ps1 file begins copying data from "C:\Users\jcarter\AppData\Roaming\npm\.npmrc", "C:\Users\jcarter\AppData\Local\Google\Chrome\User Data\Default\Login Data", "C:\Users\jcarter\.aws\credentials" and staging them in C:\Users\jcarter\AppData\Local\Temp\ | 2026-04-01 19:27:17 | T1074.001         |
| Suspicious transfer            | ` C:\Windows\system32\Robocopy.exe "C:\Jenkins\workspace\customer-portal\dist\customer-portal" "\\SRV-APP-01\c$\inetpub\customer-portal" /MIR /R:1 /W:1`<br>SMB transfer from `BUILD-01` to `SRV-APP                                                            | 2026-04-03 08:24:00 |                   |
| Initital access                | DEV-WKS-01 makes connection to sfrclak.com  over port 8000 using  C:\ProgramData\wt.exe                                                                                                                                                                         | 2026-03-31 00:45:23 |                   |
| Lateral Movement               | jcarter from `devs-wks-01` logs into svc_jenkinsdeploy on `build-01.meridian`on eventcode 4648                                                                                                                                                                  |                     |                   |
| Enumeration                    | Upon logging in as svc_jenkinsdeploy on BUILD-01, attacker enumerates Domain admins, host name, build.bat for credentials                                                                                                                                       | 2026-04-02 19:41:24 |                   |
| Timestamp modification         | svc_jenkins modified timestamps for app.js and build.bat. This is known as Timestomping                                                                                                                                                                         | 2026-04-03 08:17:30 | T1070.006         |
| Lateral Movement               | telemtry.js from BUILD-01 gets copied over to SRV-APP-01 in the customer portal plugins                                                                                                                                                                         | 2026-04-03 08:24:05 |                   |
| Named Pipe created             | User svc_portal using svc_helper.exe created a named pipe called spoolss                                                                                                                                                                                        | 2026-04-03 14:18:50 |                   |
| Persistence                    | CommandLine: ` sc create WinTelemetrySvc binPath= "C:\ProgramData\WinTelemetry\svc.exe" start= auto <br><br>New service created with weird binary set to execute on startup                                                                                     | 2026-04-03 15:51:30 | T1547, T1036.004  |
| c2 beaconing                   | SRV-APP-01 begins communicating with Threat Actor's c2 server over port 8000                                                                                                                                                                                    | 2026-04-03 08:24:42 |                   |

# Big learning curves
1. node.exe is the java executable outside of a web browser. This was used a LoTL binary to execute malicious javascript on the system.
2. In Sysmon EventID 13, The details key:value pair indicates what gets inserted in the registry value
3. Finding the malicious IP in the first question. IF I had done a malicious IP lookup I would have found this sooner.
4. Finding the lateral movement from WKS-BUILD
