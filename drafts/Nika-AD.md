#WireSharkCTF #Splunk #MediumCTF #EternalBlue #CyberchefCTF
# Context
CYPYRATE’s network operations have been significantly disrupted by BlackCipher, an elite cyber-warlord. The attack has affected multiple components within the network. The setup includes the following key systems and users:

Domain Controller (DC): Managed by the Administrator, IP 10.0.2.2.
IT Admin Workstation: Used by Roar Zen, IP 10.0.2.5.
Web Server: Operated by Sunny Merry, IPs 10.0.2.10 and 192.168.1.13.
File Server: IP 10.0.2.6.

The internal network operates on the 10.0.2.0/24 subnet, while the 192.168.1.0/24 subnet is designated as the DMZ. Your mission is to analyze the cyber-attack, identify the specific techniques used by BlackCipher, and assist in restoring CYPYRATE’s network functionality.

If you find that Splunk is not working when you open Firefox, please go to the Investigation Files folder present on the Desktop. Inside which you will find a document titled "Troubleshooting-Splunk.pdf" that can help you resolve the issue.
# Questions
## 1.  Q1) Using network packet analysis, determine the IP address of the attacker (Format: X.X.X.X) _(2 points)_
```shell
ip.addr==192.168.1.12 && ip.addr==192.168.1.13 && tcp.flags.syn == 1 && tcp.flags.ack == 1

# Checking conversations confirmed this and there was scanning occurring from that IP as well.
```
## 2.  Q2) Which service did the attacker target to gain access to the Web Server? (Format: XXX) _(2 points)_
```shell
ip.addr==192.168.1.12 && tcp.dstport in {445 4444 135 139}
# Viewed activity of these ports.

```
## 3.  Q3) What is the operating system and version of the targeted Web Server? (Format: Xxxxxxx X) _(3 points)_
```shell
ip.addr==192.168.1.12 && tcp.port == 445
# Checked the NTLMSSP challenge
```
## 4. Q4) Based on the packets' information and flow, identify the popular exploit that is being used here (Format: XxxxxxxXxxx) _(3 points)_
```shell
Eternal Blue
# THis is made evident by 
# SMB anonymous login with a PeekNamedPipe giving code STATUS_INSUFF_SERVER_RESOURCES indicates vulnerable to EternalBlue
```

## 5. Q5) Without verifying their identity, the attacker received a user's hash from the Domain Controller. Using Splunk, determine what type of attack was used (Format: XXXXXXxxxxxxx) _(3 points)_
```shell
EventID=4768
# THis reveals hashes that were received
```

## 6. Q6) Which domain user was targeted in the attack? (Format: DOMAIN\User) _(3 points)_
```shell
CYPYRATE\nrob
```
## 7.  Q7) Which computer did the attacker log into after compromising the user? (Format: XXXX-XXXXX) _(3 points)_
```shell
index=* host="FILE-SERVER" Account_Name=nrob   TaskCategory=Logon  Logon_Type=10 | sort + UtcTime
# Logon Type 10 reveals when they first logged in and into what.
```
## 8. Q8) What protocol did the attacker utilize to gain access to the computer? (Format: Protocol) _(3 points)_
```shell
index=* host="FILE-SERVER" Account_Name=nrob   TaskCategory=Logon  Logon_Type=10 | sort + UtcTime
# Logon Type 10 reveals RDP login
```
## 9.  Q9) Identify any privilege escalation attempts on the same computer. Which file or script was used to find potential methods of escalation? (Format: file.ext) _(4 points)_
```shell
index=* host="FILE-SERVER" EventCode IN ("1", "4688", "4104", "4103") Image!="*splunk*" latest="05/18/2024:08:50:37"
| sort - _time
| table _time, EventCode, Image, CommandLine, ParentCommandLine, ParentImage, User
# EventID 4104 script block execution revealed what was run within the powershell.exe session that eventCode 1 didn't.
# Powerview.ps1 was the answer
```
## 10. Q10) Determine the service exploited for privilege escalation on the same computer. What is the name of the service that was abused? (Format: ServiceName) _(3 points)_
```shell
index=* host="FILE-SERVER" EventCode IN ("1", "4688") powershell.exe Image!="*splunk*"
| sort + _time
| table _time, Image, CommandLine, ParentCommandLine, ParentImage, User
# Used to locate Processes involving powershell execution on the file server
```
## 11. Q11) What command was used to abuse the service? (Format: Command) _(3 points)_
```shell
net localgroup Administrators CYPYRATE\nrob /add
# net localgroup Administrators CYPYRATE\nrob /add
```
## 12.  Q12) What is the MITRE ID for the technique used to escalate privileges via the exploited service on the same computer? (Format: TXXXX.xxx) _(2 points)_
```shell
T1574.010
```
## 13. Q13) Which malicious executable did the attacker use to dump credentials? (Format: file.ext) _(2 points)_
```shell
mimikatz.exe
# Search used was :
# index=* host="FILE-SERVER" "*\\Temp\\*" OR "*\\tmp\\*" OR "\\Downloads\\*" OR "\\*AppData\\*" OR "*\\ProgramData\\*" OR "*\\Tasks\\*" NOT "*splunk*"
```
## 14.  Q14) From which directory was the malicious executable executed? (Format: X:\path\to\directory) _(2 points)_
```shell
# Answer: C:\Users\nrob\Downloads\m\mimikatz-master\x64

```
## 15.  Q15) Which computer did the attacker access using a newly compromised user with a similar method as previously observed? (Format: XX-XXXXX) _(2 points)_
```shell
Answer: IT-WKSTN
Solution: 
```
## 16. Q16) Which domain user's credentials were likely used from the credential dump to log into the new system? (Format: DOMAIN\user) _(2 points)_
```shell
index=* host="FILE-SERVER" EventCode IN ("1", "4688", "4104", "4103", "4624", "4625") Image!="*splunk*" earliest="05/18/2024:08:50:37"
| stats count by User
```
## 17. Q17) What attack did the attacker use to maintain persistent network access? (Format: Xxxxxx Xxxxxx _(2 points)_
```shell
Golden Ticket
```
## 18. Q18) Provide the aes-256 hash used to execute the attack (Format: Hash) _(2 points)_
```shell
# 4c517465330767f6a9ab9bb02f6b07da6a6c7f401087b97fceb3fdbe1cb9ee2a
```
## 19. Q19) Provide the name of the ticket (file), that was used in the previously found attack? (Format: file.ext) _(2 points)_
```shell
Answer: comp.kirbi
Solution: 
```
## 20. Q20) Which utility did the attacker use to execute commands on the Domain Controller? (Format: file.ext) _(2 points)_
```shell

Answers: PsExec64.exe
# Solution = index=* earliest="05/18/2024:08:56:32" CurrentDirectory="C:\\Users\\rzen\\*"
| table _time, User, CommandLine, ParentCommandLine, host, Hashes

```
# Workflow


# Artifacts / Assets

| Item       | Value | Connection |
| ---------- | ----- | ---------- |
| Web server |       |            |

# Indicators

| TYPE                   | Summary                                                                                                                      | Timestamp                | Mitre ATT&CK code |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ----------------- |
| Reconnaisance          | 192.168.1.12 port scanned web server and found ports 445, 4444, 139, 135 and 49xxxx ephermal ports open                      | 2024-05-17 19:32:28      | T0846.001         |
| SMB EternalBlue        | SMB anonymous login with a PeekNamedPipe giving code STATUS_INSUFF_SERVER_RESOURCES indicates vulnerable to EternalBlue      | 2024-05-17 19:31:30      |                   |
| Valid Accounts Domain  | Attacker logs in as nrob on file-server                                                                                      | 2024-05-18T01:51:52.000Z | T1078.002         |
| Sc.exe usage           | CommandLine: "C:\Windows\system32\sc.exe" config AV_Troubleshoot binpath= "net localgroup Administrators CYPYRATE\nrob /add" |                          |                   |
| Credential enumeration | EventID 5379 credential manager creds getting enumerated                                                                     | 05/17/2024 09:22:48 PM   | T1078.002         |
| Privilege Escalation   | NROB gets added to the administrator group by exploitation of weak service permissions                                       | 2024-05-18 08:49:59      | T1574.010         |
| Credential Dumping     | Power.ps1 is used to find privilege escalation methods on the File Server by nrob                                            | 2024-05-18 08:45:24      | T1059.001         |
| Powershell Executin    | C:\Users\rzen\pv.ps1 at                                                                                                      | 05/18/2024 02:06:27 AM   |                   |
| Credential Access      | C:\Users\nrob\Downloads\m\mimikatz-master\x64\mimikatz.exe was downloaded and run                                            | 2024-05-18 08:56:32      | T1003             |

# Big learning curves
1. I got stumped trying to find what was used to enumerate for rzen's credentials. I searched for eventcode 4688 and 1 but there was no relevant events there. Only until I looked at 4104 did I actually get script block execution. When powershell got spawned there was eventcode 1 for it, all that was executed in there didn't appear. 4104 will display what got executed in that processes memory. This showed power.ps1 being used to enumerate credentials.
2. I got stumped trying to find where the malicious executabl mimikatz was being used. It appears in EventCode 1 however didn't appear when I specified 4688 and 1. Eventually I found it by doing a general temp/download directory search with 