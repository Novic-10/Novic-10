#CTF #MediumCTF #SplunkCTF   #spath #AWS #dedup #ec2image
# Context
At SecureNetDynamics, a developer (dev_harry) unknowingly left his AWS access keys in the source code of the company’s website. An attacker quickly spotted this mistake and used the keys to breach SecureNet’s AWS infrastructure. The attacker conducted a detailed enumeration of the environment, extracted sensitive keys from S3, planted persistence mechanisms, and eventually launched a ransomware attack, encrypting vital files. Now, SecureNetDynamics is in crisis mode and they to respond to it. They have a README file for you. Help them, Defender !!!
## Proof of completion Link= https://blueteamlabs.online/achievement/share/172832/233

# Questions
## 1.  1) When was the first successful activity seen from the compromised AWS User as per logs? (Format: YYYY-MM-DD HH:MM:SS UTC) _(4 points)_
```shell
# Answer: 2024-08-20 06:00:10 UTC
index=* "userIdentity.arn"="arn:aws:iam::764581110688:user/dev_harry" 
| where isnull(errorCode)
| sort + eventTime
# Had to use eventTime per the readme.txt

```
## 2.  2) What was the Source IP address associated with the activities? (Format: IP Address) _(4 points)_
```shell
Annswer = 3.144.171.70
```
## 3.  3) The attacker performed further enumeration and found an AMI image that the compromised user had access to. This AMI was used to create EC2 Instances. Find the AMI-ID. (Format: AMI-ID) _(5 points)_
```shell
# Answer: ami-08be8aa61081045c0
Solution: 
index=* "userIdentity.arn"="arn:aws:iam::764581110688:user/dev_harry" eventName="RunInstances"
| spath
| dedup requestParameters.instancesSet.items{}.imageId
| table eventTime eventName requestParameters.instancesSet.items{}.imageId _raw
# Pulled the ID from the json using dedup and spath while quoting the 
```
![[BTLO_awesome_AMI-pulled.png]]
AMI in the logs.
## 4. 4) The attacker changed the ingress rule of a security group, allowing everyone to connect through any port. Find this Security Group ID. (Format: Security Group ID) _(5 points)_
```shell
#Answer: sg-085becd1c5d4f7621 
Solution = 
Splunk Query = eventName IN ("*ModifySecurityGroupRules*", "ModifySecurityGroupIngress", "AuthorizeSecurityGroupIngress")

```

## 5. 5) Attacker after further enumeration found the Console Login credentials of a user. What is the name of the user? (Format: Username) _(4 points)_
```shell
# Answer = dev-neo
Solution = index=* source="cloudtrail-awesome.json" eventName IN ("ListUsers", "GetLoginProfile", "GenerateCredentialReport", "GetCredentialReport") eventName=GetLoginProfile
# GetLoginProfile was used to get dev-neo which returned null meaning 

```

## 6. 6) From which IP was this login originated? (Format: IP Address) _(4 points)_
```shell
# Answer = 103.99.35.120
index=* source="cloudtrail-awesome.json" "userIdentity.arn"="arn:aws:iam::764581110688:user/dev-neo"  eventName=ConsoleLogin
# Dsicovered COnsole Login event.
```
## 7.  7) What policy was attached to escalate access for this compromised user? (Format: Policy ARN) _(4 points)_
```shell
Answer = arn:aws:iam::aws:policy/AdministratorAccess
Solution = 
index=* source="cloudtrail-awesome.json" "userIdentity.arn"="arn:aws:iam::764581110688:user/dev-neo" eventName IN ("AssumeRole", "AttachUserPolicy", "PutUserPolicy")
# Showed admin access being given to compromised account 
```
## 8. 8) The attacker downloaded a critical file from S3 Bucket using which an important instance can be accessed. What is the name of the File? (Format: Filename.extension) _(4 points)_
```shell
Answer = devlopement-keys.pem
Solution = grep --color=always -i "key" ./* | tail -n 10
# Showed dev-neo accessing devlopment-keys.pem
```
![[BTLO_awesome_Key-access.png]]
Shows key access 
## 9.  9) For more stealth access in the environment, the attackers created a user and a group with Administrative access. Find the username and groupname. (Format: Username, Groupname) _(4 points)_
```shell

# Answer = dev_harry_bg, dev_group
SOilution = index=* source="cloudtrail-awesome.json" "userIdentity.arn"="arn:aws:iam::764581110688:user/dev-neo" eventName="CreateUser"

index=* source="cloudtrail-awesome.json"  "dev_harry_bg" eventName=AddUserToGroup
```
![[BTLO_awesome_new-user.png]]
## 10. 10) The attacker got access to an Instance and a Ransomware Script was downloaded in it. Using the given Instance.zip as an artifact, identify the IP and port from where the file was downloaded. (Format: IP:Port/File.extension) _(5 points)_
```shell
Answer = 3.144.171.70:8080/a.py
# I checked the user account's bash history
```
```shell
# Answer  = vdkx
```

# Workflow
index=* source="cloudtrail-awesome.json" eventName="ConsoleLogin"

# Artifacts / Assets

| Item                                 | Value                                                 | Connection           |
| ------------------------------------ | ----------------------------------------------------- | -------------------- |
| Compromised user                     | arn:aws:iam::764581110688:user/dev_harry              |                      |
| Compromised user                     | arn:aws:iam::764581110688:user/dev-neo                | src IP 103.99.35.120 |
| Newly created account added to group | Dev_neo adds dev_harry_bg to dev_group after creation |                      |

# Indicators

| TYPE                              | Summary                                                                                                     | Timestamp            | Mitre ATT&CK code |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ----------------- |
| AWS api call enumeration          | dev_harry ran `GetCallerIdentity` API with user agent BOTO. GetCallerIdentity is the equivalent of `whoami` | 2024-08-20T06:00:35Z |                   |
| Runinstances                      | dev_harry ran instances with ip address `172.31.30.142` and AMI ID  ami-08be8aa61081045c0                   | 2024-08-20T06:32:35Z |                   |
| Degrade security                  | Compromised account dev_harry modified securitygroup rules to allow public access                           | 2024-08-20T06:36:37Z | T1562.007         |
| Lateral Movement through accounts | arn:aws:iam::764581110688:user/dev-neo  signed into from 103.99.35.120                                      | 2024-08-20T06:43:30Z | T1078.004         |
| Privilege escalation              | Dev_NEO assigned administrator access ` arn:aws:iam::aws:policy/AdministratorAccess `                       | 2024-08-20T06:45:39Z | T1098.003         |
| Cloud credential creation         | TA's IP creates a new user dev_harry_bg. Harry gets added to dev_group afterwards                           | 2024-08-20T07:08:33Z | T1098.001,        |
|                                   |                                                                                                             |                      |                   |

# Big learning curves
