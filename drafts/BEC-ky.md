#CyberchefCTF #BECCTF #EmailAnalysisCTF #TimeLineExplorerCTF
# Context
Our Situation? - Up the creek without a paddle. We’re facing a suspected cyber incident involving unauthorised yet seemingly legitimate bank transfers from the company pension fund to multiple external accounts. Figure out what’s happened.
# Questions
## 1. What is the source address of the initial phishing email? _(5 points)_
```shell
Sabastian@flanaganspensions.co.uk
```
## 2. What type of compromise is this? _(5 points)_
```shell
Business Email COmpromise based on the name of the 
```
## 3.  What are the two IPs utilised by the TA? _(5 points)_
```shell
Had to read the azure .csv logs. The first one was located among others under the code UserLoggedIN and key:value of ClientIp

The 2nd was located under new-inboxrule with CLient IP as well

```
## 4. Which bank is the transaction sent to? _(2 points)_
```shell
Read one of the emails that contains the SWIFT information and you can lookup the bank there.
It was a nigerian bank
```

## 5. What is the name of the Inbox folder created during the compromise? _(4 points)_
```shell
Check out FolderCreated operation code
```

## 6. What word is the first inbox rule created looking for, within the subject or body, prior to deleting the email _(4 points)_
```shell
Chec k
```

# Workflow


# Artifacts / Assets

| Item                  | Value                                       | File accessed                                                                      |
| --------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------- |
| Beck Inbox Access IPs | , 20.68.123.31, 20.77.248.66, 52.108.224.1, | tempestasenergyoutlook-my.sharepoint.com/personal/becky_lorray_tempestasenergy_com |
| IPs                   |                                             | 2.127.216.50, 20.77.248.66, 52.108.224.1, 109.175.196.67, 159.203.17.81            |

# Indicators

| TYPE                   | Summary                                                                                              | Timestamp           | Mitre ATT&CK code |
| ---------------------- | ---------------------------------------------------------------------------------------------------- | ------------------- | ----------------- |
| New-InboxRule          | Becky had a new iunbox rule created to forward emails to 95.181.232.30:23701 and                     | 2025-07-02T15:40:10 |                   |
| DeleteMessage          | Client IP 95.181.232.30:24176 initiated this on a message. Rule named "Stop processing rules"        | 2025-07-02T15:48:39 |                   |
| Becky suspicious login | Attacker logs in from 95.181.232.30 wiuth failed login initially. 2.127.216.50, 40.126.41.96<br><br> | 2025-07-02T15:45:05 |                   |
| SMTP send Code         | Attack sends email "Withdrawal-bernard" to                                                           | 2025-07-02T15:57:23 |                   |
| New-InboxRule          | Sent to Sebastian@flanaganspensions.co.uk,                                                           | 2025-07-02T15:58:42 |                   |
| Email fund transfer    | The SWIFT/BIC of the Bank maps to FIRST BANK OF NIGERIA LTD                                          |                     |                   |
| Phishing Email         | COntains a image.png                                                                                 |                     |                   |

# Big learning curves
1. Once the first malicious action has been discovered, correlate it with the previous login time.
2. Understanding the operation codes was the first big hurdle and parsing the log information for what actions are being taken. 
