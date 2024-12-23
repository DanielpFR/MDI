# Tips & Tricks #Investigate with Microsoft Defender for Identity

---
Author: Daniel Pasquier

## Introduction

Microsoft Defender for Identity (MDI) is the ideal solution for detecting and investigating advanced threats, compromised identities, and malicious insider actions in Active Directory. For each AD Cybersecurity Crisis where our [Microsoft Detection and Response Team (DART)](https://www.microsoft.com/security/blog/microsoft-detection-and-response-team-dart-blog-series/) is involved, they always ask for installing MDI to better investigate and set the appropriate remediation actions.
SecOp analysts and security professionals who use Microsoft Defender for Identity give us great feedbacks (such as preventing CryptoLocker activities etc..); and [Jugoslav](https://www.linkedin.com/in/jugoslav-stevic-5693b773/) and [I](https://www.linkedin.com/in/danielpasquier/) would like to share best practices from the field.
Keep in mind that MDI has unique capabilities to capture source data using deep packet inspection (traffic on all DCs), Event Tracing, Event Logs… combined with User profiling, Machine learning and fast updated Alerts based on the Threat landscape.
  
MDI is also very relevant when the source attack comes from an unknown, unmanaged machine (no AV/EDR/GPO) where you have no control...

Here are the MDI capabilities :
  
-	[Microsoft Defender for Identity Alerts](https://docs.microsoft.com/en-us/defender-for-identity/suspicious-activity-guide?tabs=external)
-	[Microsoft Defender for Identity monitored domain activities](https://docs.microsoft.com/en-us/defender-for-identity/monitored-activities)
-	[Microsoft Defender for Identity user profiles activities](https://docs.microsoft.com/en-us/defender-for-identity/entity-profiles)
-	[Microsoft Defender for Identity Lateral Movement Paths](https://docs.microsoft.com/en-us/defender-for-identity/use-case-lateral-movement-path)
-	[Microsoft Defender for Identity's identity security posture assessments](https://docs.microsoft.com/en-us/defender-for-identity/isp-overview#access--using-cloud-app-security)
-	[Working with Microsoft Defender for Identity Reports](https://docs.microsoft.com/en-us/defender-for-identity/reports)
-	[Microsoft Defender for Identity Advanced hunting](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview?view=o365-worldwide)
  
In this documentation, we want to share some of useful Advanced Hunting KQL queries that you can use with the [Microsoft 365 Defender portal](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-365-defender)  available from [https://security.microsoft.com](https://security.microsoft.com).
  
To get the list of ActionType you can use in your environment for **IdentityDirectoryEvents** API, just run:

*IdentityDirectoryEvents*  
*| summarize by ActionType*
  
Here are few tips you can use or optimize:
  
## Tips 1 – List of machines where service account is running

In case of a SVC account is compromised, or if you need to change the SVC account password or if someone knowing the SVC account password leaves your organisation; it could be very useful to know where a service account is configured (consider using gMSA instead):

*IdentityLogonEvents*  
*| where Application == @"Active Directory"*  
*| where AccountUpn == @"ACCOUNT_SVC@MSDEMO.FR" // set your SVC account here*  
*| where ActionType == @"LogonSuccess"*  
*| summarize count() by DeviceName*  
  
In this example, over the last 30 days, account_svc@msdemo.fr is used on 432 machines (logon success), the list of machines can be exported into a CSV file.
If needed, you can add additional information such as the LogonType (Resource access, Credentials validation…).
This is not an exhaustive list as the ActionType == LogonSuccess must occur in the last month, but after several months you should catch a good list.  

![Image1](https://user-images.githubusercontent.com/95940022/146009404-5b90694e-9489-43a7-aa56-6f4f035b5b5f.png)
  
## Tips 2 – Kerberos versus NTLM use  

We all know that Kerberos provides several security benefits over NTLM and provides best performance. Here the following KQL query will provide the ratio of the success logon using NTLM and Kerberos:   

*IdentityLogonEvents*  
*| where ActionType == "LogonSuccess"*  
*| where Application == "Active Directory"*  
*| where Protocol in ("Ntlm", "Kerberos")*  
*| summarize count() by Protocol*  

![Image2](https://user-images.githubusercontent.com/95940022/146010249-f9ad5964-f8c0-4c4d-8b1d-d624e8663de7.png)  

Since the NTLMv1 hash is always at the same length, it is only a matter of seconds if an attacker wants to crack it. In addition, the challenge-response mechanism exposes the password to offline cracking. It is recommended not to use it if possible.  

To track the use of NTLMv1 you can run:  

*IdentityLogonEvents*  
*| where Timestamp > ago (7d) // shows activies in the last 7 days*  
*| where Application contains "directory"*  
*| where Protocol == "NTLM"*  
*| extend AddData = todynamic(AdditionalFields)*  
*| extend NTLMV1 = tostring(AddData.IsNtlmV1)*  
*| extend Account = tostring((AddData).["ACTOR.ACCOUNT"])*  
*| where NTLMV1 == "True"*  
*| summarize count() by Account, AccountSid ,  DC = DestinationDeviceName*  

To understand failure reasons during Kerberos authentication in your environment:  

*IdentityLogonEvents*  
*| where ActionType == "LogonFailed"*  
*| where Application == "Active Directory"*  
*| where Protocol == "Kerberos"*  
*| summarize count() by FailureReason*  

![Image3](https://user-images.githubusercontent.com/95940022/146011101-6fdebba2-09ac-446c-8158-8f6d21becb10.png)  

Do you want to know who and from where weak cipher such as DES or RC4 are used for Kerberos authentication? Just use the following query:  

*IdentityLogonEvents*   
*| where Protocol == @"Kerberos"*  
*| extend ParsedFields=parse_json(AdditionalFields)*  
*| project Timestamp, ActionType, DeviceName, IPAddress, DestinationDeviceName, AccountName, AccountDomain, EncryptionType = tostring(ParsedFields.EncryptionType)*  
*| where EncryptionType == @"Rc4Hmac"*  

![Image15](https://user-images.githubusercontent.com/95940022/146078610-6add4299-8402-4839-96e3-8240e8dd74ed.png)  

Remark : This information is also available from the [Microsoft Defender for Identity's identity security posture assessments](https://docs.microsoft.com/en-us/defender-for-identity/isp-overview#access--using-cloud-app-security)

## Tips 3 – List of files copied from a client to DCs over the last 30 days  

Except if your DCs are used as files server, which is of course not recommended at all you should not see many files copied from a workstation or member server to DCs.  

Using this KQL query you can monitor this activity and identify potential suspect activities or even risky activities:  

*IdentityDirectoryEvents*  
*| where ActionType == @"SMB file copy"*  
*| extend ParsedFields=parse_json(AdditionalFields)*  
*| project Timestamp, ReportId, ActionType, DeviceName, IPAddress, AccountDisplayName, DestinationDeviceName, DestinationPort, FileName=tostring(ParsedFields.FileName), FilePath=tostring(ParsedFields.FilePath), Method=tostring(ParsedFields.Method)*  
*| where Method == @"Write"*  

![Image4](https://user-images.githubusercontent.com/95940022/146016380-1d6dcb4a-02f7-4b2c-8fe0-70f21e197075.png) 

Remark: MDI has also an alert for data exfiltration (such as the NTDS.DIT file copied from a DC to a workstation).  

## Tips 4 – “Account Password Not Required” changed from FALSE to TRUE   

Even with a password policy in place that affects all user accounts, it is possible to set a blank password for a user with the setting “Account Password Not Required” using for example a PowerShell cmdlet (not possible through the GUI). This is why it's important to list all users with this setting enabled using the MDI portal but also to track all changes from “Account Password Not Required” = FALSE to TRUE:  

*IdentityDirectoryEvents*  
*| where ActionType == @"Account Password Not Required changed"*  
*| extend PreviousValue = todynamic(AdditionalFields)["FROM Account Password Not Required"]*  
*| extend NewValue = todynamic(AdditionalFields)["TO Account Password Not Required"]*  
*| where "True"==NewValue*  
*| project Timestamp, ActionType, Application, TargetAccountDisplayName, PreviousValue, NewValue*  

![Image5](https://user-images.githubusercontent.com/95940022/146022121-bc2576a4-804d-4339-ae57-6848d56c7505.png)  

## Tips 5 – “Account Password Never Expires” changed from FALSE to TRUE  

This setting could be expected for service account if you can’t use gMSA; however, we should never see “Account Password Never Expires” changed from FALSE to TRUE for an user account (not SVC) or for an admin account (a lazy one 😊). Here how to track this information:  

*IdentityDirectoryEvents*  
*| where ActionType == @"Account Password Never Expires changed"*  
*| extend PreviousValue = todynamic(AdditionalFields)["FROM Account Password Never Expires"]*  
*| extend NewValue = todynamic(AdditionalFields)["TO Account Password Never Expires"]*  
*| where "True"==NewValue*  
*| where TargetAccountDisplayName !contains "SVC"*  
*| project Timestamp, ActionType, Application, TargetAccountDisplayName, PreviousValue, NewValue*  

![Image6](https://user-images.githubusercontent.com/95940022/146022612-c15937ab-b378-452c-9182-1545daf13b4f.png)  

## Tips 6 – Expected “PowerShell execution” on DCs?  

MDI generates an alert when remote code execution is performed against a DC, however if you need further investigation, you can run the following query to get the list of PowerShell command executed remotely to a DC (Of course it’s the same logic for “WMI execution”, PSEXE execution…):  

*IdentityDirectoryEvents*  
*| where ActionType == @"PowerShell execution"*  
*| extend Command = todynamic(AdditionalFields)["PowerShell execution"]*  
*| project Timestamp, ReportId, ActionType, DeviceName, IPAddress, DestinationDeviceName, AccountName, AccountDomain, Command*  

![Image7](https://user-images.githubusercontent.com/95940022/146022984-a1cb5191-e3e7-4b28-88fa-edb0ce37bde0.png)  

## Tips 7 – Expected “Service creation” on DCs?  

Do you want to know which new service, task scheduled are created on yours DCs remotely? Here is a sample for all services except for two which are expected in my environment:  

*IdentityDirectoryEvents*  
*| where ActionType == @"Service creation"*  
*| extend ParsedFields=parse_json(AdditionalFields)*  
*| project Timestamp, ReportId, ActionType, TargetDeviceName, AccountName, AccountDomain, ServiceName=tostring(ParsedFields.ServiceName), ServiceCommand=tostring(ParsedFields.ServiceCommand)*  
*| where ServiceName != @"Microsoft Monitoring Agent Azure VM Extension Heartbeat Service"*  
*| where ServiceName != @"MOMAgentInstaller"*  
*| where ServiceName !contains @"MpKsl"*  

![Image8](https://user-images.githubusercontent.com/95940022/146023422-f8fcefb3-97a4-4e17-ac25-04fc668f3806.png)  

## Tips 8 – Total Count – Computers with failed logon unknown users (>100)  

This query provides information mainly for misconfigured application that generate failed logon with status “UnknownUser”, probably because the wrong name was set.  

Of course, it could be also an attacker looking for valid account name based on the DC response WrongPassword (0xc000006a) or NoSuchUser (0xc0000064):  

*IdentityLogonEvents*  
*| where LogonType == "Failed logon"*  
*| where FailureReason == "UnknownUser"*  
*| where isnotempty(DestinationDeviceName)*  
*| summarize Attempts = count() by DeviceName, DestinationDeviceName , FailureReason*  
*| where Attempts > 100*  

![Image9](https://user-images.githubusercontent.com/95940022/146023738-77cc0fcd-e1f1-428b-80ef-2aff1e62ceb1.png)  

## Tips 9 – Top Spike for user’s logon activities over the last 30 days  

If you see a logon spike activity based on the activity during the past 30 days it could worth an investigation 😊 :  

*let interval = 12h;*  
*IdentityLogonEvents*  
*| where isnotempty(AccountUpn)*  
*| make-series LogonCount = count() on Timestamp from ago(30d) to now() step interval by AccountUpn*  
*| extend (flag, score, baseline) = series_decompose_anomalies(LogonCount)*  
*| mv-expand with_itemindex = FlagIndex flag to typeof(int) // Expand, but this time include the index in the array as FlagIndex*  
*| where flag == 1 // Once again, filter only to spikes*  
*| extend SpikeScore = todouble(score[FlagIndex]) // This will get the specific score associated with the detected spike*  
*| summarize MaxScore = max(SpikeScore) by AccountUpn*  
*| top 5 by MaxScore desc*  
*| join kind=rightsemi IdentityLogonEvents on AccountUpn*  
*| summarize count() by AccountUpn, bin(Timestamp, interval)*  
*| render timechart*  

![Image10](https://user-images.githubusercontent.com/95940022/146044976-04969a33-a458-4515-85a7-762dcb34f45b.png)  

## Tips 10 – Processes that performed LDAP authentication with cleartext passwords  

This query is available from  [https://github.com/Iveco/xknow_infosec/blob/main/M365D_tables.md](https://github.com/Iveco/xknow_infosec/blob/main/M365D_tables.md) and requires to have Microsoft Defender for Endpoint (MDE) to combine the result with MDI detection :  

*IdentityLogonEvents*  
*| where Timestamp > ago(7d)*   
*| where LogonType == "LDAP cleartext" //and isnotempty(AccountName)*  
*| project LogonTime = Timestamp, DeviceName, Application, ActionType, LogonType //,AccountName*  
*| join kind=inner (   
*DeviceNetworkEvents*  
*| where Timestamp > ago(7d) | where ActionType == "ConnectionSuccess"*  
*| extend DeviceName = toupper(trim(@"\..*$",DeviceName))*  
*| where RemotePort == "389"*  
*| project NetworkConnectionTime = Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine ) on DeviceName*  
*| where LogonTime - NetworkConnectionTime between (-2m .. 2m)*  
*| project Application, LogonType, ActionType, LogonTime, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine //, AccountName*  

## Tips 11 – Detect T0 Admin login on unsecure machines  

We all know that T0 Admins should be used only on secured/protected access workstations (SAW/PAW) to mitigate credential theft and a GPO can be used to deny logon types on all machines except a whitelist that matches SAW or PAW machines. Here, We want to be sure that T0 admins use only Privileged Access Workstation (PAW) machine or legitimate Admin jump servers; create this detection rule to identify any deviance.

*let T0Users = ExposureGraphNodes*  
*| where NodeLabel == "user"*  
*| extend parsedfields = parse_json(NodeProperties)*  
*| extend parsedRawData = parse_json(parsedfields.rawData)*  
*| where parsedRawData.primaryProvider == "ActiveDirectory" or parsedRawData.primaryProvider == "Hybrid"*  
*| extend nestedAdGroupNames = parse_json(parsedRawData.nestedAdGroupNames)*  
*| where nestedAdGroupNames contains "T0_Admins" // This is your T0 AD group*  
*| extend AccountSid = tostring(parsedRawData.adSid);*  
*let T0Machines = pack_array( // Declare PAW machines, jump admin servers as well as DCs*  
*'msdemo-dc1.msdemo.local',*  
*'cli2-win11-domj.msdemo.local'*  
*);*  
*IdentityLogonEvents*  
*| where Application == @"Active Directory"*  
*| where LogonType == "Interactive" or LogonType == "Remote desktop"*  
*| where not(DeviceName in~ (T0Machines))*  
 
  
## Tips 12 – Identify machines or IPs from where Account Lockout threshold is triggered  

The account lockout policy is a built-in security measure that limits malicious users and hackers from illegitimately accessing your network resources. However, employees often use multiple devices, numerous productivity applications, Windows services, tasks, network mapping and more, which can store a wrong password and set off the account lockout.  
It could be interesting to identify machines or IPs from where Account Lockout threshold is triggered only based on MDI raw data.  
Remark: DeviceName and IPAdress can sometime be empty (no raw data).

*IdentityLogonEvents*   
*| where Application == @"Active Directory" // AD only*  
*| where AccountDomain == @"msdemo.org" // if needed to filter by domain*  
*| where ActionType == @"LogonFailed"*  
*| where FailureReason == @"WrongPassword" or FailureReason == @"AccountLocked" //badpasswordcount attribute*  
*| summarize FailureReason = count() by DeviceName, IPAddress, AccountUpn*  
*| where FailureReason > 15 //depending on the Account Lockout threshold*  
  
<img width="671" alt="test" src="https://github.com/DanielpFR/MDI/assets/95940022/0d2815eb-8b87-4926-bda6-8308d198fcdd">  

## Tips 13 – Monitor AD Groups membership 

We all know that monitoring sensitive groups membership is very important, it could be the built-in ones such as Domain Admins, Enterprise Admins etc.., but it makes sense also to monitor custom AD groups such as Admin servers, Helpdesk or any groups that give access to sensitive data.
With MDI you can tag manually group as "Sensitive" in addition to those tagged by default and see the "Modifications to sensitive groups" Excel report available from "Identities reports" in the Defender XDR portal; MDI can also generate the "Suspicious additions to sensitive groups (external ID 2024)" alert based on machine learning.  
Please find below a KQL query to monitor AD groups, from Gershon Levitz in the ITDR product group. Keep in mind that can also be custom detection, meaning you can generate an MDI custom alert if we get a result.  


*let SensitiveGroupName = pack_array(  // Declare Sensitive Group names. Add any groups that you manually tagged as sensitive or nested groups in one of the default groups.*  
    *'Account Operators',*  
    *'Administrators',*  
    *'Domain Admins',*  
    *'Backup Operators',*  
    *'Domain Controllers',*  
    *'Enterprise Admins',*  
    *'Enterprise Read-only Domain Controllers',*  
    *'Group Policy Creator Owners',*  
    *'Incoming Forest Trust Builders',*  
    *'Microsoft Exchange Servers',*  
    *'Network Configuration Operators',*  
    *'Print Operators',*  
    *'Read-only Domain Controllers',*  
    *'Replicator',*  
    *'Schema Admins',*  
    *'Server Operators',*  
    *'Mark 8 Project Team'*  
*);*  
*IdentityDirectoryEvents*  
*| where Application == "Active Directory"*  
*| where ActionType == "Group Membership changed"*  
*| extend ToGroup = tostring(parse_json(AdditionalFields).["TO.GROUP"]) // Extracts the group name if action is add entity to a group.*  
*| extend FromGroup = tostring(parse_json(AdditionalFields).["FROM.GROUP"]) // Extracts the group name if action is remove entity from a group.*  
*| extend Action = iff(isempty(ToGroup), "Remove", "Add") // Calculates if the action is Remove or Add.*  
*| extend GroupName = iff(isempty(ToGroup), FromGroup, ToGroup) // Group name that the action was taken on.*   
*| where GroupName in~ (SensitiveGroupName)*  
*| project Timestamp, Action, ToGroup, FromGroup,  Target_Account = TargetAccountDisplayName, Target_UPN = TargetAccountUpn, AccountSid, DC=DestinationDeviceName, Actor=AccountName, ActorDomain=AccountDomain, ReportId, AdditionalFields*  
*| sort by Timestamp desc*  

![Capture d'écran 2024-05-30 162519](https://github.com/DanielpFR/MDI/assets/95940022/8f28b0c2-b6df-48b2-8a01-96336065593f)

## Tips 14 – Create a detection / notification rule  

Depending on the columns result you can set a detection rule to run at regular intervals, generating alerts and taking response actions whenever there are matches; this could be useful to notify your SOC team.  

See [Create and manage custom detection rules in Microsoft 365 Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide)  




















