# Microsoft Defender for Identity (MDI) when running a playbook or a pentesting

---
Author: Daniel Pasquier

## Introduction

As you know, MDI is a powerful solution to detect abnormal or suspicious activities from managed or unmanaged or even unknown machines targeting Domain Controllers. 
When running a playbook or a pentesting ensure your MDI configuration is well configured and ready, especially with the machine learning period; please see linked-In article: https://www.linkedin.com/post/edit/6938115126705184768/.

Then from a new machine (fresh install, managed or unmanaged) try the following scenarios:

## 1 – Network mapping reconnaissance (DNS)  
This reconnaissance is used by attackers to map your network structure and target interesting computers for later steps in their attack.

There are several query types in the DNS protocol. This Defender for Identity security alert detects suspicious requests, either requests using an AXFR (transfer) originating from non-DNS servers, or those using an excessive number of requests.

From a command line run :  
  
*Nslookup*  
*server MSDemoDC01.msdemo.local*  
*ls -d msdemo.local*   

You should see activity in success or failure (connection refused) and the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image2.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image1.png)  

## 2 - User and IP address reconnaissance  
In this detection, an alert is triggered when an SMB session enumeration is performed against a domain controller; users and computers need at least to access the sysvol share in order to retreive GPOs. Attacker can use this information to know where users recently logged on and move laterally in the network to get to a specific sensitive account.  

From a command line run :    

*NetSess.exe MSDemo-DC01.msdemo.local*  

Tools availbale from : http://www.joeware.net/freetools/tools/netsess/  

You should see activity and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image6.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image5.png)  

## 3 - User and group membership reconnaissance (SAMR)  
In this detection, User and group membership reconnaissance are used by attackers to map the directory structure and target privileged accounts for later steps in their attack using SAMR protocol.

From a command line with proper permissions, run:  
   
*net user /domain*  
*net group /domain*  
*net group "Domain Admins" /domain*  
*net group "Enterprise Admins" /domain*  
*net group "Schema Admins" /domain!*  

You should see activity and the alert in the user timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image7.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image8.png) 

## 4 - Security principal reconnaissance (LDAP)  
In this detection, MDI looks for LDAP security principal reconnaissance which is commonly used as the first phase of a Kerberoasting attack. Kerberoasting attacks are used to get a target list of Security Principal Names (SPNs), which attackers then attempt to get Ticket Granting Server (TGS) tickets for.

From a command line with proper permissions, run the tools from the French Security Agency (https://www.linkedin.com/company/anssi-fr/) for data collection:   
  
*Oradad.exe*  

Tools available from : https://github.com/ANSSI-FR/ORADAD/releases 
  
You should see the activities and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image9.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image10.png)  

## 5 - Honey Token activity  
This lure account should be attractive for attackers (attractive name or sensitive group memebership..) and be left unused by your organisation; any activity from them might indicate malicious behavior (LDAP, NTLM or Kerberos logon attempts).

From MSTSC.exe or from an interactive logon, try to logon using this account with a wrong password and/or valid password :  

You should see the logon activity and the alert in the Honey Token user timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image11.png)  

Detail in the alert (failed logon attempt):  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image12.png)  

## 6 - Active Directory attributes reconnaissance (LDAP)  
Active Directory LDAP attributes reconnaissance is used by attackers to gain critical information about the domain environment, such as accounts with DES or RC4 kerberos cipher, accounts with Kerberos Pre-Authentication disabled and service account configured woth Uncosntrainted Keberos Delegation.

From adsisearcher (PowerShell) or any ldap browser such as ldp.exe set the following ldap filters :  

*(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)) FindAll()* => Enumerate accounts with Kerberos DES enabled

*(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) FindAll()* => Enumerate accounts with Kerberos Pre-Authentication disabled  

*(&(objectCategory=computer)(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288))) FindAll()* => Enumerate all servers configured for Unconstrained Delegation (Excluding DCs)  

*(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) FindAll()* => Enumerate all enabled accounts

or run from a command line with admin rigths:  

*repadmin /showattr * DC=msdemo,DC=local ou repadmin /showattr * DC=msdemo,DC=local /subtree /filter:"((&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))" /attrs:cn,msDs-AllowedToActOnBehalfOfOtherIdentity* => Enumerate servers configured for Resource Based Constrained Delegation

You should see the activities and the alert in the client machine timeline :  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image18.png)  

Detail in the alert:  

![image1](https://raw.githubusercontent.com/DanielpFR/MDI/Images/Image14.png)  


# 7 - Account enumeration Reconnaissance  




