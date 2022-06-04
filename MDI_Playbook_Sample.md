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



