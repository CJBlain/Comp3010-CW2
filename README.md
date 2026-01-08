# Comp3010-CW2

Connor Blain
Comp3010 Report and Analysis on BOTSv3 Dataset
Link to Video:


**Introduction:** 
An SOC (Security Operations Centre), serves as a central hub for monitoring, detecting, analysing and responding to real time cyber security threats. The Botsv3 dataset that has been used in this report allows you to practise these skills. The dataset simualtes a security incident at a fake brewing company called frothy. The datset provides the user with a wide range of logs, these range from emails to to network endpoints. on top of all of that, the BOTSv3 Dataset also includes logs from cloud services such a amazon web services and microsft azure.

The Primary purpose of the investation will be to analyse anolomises related to AWS and answer the set of level 200 questions. 

Assumptions made:
All logs in BOTSv3 are trusted and correctly timestamped.
The investigation is retrospective (post-incident analysis).



**SOC Roles & Incident Handling Reflection:**
in real life, a security operations centre uses 3 tiers to handle secuity incidents. These are as follows:
Tier 1 (Alert Triage) defined as initial alert review and validation.
Tier 2 (Incident Analysis) defined as deep investigation, correlation, and root cause analysis.
Tier 3 (Threat Hunting & Engineering) defiend as advanced analysis, detection engineering, and remediation.

The BOTSv3 exercise mostly focuses around the responsabilities of the second tier. This means that it requires log analysis, following evidence to form conclusions and linking data together to form corralations.


**Installation & Data Preparation:**
The envirmmoment to complete this exercise was swtup to closely miror real world SOC lab infrastructure. 
Host: VMware Workstation Pro 17 on Windows 11 host
Guest OS: Ubuntu 22.04.5 LTS Desktop (64-bit)
Resources allocated: 8 vCPUs, 32 GB RAM, 120 GB dynamic disk

The reasons for allocating the amount of disk space and RAM was to ensure perfomance when loading the dataset was not an issue. As well as this, when i was investigating the dataset i did not want to have to wait ages everytime i searched. 

Instillation steps were as follows.
1. VMware VM created with VMware Tools installed for optimal performance.
2. Ubuntu installed using download from the DLE [Proof of Ubuntu Download](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-04%20150243.png)
3. Upon Successfull download i made sure to check for any Ubuntu Updates
4. Splunk Enterprise 9.2.2 installed via official site. [Proof of Splunk Liscense](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-06%20131916.png)
5. Download of BOTSv3 Dataset from DLE on the VM
6. BOTSv3 dataset ingested using the official one-shot script from https://github.com/splunk/botsv3. 
7. Validation: index=botsv3 | stats count by sourcetype returned 38 sourcetypes and over 24 million events.


**Findings of the Investigation**
all searches make use of index=botsv3 earliest=0 in order to ensure i am looking through not only the correct dataset but also the full version of it.


**Conclusion and Presentation:**

**References:**
[1] Splunk, "BOTSv3 Dataset," GitHub, 2020. [Online]. Available: https://github.com/splunk/botsv3.


