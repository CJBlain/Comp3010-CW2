# Comp3010-CW2

Connor Blain
Comp3010 Report and Analysis on BOTSv3 Dataset
Link to Video:


# **Introduction:** 
An SOC (Security Operations Centre), serves as a central hub for monitoring, detecting, analysing and responding to real time cyber security threats. The Botsv3 dataset that has been used in this report allows you to practise these skills. The dataset simualtes a security incident at a fake brewing company called frothy. The datset provides the user with a wide range of logs, these range from emails to to network endpoints. on top of all of that, the BOTSv3 Dataset also includes logs from cloud services such a amazon web services and microsft azure.

The Primary purpose of the investation will be to analyse anolomises related to AWS and answer the set of level 200 questions. 

### Assumptions made:
All logs in BOTSv3 are trusted and correctly timestamped.
The investigation is retrospective (post-incident analysis).



# **SOC Roles & Incident Handling Reflection:**
in real life, a security operations centre uses 3 tiers to handle secuity incidents. These are as follows:
Tier 1 (Alert Triage) defined as initial alert review and validation.
Tier 2 (Incident Analysis) defined as deep investigation, correlation, and root cause analysis.
Tier 3 (Threat Hunting & Engineering) defiend as advanced analysis, detection engineering, and remediation.

The BOTSv3 exercise mostly focuses around the responsabilities of the second tier. This means that it requires log analysis, following evidence to form conclusions and linking data together to form corralations.


# **Installation & Data Preparation:**
The envirmmoment to complete this exercise was swtup to closely miror real world SOC lab infrastructure. 
Host: VMware Workstation Pro 17 on Windows 11 host
Guest OS: Ubuntu 22.04.5 LTS Desktop (64-bit)
Resources allocated: 8 vCPUs, 32 GB RAM, 120 GB dynamic disk

The reasons for allocating the amount of disk space and RAM was to ensure perfomance when loading the dataset was not an issue. As well as this, when i was investigating the dataset i did not want to have to wait ages everytime i searched. 

## **Instillation steps were as follows.**
1. VMware VM created with VMware Tools installed for optimal performance.
2. Ubuntu installed using download from the DLE [Proof of Ubuntu Download](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-04%20150243.png)
3. Upon Successfull download i made sure to check for any Ubuntu Updates
4. Splunk Enterprise 9.2.2 installed via official site. [Proof of Splunk Liscense](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-06%20131916.png)
5. Download of BOTSv3 Dataset from DLE on the VM
6. BOTSv3 dataset ingested using the official one-shot script from https://github.com/splunk/botsv3. 
7. Validation: index=botsv3 | stats count by sourcetype returned 38 sourcetypes and over 24 million events.


# **Findings of the Investigation**
all searches make use of index=botsv3 earliest=0 in order to ensure i am looking through not only the correct dataset but also the full version of it.

### **4.1 IAM Users Accessing AWS Services**

**SPL Query**
splindex=botsv3 sourcetype="aws:cloudtrail" userIdentity.type="IAMUser" 
| stats values(userIdentity.userName) as IAM_Users 
| mvexpand IAM_Users 
| sort IAM_Users 
| table IAM_Users

**Result**
bstoll,btun,splunk_access,web_admin

**Significance**
this provides me with a starting point of all users within the enviroment. this is an essental Tier 2 SOC task. if a new and often unused d account started to suddenly access the AWS a lot and acting unusal it coud point towards someones account being comprosed and misused.






### **4.2 Field to Detect AWS Actions Without MFA**

**SPL Query**
splindex=botsv3 sourcetype="aws:cloudtrail" NOT eventName="ConsoleLogin" "mfaAuthenticated"
| table _time, eventName, userIdentity.sessionContext.attributes.mfaAuthenticated

**Result**
userIdentity.sessionContext.attributes.mfaAuthenticated

**Significance**
Multi layered authentication provides an extra layer of security. Using AWS without having MFA on your account is risky because having your password stolen would give the attacker full acccess to your account.  




### **4.3 Processor Used on the Web Servers**

**SPL Query**
splindex=botsv3 sourcetype=hardware host="gacrux.i-*"
| stats values(CPU_TYPE) as Processor by host
| table host, Processor

**Answer**
E5-2676 

**Significance**
confiming that the same processor is used across all of the web servers allows the SOC team to ensure that there is not a risk of a security breach due to hardware lagging behind. if a server was differnt it would be flagged here and could indicate that theer has been another sever added to the network without permission 



### **4.4 Event ID That Made the S3 Bucket Public**

**SPL Query**
splindex=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| sort _time
| table _time, eventID, userIdentity.userName

**Answer**
ab45689d-69cd-41e7-8705-5350402cf7ac

**Significance**
this is the exact moment that a user made a storage bucket public to anyone on the internet. a storage bucket is like a folder in the clooud where you can store files, images, logs, backups. this alows the SOC team to pinpoint the beginning of an incident and work forwards from there so it is very valuble information to identify.


### **4.5 Username That Made the Change**

**SPL Query**
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| sort _time
| table _time, eventID, userIdentity.userName

**Answer**
Bstoll

**Significance**
knowing who made the change allows for the SOC to either talk to that person and provde them with an exaplantion o n the dangers of their actions and possibly futher training if needed or remvoe their access entrly. either way idenfiying uses when they do something bad is a big and important step in an SOC job


### **4.6 Name of Identifyed Public Bucket**

**SPL Query**
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| spath input=requestParameters bucketName
| table bucketName

**Answer**
frothlywebcode

**Significance**
once the SOC knows whch bucket was made publically avalible they are able to view the contents of the bucket and idenfty exactly how senstive the data it contains is or not. 



### **4.7 Text File Uploaded While the Bucket Was Public**

**SPL Query**
index=botsv3 sourcetype="aws:s3:accesslogs" bucket_name="frothlywebcode" 
operation="REST.PUT.OBJECT" status=200 *.txt
| table _time, key, status
| sort _time

**Answer**
OPEN_BUCKET_PLEASE_FIX.txt

**Significance**
within a few minutes someone from outside of the organsation was able to uploaed a file to the bucket. while the file thye uplaoded was just a txt file there was a real poibbility of a person uploading more malicioys software and potentally gaining access.


# **Conclusion**

# **AI **

# **References:**
[1] Splunk, "BOTSv3 Dataset," GitHub, 2020. [Online]. Available: https://github.com/splunk/botsv3.


