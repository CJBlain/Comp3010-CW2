# Comp3010-CW2

#### Connor Blain

#### Comp3010 Report and Analysis on BOTSv3 Dataset

#### Link to Video: https://youtu.be/uiULlUSjwZk


# **Introduction:** 
An SOC (Security Operations Centre), serves as a central hub for monitoring, detecting, analysing and responding to real time cyber security threats. The Botsv3 dataset that has been used in this report allows you to practise these skills. The dataset simualtes a security incident at a fake brewing company called frothy. The datset provides the user with a wide range of logs, these range from emails to to network endpoints. on top of all of that, the BOTSv3 Dataset also includes logs from cloud services such a amazon web services and microsft azure.

The Primary purpose of the investation will be to analyse anolomises related to AWS and answer the set of level 200 questions. 

### Assumptions made:
+ All logs in BOTSv3 are trusted and correctly timestamped.
+ The investigation is retrospective (post-incident analysis).



# **SOC Roles & Incident Handling Reflection:**
in real life, a security operations centre uses 3 tiers to handle secuity incidents. These are as follows:
+ Tier 1 (Alert Triage) defined as initial alert review and validation.
+ Tier 2 (Incident Analysis) defined as deep investigation, correlation, and root cause analysis.
+ Tier 3 (Threat Hunting & Engineering) defiend as advanced analysis, detection engineering, and remediation.

The BOTSv3 exercise mostly focuses around the responsabilities of the second tier. This means that it requires log analysis, following evidence to form conclusions and linking data together to form corralations.


# **Installation & Data Preparation:**
The envirmmoment to complete this exercise was swtup to closely miror real world SOC lab infrastructure. 
**Host:** VMware Workstation Pro 17 on Windows 11 host
**Guest OS:** Ubuntu 22.04.5 LTS Desktop (64-bit)
**Resources allocated:** 8 vCPUs, 32 GB RAM, 120 GB dynamic disk

The reasons for allocating the amount of disk space and RAM was to ensure perfomance when loading the dataset was not an issue. As well as this, when i was investigating the dataset i did not want to have to wait ages everytime i searched. 

## **Instillation steps were as follows.**
1. VMware VM created with VMware Tools installed for optimal performance.
2. Ubuntu installed using download from the DLE [Proof of Ubuntu Download](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-04%20150243.png)
3. Upon Successfull download i made sure to check for any Ubuntu Updates
4. Splunk Enterprise 9.2.2 installed via official site. [Proof of Splunk Liscense](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202025-12-06%20131916.png)
5. Download of BOTSv3 Dataset from DLE on the VM
6. BOTSv3 dataset ingested using the official one-shot script from https://github.com/splunk/botsv3. [Proof of Ingestion](https://github.com/CJBlain/Comp3010-CW2/blob/main/proof%20of%20botsv3%20ingestion%20picture%201.png)
7. Validation: index=botsv3 | stats count by sourcetype returned 38 sourcetypes and over 24 million events. [Proof of Ingestion Result](https://github.com/CJBlain/Comp3010-CW2/blob/main/proof%20of%20botsv3%20ingestion%20picture%202.png)


# **Findings of the Investigation**
all searches make use of index=botsv3 earliest=0 in order to ensure i am looking through not only the correct dataset but also the full version of it.

### **4.1 IAM Users Accessing AWS Services**

**SPL Query:**

splindex=botsv3 sourcetype="aws:cloudtrail" userIdentity.type="IAMUser" 
| stats values(userIdentity.userName) as IAM_Users 
| mvexpand IAM_Users 
| sort IAM_Users 
| table IAM_Users

**Result:**

bstoll,btun,splunk_access,web_admin

**Significance:**

this provides me with a starting point of all users within the enviroment. this is an essental Tier 2 SOC task. if a new and often unused d account started to suddenly access the AWS a lot and acting unusal it coud point towards someones account being comprosed and misused.

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20Q1.png)





### **4.2 Field to Detect AWS Actions Without MFA**

**SPL Query:**

splindex=botsv3 sourcetype="aws:cloudtrail" NOT eventName="ConsoleLogin" "mfaAuthenticated"
| table _time, eventName, userIdentity.sessionContext.attributes.mfaAuthenticated

**Result**

userIdentity.sessionContext.attributes.mfaAuthenticated

**Significance:**

Multi layered authentication provides an extra layer of security. Using AWS without having MFA on your account is risky because having your password stolen would give the attacker full acccess to your account.  

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20q2.png)



### **4.3 Processor Used on the Web Servers**

**SPL Query:**

splindex=botsv3 sourcetype=hardware host="gacrux.i-*"
| stats values(CPU_TYPE) as Processor by host
| table host, Processor

**Result:**

E5-2676 

**Significance:**

confirming that the same processor is used across all of the web servers allows the SOC team to ensure that there is not a risk of a security breach due to hardware lagging behind. if a server was differnt it would be flagged here and could indicate that theer has been another sever added to the network without permission 

### **4.4 Event ID That Made the S3 Bucket Public**

**SPL Query:**

splindex=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| sort _time
| table _time, eventID, userIdentity.userName

**Result:**

ab45689d-69cd-41e7-8705-5350402cf7ac

**Significance:**

this is the exact moment that a user made a storage bucket public to anyone on the internet. a storage bucket is like a folder in the clooud where you can store files, images, logs, backups. this alows the SOC team to pinpoint the beginning of an incident and work forwards from there so it is very valuble information to identify.

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20q4.png)

### **4.5 Username That Made the Change**

**SPL Query:**

index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| sort _time
| table _time, eventID, userIdentity.userName

**Result:**

Bstoll

**Significance:**

knowing who made the change allows for the SOC to either talk to that person and provde them with an exaplantion o n the dangers of their actions and possibly futher training if needed or remvoe their access entrly. either way idenfiying uses when they do something bad is a big and important step in an SOC job

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20q5.png)

### **4.6 Name of Identifyed Public Bucket:**

**SPL Query:**

index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" "AllUsers"
| spath input=requestParameters bucketName
| table bucketName

**Result:**

frothlywebcode

**Significance:**

once the SOC knows whch bucket was made publically avalible they are able to view the contents of the bucket and idenfty exactly how senstive the data it contains is or not. 

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20q6.png)


### **4.7 Text File Uploaded While the Bucket Was Public:**

**SPL Query:**

index=botsv3 sourcetype="aws:s3:accesslogs" bucket_name="frothlywebcode" 
operation="REST.PUT.OBJECT" status=200 *.txt
| table _time, key, status
| sort _time

**Result:**

OPEN_BUCKET_PLEASE_FIX.txt

**Significance:**

within a few minutes someone from outside of the organsation was able to uploaed a file to the bucket. while the file thye uplaoded was just a txt file there was a real poibbility of a person uploading more malicioys software and potentally gaining access.


### **4.8 Computer Running a Different Windows Version**

**SPL Query:**

index=botsv3 sourcetype=winhostmon
| stats values(OS) as OS by host
| where OS != "Microsoft Windows 10 Pro"
| table host, OS

**Result:**

BSTOLL-L.froth.ly

**Significance:**

Most company computers run the same version of Windowws. One different version often means it’s a more powerful admin or developer machine. These compters are bigger targets for attackers. The SOC needs to watch them more closely and make sure they have extra protection.

[Proof of Investigation](https://github.com/CJBlain/Comp3010-CW2/blob/main/botsv3%20q8.png)


# **Conclusion**
the investigation inside this report showed how a small mistake in the cloud can quickly turn into a real security problem. An employee (bstoll) accidentally changed the settings on an AWS S3 bucket called frothlywebcode, making it open to anyone on the internet. Within minutes, someone from outside uploaded a file to prove the bucket was exposed. had this been a malicaious file rather than just a plain txt file the sition coul #d have turned very nasty. While the main focus of the investiagion centres around this exposed bucuket, the analysis also highlihted other important details, such as which user accounts were active in AWS, actions taken without multi-factor authentication, consistent hardware on web servers, and one computer running a different version of Windows.
The incident demostrates  why good logging is essential. Without AWS CloudTrail and S3 access logs (which show who accessed the bucket), the SOC would have had no idea this happened.

### **What I have learned from this coursework:**

1. Cloud logs are just as important as computer logs. The amount fo data that passess through the cloud makes it a valuable access point for people will bad intentions 
3. Simple mistakes (like making a storage bucket public) can have big consequences. this also highlights jsut how important being able to trace every action within your server is.
2. Knowing the normal hardware helps spot issues quickly. By checking the processor versions as seen in q3. the SOC was able to dertime if any other actors had gained access and added thier own server.
3. Clear evidence and attribution make response easier. Being able to say exactly who did what and when allows for imedate correction of proo practses or limitng access.
4. Splunk is a powerful tool for joining up different logs and finding the story behind an incident.

Overall, this exercise gave me a practical understanding of how a real SOC analyst works: spotting problems through logs, rebulding what happened, and suggesting ways to make the environment safer. It also showed the value of careful setup  and clear documenation with screenshots and queries.

# **AI as a tool in an SOC Investigation**
Artificial Intelligence is becoming an important assisstant in SOC's, working best as a partner to human analysts rather than a replacement. In a typical investigation, AI can quickly handle large amounts of data that would take people much longer to review.
For example, AI-powered tools in Splunk can automatically group similar alerts, spot unusual patterns in user behaviour, or highlight the most serious events from thousands of daily logs. Machine learning models can learn what “normal” looks like for a company’s network and flag anything that doesn’t fit
However, if you were only to rely soley on AI you would be exposing your server and your company to great risk. AI lacks the human element and often will due view secuity elements as black and white. a much better option is for humans to ay on AI to streamline ther own knowlege rather than an outright replacement for what they dont know. 

During an investigation like the BOTSv3 exercise, generative AI are a solid option to analysts by doing tasks such as suggesting or improving Splunk queries, explaining unfamiliar log fields, summarising long event descriptions, or drafting clear report sections. This saves time and helps less experienced analysts work faster and more confidently.
AI is also useful for suggesting detection rules. After finding a publc S3 bucket misconfiguration, AI can recommend a ready-to-use Splunk alert to catch similar problems in future. Hpwever, a lot of SOC handle very sentive company data and by allowing the data to be accessed byu the AI you could protenally be comprsing company trade secrets like financial data.

In order to highlight this point of using AI as a tool rather than a replacemnt, i fed relevent parts of the dataset to grok and asked him to expand on parts where my knowledge was lacking. As you can see in the image below, using him to expand on points i was unsure about makes me a better SOC security operator. If i just used it to do all the investigations for me i would never learn anything for myself.

[Expansion of Knowledge using AI](https://github.com/CJBlain/Comp3010-CW2/blob/main/Screenshot%202026-01-08%20204901.png?raw=true)

# **References:**
[1] Splunk, "BOTSv3 Dataset," GitHub, 2020. [Online]. Available: https://github.com/splunk/botsv3.
[2] Github Docs, Basic writing and formatting syntax, Avaiable at https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax


