# The Temporal Score Database v2

## What is the temporal score database?
The temporal score database is a python script that pulls data from NVD, MITRE, EPSS, Nuclei, ExploitDB, Github, and Metasploit to enrich CVSS data. The database provides a daily .xlsx file which pulls from the aforementioned sources, and calculates the temporal vector, score, and severity for all CVEs published by NVD or MITRE. The main aim is to provide intelligence and clarity for all security professionals to sort through the constant noise of vulnerability disclosures. This can be used as part of the vulnerability decision tree. The database was thought of to supplement the [vulnerability decision tree.](https://github.com/mmmporkbelly/vulnerability_decision_tree/blob/main/README.md)

> [!NOTE]
> Check out the [temporal score database web application](https://temporalscoredatabase.com/) to see the information that can be pulled by the script. Please keep in mind that this web app was only made to present the information that can be pulled in a UI - it is not a robust web app.

## Does it actually have an impact?
Yes! If you agree with the calculation method (see below), the web app shows the before and after in calculations for all CVEs that are published. As of 6/13/24, here is the breakdown by the numbers:

 - Critical Severity CVEs - 27538 Criticals to 604 Criticals 
 - High Severity CVEs - 106088 Highs to 63566 Highs 
 - Medium Severity CVEs - 118591 Mediums to 157053 Mediums 
 - Low Severity CVEs - 9274 Lows to 40268 Lows 

## How is everything calculated?
*Please keep in mind that the database is by no means a silver bullet. The point of this database is to sort through the noise by automating temporal score calculations, but it is by no means complete or perfect.*

The following exploit sources are used:
 - ExploitDB
 - Metasploit
 - EPSS (If score is above 40%)
 - CISA KEV
 - Github
 - Nuclei
 - Packet Storm
 - Google Project Zero
 - Vulncheck
 - Ransomware Affiliation through CISA KEV
 
 Exploit code maturity (E:) is calculated in the following manner. 
 - Unproven (U): No sources are flagging for exploit code. 
 - Proof of Concept (P): 1 to 3 sources are flagging for exploit code.
 - Functional (F): 4 to 6 sources are flagging for exploit code.
 - High(H): 7+ sources are flagging for exploit code.
 
 Remediation Level (RL) is calculated in the following manner.
 - Unavailable (U): No hyperlink is provided
 - Temporary Fix (T): NVD provides a hyperlink - most vulnerabilities that warrant an article usually have
 some sort of workaround provided by the product owner
 - Official Fix (O): NVD provides a hyperlink with a tag labeled as "patch"
 
 Report Confidence is calculated in the following manner.
 - Unknown (U): MITRE or NVD mark CVE as "REJECTED"
 - Reasonable (R): MITRE or NVD mark CVE as "Received", "Awaiting Analysis", or "Undergoing Analysis"
 - Confirmed (C): MITRE or NVD mark CVE as "Anaylzed", "Published", or "Modified"

## Great! Can I use it? Do I have to edit it in any way?
This is an opensourced passion project - please refer to license for further information.


## How can I view the data?
The recommended method is to build a container (docker file included in code) and run it on a daily basis. The code is currently formatted to support AWS services, including secrets manager and uploading/downloading to an S3 bucket.

## You mentioned secrets manager. Does it use any keys?
Yes, but only an NVD API and Vulncheck API key. That key is not necessary to actually pull the data, you will just be rate limited without it. 
