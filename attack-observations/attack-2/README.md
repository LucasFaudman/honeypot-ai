
# Attack: 7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `1` unique source IP address(es): `91.92.251.103`
- A total of `19` sessions were logged. `2` sessions were successful logins.
- `50` login attempts were made. `2` were successful.
- `25` unique username/password pairs were attempted. `1` were successful.
- `1` unique destination ports were targeted: `2222`
- `19` unique source ports were used:  Min: 33434, Max: 60038
- `12` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `0` unique malware samples were downloaded. `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: `cowrie.log`, `cowrie.json`, `dshield.log`
- A total of `974` log events were logged in `34` log files: `notice.log`, `notice.log`, `cowrie.2023-12-06.json`, `cowrie.2023-12-06.json`, `conn.log`, `conn.log`, `ssh.log`, `ssh.log`, `cowrie.json`, `cowrie.json`, `auth_random.json`, `auth_random.json`, `cowrie.2023-12-02.json`, `cowrie.2023-12-02.json`, `cowrie.log`, `cowrie.log`, `cowrie.2023-12-06.log`, `cowrie.2023-12-06.log`, `cowrie.2023-12-04.log`, `cowrie.2023-12-04.log`, `cowrie.2023-12-05.log`, `cowrie.2023-12-05.log`, `cowrie.2023-12-02.log`, `cowrie.2023-12-02.log`, `cowrie.2023-12-03.log`, `cowrie.2023-12-03.log`, `cowrie.2023-12-03.json`, `cowrie.2023-12-03.json`, `cowrie.2023-12-04.json`, `cowrie.2023-12-04.json`, `cowrie.2023-12-05.json`, `cowrie.2023-12-05.json`, `dshield.log`, `dshield.log`

</details>

---

# Executive Summary of Attack

## Attack Details
Throughout the course of the observed attack, multiple reconnaissance commands were executed from the source IP address `91.92.251.103` targeting a honeypot with the intent to gather information about the system's architecture, running processes, and resources.

The commands used were indicative of an attacker in the information-gathering phase, with no direct evidence of a specific vulnerability being exploited. The consistent use of SSH from the attacking IP with a unique HASSH (`a7a87fbe86774c2e40cc4a7ea2ab1b3c`) and version (`SSH-2.0-libssh2_1.8.2`) suggests a systematic and potentially automated approach focused on profiling the system.

The destination port used for the attack was `2222`, indicating that the attacker may have been attempting to exploit a service running on this non-standard SSH port.

## Methods
The methods employed in the attack are consistent with an initial reconnaissance and probing stage of the Cyber Kill Chain:

1. **System Profiling**: Gathering hardware and system information using commands like `uname -a` and `cat /proc/cpuinfo`.
2. **Resource Discovery**: Checking available system resources with `free -m`.
3. **Service Enumeration**: Listing running processes via `ps -x`.
4. **Virtualization Detection**: Searching for evidence of a virtualized environment using `dmesg | grep irtual`.
5. **SSH Fingerprinting**: Establishing SSH connections to determine the SSH version and client fingerprint.

OSINT sources identified the IP as being associated with malicious activities, flagged in various threat intelligence feeds, and implicated the IP in scanning and brute-force activities, particularly involving SSH services.

## Goals
The goals of the attack appear to be focused on the following:

- **Gathering Intelligence**: The attacker is likely attempting to compile information in preparation for further, more targeted attacks.
- **Identifying Vulnerabilities**: The collected data could be used to pinpoint weaknesses for future exploitation.
- **Preparing for Secondary Actions**: Information such as system specifications and running services could be groundwork for designing specific attacks like resource exhaustion or privilege escalation.

The honeypot nature of the target implies that the attacker may not have breached an actual production system. Nevertheless, the attack pattern can offer insights into the attacker's capabilities and methods.

---

It's important to keep in mind that these findings are based on the observed evidence and may not fully encapsulate the assailant's intentions or capabilities, especially in the absence of more overtly malicious activities such as malware deployment or data exfiltration.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `1` unique **source IP** address(es):
	- `SourceIP 91.92.251.103 with 19 sessions, 1 dst_ports 2 successful logins, 12 commands, 0 uploads, 0 downloads`

- `19` unique **source ports** were used:
	- `Src Port: 36574 Used 1 times`
	- `Src Port: 44494 Used 1 times`
	- `Src Port: 58640 Used 1 times`
	- `Src Port: 48304 Used 1 times`
	- `Src Port: 41420 Used 1 times`
	- `Src Port: 42226 Used 1 times`
	- `Src Port: 48332 Used 1 times`
	- `Src Port: 49896 Used 1 times`
	- `Src Port: 38270 Used 1 times`
	- `Src Port: 33622 Used 1 times`
	- `Src Port: 41974 Used 1 times`
	- `Src Port: 36728 Used 1 times`
	- `Src Port: 58552 Used 1 times`
	- `Src Port: 54436 Used 1 times`
	- `Src Port: 35896 Used 1 times`
	- `Src Port: 44536 Used 1 times`
	- `Src Port: 33434 Used 1 times`
	- `Src Port: 60038 Used 1 times`
	- `Src Port: 59472 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2222` Used `19` times`

- A total of `19` sessions were logged:
	- `Session f5ed34cc200c SSH 91.92.251.103:36574 -> 172.31.5.68:2222 Duration: 0.93s`
	- `Session bc1f43521f52 SSH 91.92.251.103:44494 -> 172.31.5.68:2222 Duration: 0.94s`
	- `Session 2f7877d1cbff SSH 91.92.251.103:58640 -> 172.31.5.68:2222 Duration: 0.93s`
	- `Session 13da7b98b8d4 SSH 91.92.251.103:48304 -> 172.31.5.68:2222 Login: 0aduserog34oxf4Bsf4Bsr_wasadmin:og34oxf4Bsf4Bsr_ Commands: 6, Duration: 8.43s`
	- `Session e166fbd15baa SSH 91.92.251.103:41420 -> 172.31.5.68:2222 Login: 0aduserog34oxf4Bsf4Bsr_wasadmin:og34oxf4Bsf4Bsr_ Commands: 6, Duration: 8.43s`
	- `Session 8a50f940d559 SSH 91.92.251.103:42226 -> 172.31.5.68:2222 Duration: 13.57s`
	- `Session 6ca4de9ec1e7 SSH 91.92.251.103:48332 -> 172.31.5.68:2222 Duration: 13.56s`
	- `Session 5ae75a25729b SSH 91.92.251.103:49896 -> 172.31.5.68:2222 Duration: 13.54s`
	- `Session 2287dbb6f09e SSH 91.92.251.103:38270 -> 172.31.5.68:2222 Duration: 13.55s`
	- `Session 71b5cf767ec8 SSH 91.92.251.103:33622 -> 172.31.5.68:2222 Duration: 13.56s`
	- `Session 171f7939c1c0 SSH 91.92.251.103:41974 -> 172.31.5.68:2222 Duration: 13.53s`
	- `Session c9443f6dfbbe SSH 91.92.251.103:36728 -> 172.31.5.68:2222 Duration: 13.52s`
	- `Session b42d063052f6 SSH 91.92.251.103:58552 -> 172.31.5.68:2222 Duration: 13.65s`
	- `Session da1009d1e15f SSH 91.92.251.103:54436 -> 172.31.5.68:2222 Duration: 13.66s`
	- `Session c9b83c291ef9 SSH 91.92.251.103:35896 -> 172.31.5.68:2222 Duration: 13.53s`
	- `(and `4` more)`

- `2` were **successful logins**, 
- `17` were **failed logins**, 
- `2` had commands, 
- `0` had malware.
- `50` unique username/password pairs were attempted. `2` were successful.
- `12` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `0` unique malware samples were downloaded. 
- `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `dshield.log`

- A total of `974` log events were logged in `26` log files: 
	- `notice.log`
	- `notice.log`
	- `cowrie.2023-12-06.json`
	- `cowrie.2023-12-06.json`
	- `conn.log`
	- `conn.log`
	- `ssh.log`
	- `ssh.log`
	- `cowrie.json`
	- `cowrie.json`
	- `auth_random.json`
	- `auth_random.json`
	- `cowrie.2023-12-02.json`
	- `cowrie.2023-12-02.json`
	- `cowrie.log`
	- `cowrie.log`
	- `cowrie.2023-12-06.log`
	- `cowrie.2023-12-06.log`
	- `cowrie.2023-12-04.log`
	- `cowrie.2023-12-04.log`
	- `cowrie.2023-12-05.log`
	- `cowrie.2023-12-05.log`
	- `cowrie.2023-12-02.log`
	- `cowrie.2023-12-02.log`
	- `cowrie.2023-12-03.log`
	- `cowrie.2023-12-03.log`
	- `cowrie.2023-12-03.json`
	- `cowrie.2023-12-03.json`
	- `cowrie.2023-12-04.json`
	- `cowrie.2023-12-04.json`
	- `cowrie.2023-12-05.json`
	- `cowrie.2023-12-05.json`
	- `dshield.log`
	- `dshield.log`


</details>

---


<details>
<summary>
<h1>Custom Scripts Used To Generate This Report</h1>
</summary>


| Script | Description |
| --- | --- |
| [logparser.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/logparser.py) | Base class for reading all logs as json objects with standardized keys |
| [cowrieloganalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/cowrieloganalyzer.py) | Python script for Analyzing Cowrie logs |
| [webloganalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/webloganalyzer.py) | Python script for Analyzing Web logs |
| [soupscraper.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/soupscraper.py) | Base class for scraping web pages with BeautifulSoup and Selenium |
| [ipanalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/ipanalyzer.py) | Python script for Analyzing IP addresses and domains |
| [markdownwriter.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriter.py) | Python for writing markdown files |
| [getlogsbyip.sh](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/getlogsbyip.sh) | Bash script for getting all logs for a given IP address |

</details>

---


<details>
<summary>
<h1>Time and Date of Activity</h1>
</summary>

First activity logged: `2023-12-02 19:28:16.497532`
* First session: `f5ed34cc200c`
* `Session f5ed34cc200c SSH 91.92.251.103:36574 -> 172.31.5.68:2222 Duration: 0.93s`

Last activity logged: `2023-12-07 01:07:09.074895`
* Last session: `3469b768a0ac`
* `Session 3469b768a0ac SSH 91.92.251.103:59472 -> 172.31.5.68:2222 Duration: 17.78s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `f5ed34cc200c` | `91.92.251.103` | `36574` | `2222` | `2023-12-02 19:28:16.497532` | `2023-12-02 19:28:17.432699` | `0.9344992637634277` |
| `3469b768a0ac` | `91.92.251.103` | `59472` | `2222` | `2023-12-07 01:06:51.297514` | `2023-12-07 01:07:09.074895` | `17.776742458343506` |

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `f5ed34cc200c` | `91.92.251.103` | `36574` | `2222` | `2023-12-02 19:28:16.497532` | `2023-12-02 19:28:17.432699` | `0.9344992637634277` |
| `bc1f43521f52` | `91.92.251.103` | `44494` | `2222` | `2023-12-03 11:59:43.480980` | `2023-12-03 11:59:44.417945` | `0.9363150596618652` |
| `2f7877d1cbff` | `91.92.251.103` | `58640` | `2222` | `2023-12-03 16:54:40.668565` | `2023-12-03 16:54:41.598593` | `0.9293694496154785` |
| `13da7b98b8d4` | `91.92.251.103` | `48304` | `2222` | `2023-12-04 18:43:33.363701` | `2023-12-04 18:43:41.792404` | `8.428016185760498` |
| `e166fbd15baa` | `91.92.251.103` | `41420` | `2222` | `2023-12-04 18:46:36.125942` | `2023-12-04 18:46:44.553006` | `8.426405906677246` |
| `8a50f940d559` | `91.92.251.103` | `42226` | `2222` | `2023-12-04 22:11:08.076253` | `2023-12-04 22:11:21.642929` | `13.56601095199585` |
| `6ca4de9ec1e7` | `91.92.251.103` | `48332` | `2222` | `2023-12-04 22:14:08.650801` | `2023-12-04 22:14:22.207893` | `13.556434869766235` |
| `5ae75a25729b` | `91.92.251.103` | `49896` | `2222` | `2023-12-05 01:39:55.712880` | `2023-12-05 01:40:09.251007` | `13.537481784820557` |
| `2287dbb6f09e` | `91.92.251.103` | `38270` | `2222` | `2023-12-05 01:42:54.974142` | `2023-12-05 01:43:08.527766` | `13.55178689956665` |
| `71b5cf767ec8` | `91.92.251.103` | `33622` | `2222` | `2023-12-05 08:47:54.963542` | `2023-12-05 08:48:08.527915` | `13.56369948387146` |
| `171f7939c1c0` | `91.92.251.103` | `41974` | `2222` | `2023-12-05 08:50:41.739853` | `2023-12-05 08:50:55.269193` | `13.528660297393799` |
| `c9443f6dfbbe` | `91.92.251.103` | `36728` | `2222` | `2023-12-05 19:22:35.850645` | `2023-12-05 19:22:49.372661` | `13.521352529525757` |
| `b42d063052f6` | `91.92.251.103` | `58552` | `2222` | `2023-12-05 19:25:24.905186` | `2023-12-05 19:25:38.559458` | `13.653622388839722` |
| `da1009d1e15f` | `91.92.251.103` | `54436` | `2222` | `2023-12-05 22:37:14.807785` | `2023-12-05 22:37:28.465703` | `13.657275676727295` |
| `c9b83c291ef9` | `91.92.251.103` | `35896` | `2222` | `2023-12-05 22:40:02.975976` | `2023-12-05 22:40:16.504224` | `13.52758526802063` |
| `82ff747a0bcb` | `91.92.251.103` | `44536` | `2222` | `2023-12-06 21:09:18.111418` | `2023-12-06 21:09:35.929956` | `17.81783962249756` |
| `8733d5249d99` | `91.92.251.103` | `33434` | `2222` | `2023-12-06 21:12:39.345418` | `2023-12-06 21:12:57.103772` | `17.757590532302856` |
| `800b214ea789` | `91.92.251.103` | `60038` | `2222` | `2023-12-07 01:03:32.024035` | `2023-12-07 01:03:49.784164` | `17.75946879386902` |
| `3469b768a0ac` | `91.92.251.103` | `59472` | `2222` | `2023-12-07 01:06:51.297514` | `2023-12-07 01:07:09.074895` | `17.776742458343506` |

</details>

---


</details>

---


<details>
<summary>
<h1>Relevant Logs, File or Email</h1>
</summary>


## Log Stats

| Log Name | Lines |
| --- | --- |
| cowrie.log | 570 |
| cowrie.json | 352 |
| dshield.log | 52 |

## Cowrie .log Logs
Total Cowrie logs: `570`

#### First Session With Commands 13da7b98b8d4 Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `13da7b98b8d4` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .log Logs for 13da7b98b8d4</h3>
</summary>


```verilog
2023-12-07T01:03:32.024769Z [HoneyPotSSHTransport,703,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-07T01:03:32.163503Z [HoneyPotSSHTransport,703,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-07T01:03:32.986530Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 41
2023-12-07T01:03:32.986685Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:33.036735Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!@#qweasd'] failed
2023-12-07T01:03:37.189411Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 42
2023-12-07T01:03:37.189550Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:37.240727Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!Q@W#E'] failed
2023-12-07T01:03:41.391785Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 43
2023-12-07T01:03:41.391916Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:41.441654Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!QAZ1qaz'] failed
2023-12-07T01:03:45.594237Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 44
2023-12-07T01:03:45.594362Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:45.643420Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!QAZ2wsx'] failed
2023-12-07T01:03:49.784164Z [HoneyPotSSHTransport,703,91.92.251.103] Connection lost after 17 seconds
2023-12-07T01:06:51.298252Z [HoneyPotSSHTransport,720,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-07T01:06:51.435881Z [HoneyPotSSHTransport,720,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-07T01:06:52.263113Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 45
2023-12-07T01:06:52.263219Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:06:52.314357Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!@#qweasd'] failed
2023-12-07T01:06:56.485050Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 46
2023-12-07T01:06:56.485213Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:06:56.535692Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!Q@W#E'] failed
2023-12-07T01:07:00.686006Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 47
2023-12-07T01:07:00.686124Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:07:00.735686Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!QAZ1qaz'] failed
2023-12-07T01:07:04.885842Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 48
2023-12-07T01:07:04.885981Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:07:04.934939Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!QAZ2wsx'] failed
2023-12-07T01:07:09.074895Z [HoneyPotSSHTransport,720,91.92.251.103] Connection lost after 17 seconds
2023-12-07T01:03:32.024769Z [HoneyPotSSHTransport,703,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-07T01:03:32.163503Z [HoneyPotSSHTransport,703,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-07T01:03:32.986530Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 41
2023-12-07T01:03:32.986685Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:33.036735Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!@#qweasd'] failed
2023-12-07T01:03:37.189411Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 42
2023-12-07T01:03:37.189550Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:37.240727Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!Q@W#E'] failed
2023-12-07T01:03:41.391785Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 43
2023-12-07T01:03:41.391916Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:41.441654Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!QAZ1qaz'] failed
2023-12-07T01:03:45.594237Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt: 44
2023-12-07T01:03:45.594362Z [HoneyPotSSHTransport,703,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:03:45.643420Z [HoneyPotSSHTransport,703,91.92.251.103] login attempt [b'admin'/b'!QAZ2wsx'] failed
2023-12-07T01:03:49.784164Z [HoneyPotSSHTransport,703,91.92.251.103] Connection lost after 17 seconds
2023-12-07T01:06:51.298252Z [HoneyPotSSHTransport,720,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-07T01:06:51.435881Z [HoneyPotSSHTransport,720,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-07T01:06:52.263113Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 45
2023-12-07T01:06:52.263219Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:06:52.314357Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!@#qweasd'] failed
2023-12-07T01:06:56.485050Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 46
2023-12-07T01:06:56.485213Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:06:56.535692Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!Q@W#E'] failed
2023-12-07T01:07:00.686006Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 47
2023-12-07T01:07:00.686124Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:07:00.735686Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!QAZ1qaz'] failed
2023-12-07T01:07:04.885842Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt: 48
2023-12-07T01:07:04.885981Z [HoneyPotSSHTransport,720,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-07T01:07:04.934939Z [HoneyPotSSHTransport,720,91.92.251.103] login attempt [b'admin'/b'!QAZ2wsx'] failed
2023-12-07T01:07:09.074895Z [HoneyPotSSHTransport,720,91.92.251.103] Connection lost after 17 seconds
2023-12-06T21:09:18.112229Z [HoneyPotSSHTransport,226,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-06T21:09:18.254631Z [HoneyPotSSHTransport,226,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-06T21:09:19.106354Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 33
2023-12-06T21:09:19.106483Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:19.157379Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$%^&*'] failed
2023-12-06T21:09:23.309011Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 34
2023-12-06T21:09:23.309124Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:23.358463Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$%^qwerty'] failed
2023-12-06T21:09:27.512984Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 35
2023-12-06T21:09:27.513133Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:27.562502Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$abcd,'] failed
2023-12-06T21:09:31.732866Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 36
2023-12-06T21:09:31.733033Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:31.782183Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$qwerASDF'] failed
2023-12-06T21:09:35.929956Z [HoneyPotSSHTransport,226,91.92.251.103] Connection lost after 17 seconds
2023-12-06T21:12:39.346240Z [HoneyPotSSHTransport,229,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-06T21:12:39.486299Z [HoneyPotSSHTransport,229,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-06T21:12:40.307361Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 37
2023-12-06T21:12:40.307469Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:40.357707Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$%^&*'] failed
2023-12-06T21:12:44.507493Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 38
2023-12-06T21:12:44.507631Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:44.559656Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$%^qwerty'] failed
2023-12-06T21:12:48.712018Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 39
2023-12-06T21:12:48.712197Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:48.761240Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$abcd,'] failed
2023-12-06T21:12:52.911812Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 40
2023-12-06T21:12:52.911920Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:52.961388Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$qwerASDF'] failed
2023-12-06T21:12:57.103772Z [HoneyPotSSHTransport,229,91.92.251.103] Connection lost after 17 seconds
2023-12-06T21:09:18.112229Z [HoneyPotSSHTransport,226,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-06T21:09:18.254631Z [HoneyPotSSHTransport,226,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-06T21:09:19.106354Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 33
2023-12-06T21:09:19.106483Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:19.157379Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$%^&*'] failed
2023-12-06T21:09:23.309011Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 34
2023-12-06T21:09:23.309124Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:23.358463Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$%^qwerty'] failed
2023-12-06T21:09:27.512984Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 35
2023-12-06T21:09:27.513133Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:27.562502Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$abcd,'] failed
2023-12-06T21:09:31.732866Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt: 36
2023-12-06T21:09:31.733033Z [HoneyPotSSHTransport,226,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:09:31.782183Z [HoneyPotSSHTransport,226,91.92.251.103] login attempt [b'admin'/b'!@#$qwerASDF'] failed
2023-12-06T21:09:35.929956Z [HoneyPotSSHTransport,226,91.92.251.103] Connection lost after 17 seconds
2023-12-06T21:12:39.346240Z [HoneyPotSSHTransport,229,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-06T21:12:39.486299Z [HoneyPotSSHTransport,229,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-06T21:12:40.307361Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 37
2023-12-06T21:12:40.307469Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:40.357707Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$%^&*'] failed
2023-12-06T21:12:44.507493Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 38
2023-12-06T21:12:44.507631Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:44.559656Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$%^qwerty'] failed
2023-12-06T21:12:48.712018Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 39
2023-12-06T21:12:48.712197Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:48.761240Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$abcd,'] failed
2023-12-06T21:12:52.911812Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt: 40
2023-12-06T21:12:52.911920Z [HoneyPotSSHTransport,229,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-06T21:12:52.961388Z [HoneyPotSSHTransport,229,91.92.251.103] login attempt [b'admin'/b'!@#$qwerASDF'] failed
2023-12-06T21:12:57.103772Z [HoneyPotSSHTransport,229,91.92.251.103] Connection lost after 17 seconds
2023-12-04T18:43:33.364475Z [HoneyPotSSHTransport,53,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T18:43:33.504077Z [HoneyPotSSHTransport,53,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T18:43:34.318697Z [HoneyPotSSHTransport,53,91.92.251.103] first time for 91.92.251.103, need: 2
2023-12-04T18:43:34.318813Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt: 1
2023-12-04T18:43:34.362869Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b''] failed
2023-12-04T18:43:38.512305Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt: 2
2023-12-04T18:43:38.557170Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_'] succeeded
2023-12-04T18:43:38.558818Z [HoneyPotSSHTransport,53,91.92.251.103] Initialized emulated server as architecture: linux-x64-lsb
2023-12-04T18:43:38.911037Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: uname -a
2023-12-04T18:43:38.911531Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: uname -a
2023-12-04T18:43:39.049722Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:39.380046Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: cat /proc/cpuinfo
2023-12-04T18:43:39.380640Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: cat /proc/cpuinfo
2023-12-04T18:43:39.524209Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:39.825043Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: free -m
2023-12-04T18:43:39.825528Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: free -m
2023-12-04T18:43:39.964616Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:40.324602Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: dmidecode|grep Vendor|head -n 1
2023-12-04T18:43:40.325178Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: head -n 1
2023-12-04T18:43:40.325264Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: grep Vendor
2023-12-04T18:43:40.325510Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Can't find command dmidecode
2023-12-04T18:43:40.325600Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command not found: dmidecode | grep Vendor | head -n 1
2023-12-04T18:43:40.463747Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:40.855700Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: ps -x
2023-12-04T18:43:40.856223Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: ps -x
2023-12-04T18:43:40.995423Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:41.303707Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: dmesg | grep irtual
2023-12-04T18:43:41.304221Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: grep irtual
2023-12-04T18:43:41.305738Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: dmesg 
2023-12-04T18:43:41.305856Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Reading txtcmd from "share/cowrie/txtcmds/bin/dmesg"
2023-12-04T18:43:41.445223Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:41.768871Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds
2023-12-04T18:43:41.773814Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds
2023-12-04T18:43:41.777904Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds
2023-12-04T18:43:41.782359Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds
2023-12-04T18:43:41.787438Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 0 seconds
2023-12-04T18:43:41.791615Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds
2023-12-04T18:43:41.792227Z [HoneyPotSSHTransport,53,91.92.251.103] avatar 0aduserog34oxf4Bsf4Bsr_wasadmin logging out
2023-12-04T18:43:41.792404Z [HoneyPotSSHTransport,53,91.92.251.103] Connection lost after 8 seconds
2023-12-04T18:46:36.126685Z [HoneyPotSSHTransport,67,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T18:46:36.265826Z [HoneyPotSSHTransport,67,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T18:46:37.089845Z [HoneyPotSSHTransport,67,91.92.251.103] already tried this combination
2023-12-04T18:46:37.135585Z [HoneyPotSSHTransport,67,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b''] failed
2023-12-04T18:46:41.288966Z [HoneyPotSSHTransport,67,91.92.251.103] Found cached: b'0aduserog34oxf4Bsf4Bsr_wasadmin':b'og34oxf4Bsf4Bsr_'
2023-12-04T18:46:41.333846Z [HoneyPotSSHTransport,67,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_'] succeeded
2023-12-04T18:46:41.335794Z [HoneyPotSSHTransport,67,91.92.251.103] Initialized emulated server as architecture: linux-x64-lsb
2023-12-04T18:46:41.662080Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: uname -a
2023-12-04T18:46:41.662682Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: uname -a
2023-12-04T18:46:41.801674Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:42.143035Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: cat /proc/cpuinfo
2023-12-04T18:46:42.143539Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: cat /proc/cpuinfo
2023-12-04T18:46:42.292881Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:42.591615Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: free -m
2023-12-04T18:46:42.592108Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: free -m
2023-12-04T18:46:42.732547Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:43.096571Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: dmidecode|grep Vendor|head -n 1
2023-12-04T18:46:43.097101Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: head -n 1
2023-12-04T18:46:43.097201Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: grep Vendor
2023-12-04T18:46:43.097430Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Can't find command dmidecode
2023-12-04T18:46:43.097521Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command not found: dmidecode | grep Vendor | head -n 1
2023-12-04T18:46:43.236151Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:43.536844Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: ps -x
2023-12-04T18:46:43.537316Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: ps -x
2023-12-04T18:46:43.680678Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:44.066700Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: dmesg | grep irtual
2023-12-04T18:46:44.067215Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: grep irtual
2023-12-04T18:46:44.067477Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: dmesg 
2023-12-04T18:46:44.067585Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Reading txtcmd from "share/cowrie/txtcmds/bin/dmesg"
2023-12-04T18:46:44.207488Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:44.530526Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds
2023-12-04T18:46:44.535205Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds
2023-12-04T18:46:44.539317Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds
2023-12-04T18:46:44.543454Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds
2023-12-04T18:46:44.548054Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 1 seconds
2023-12-04T18:46:44.552238Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds
2023-12-04T18:46:44.552828Z [HoneyPotSSHTransport,67,91.92.251.103] avatar 0aduserog34oxf4Bsf4Bsr_wasadmin logging out
2023-12-04T18:46:44.553006Z [HoneyPotSSHTransport,67,91.92.251.103] Connection lost after 8 seconds
2023-12-04T22:11:08.077021Z [HoneyPotSSHTransport,146,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T22:11:08.216602Z [HoneyPotSSHTransport,146,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T22:11:09.027918Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 3
2023-12-04T22:11:09.028035Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:09.073461Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b''] failed
2023-12-04T22:11:13.255210Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 4
2023-12-04T22:11:13.255389Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:13.301692Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b'wasadmin2020'] failed
2023-12-04T22:11:17.452865Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 5
2023-12-04T22:11:17.452996Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:17.498204Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b'wasadmin202020'] failed
2023-12-04T22:11:21.642929Z [HoneyPotSSHTransport,146,91.92.251.103] Connection lost after 13 seconds
2023-12-04T22:14:08.651536Z [HoneyPotSSHTransport,153,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T22:14:08.791955Z [HoneyPotSSHTransport,153,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T22:14:09.620511Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 6
2023-12-04T22:14:09.620675Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:09.665816Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b''] failed
2023-12-04T22:14:13.822496Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 7
2023-12-04T22:14:13.822652Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:13.867625Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b'wasadmin2020'] failed
2023-12-04T22:14:18.020191Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 8
2023-12-04T22:14:18.020333Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:18.065554Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b'wasadmin202020'] failed
2023-12-04T22:14:22.207893Z [HoneyPotSSHTransport,153,91.92.251.103] Connection lost after 13 seconds
2023-12-04T18:43:33.364475Z [HoneyPotSSHTransport,53,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T18:43:33.504077Z [HoneyPotSSHTransport,53,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T18:43:34.318697Z [HoneyPotSSHTransport,53,91.92.251.103] first time for 91.92.251.103, need: 2
2023-12-04T18:43:34.318813Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt: 1
2023-12-04T18:43:34.362869Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b''] failed
2023-12-04T18:43:38.512305Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt: 2
2023-12-04T18:43:38.557170Z [HoneyPotSSHTransport,53,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_'] succeeded
2023-12-04T18:43:38.558818Z [HoneyPotSSHTransport,53,91.92.251.103] Initialized emulated server as architecture: linux-x64-lsb
2023-12-04T18:43:38.911037Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: uname -a
2023-12-04T18:43:38.911531Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: uname -a
2023-12-04T18:43:39.049722Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:39.380046Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: cat /proc/cpuinfo
2023-12-04T18:43:39.380640Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: cat /proc/cpuinfo
2023-12-04T18:43:39.524209Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:39.825043Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: free -m
2023-12-04T18:43:39.825528Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: free -m
2023-12-04T18:43:39.964616Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:40.324602Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: dmidecode|grep Vendor|head -n 1
2023-12-04T18:43:40.325178Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: head -n 1
2023-12-04T18:43:40.325264Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: grep Vendor
2023-12-04T18:43:40.325510Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Can't find command dmidecode
2023-12-04T18:43:40.325600Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command not found: dmidecode | grep Vendor | head -n 1
2023-12-04T18:43:40.463747Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:40.855700Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: ps -x
2023-12-04T18:43:40.856223Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: ps -x
2023-12-04T18:43:40.995423Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:41.303707Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] CMD: dmesg | grep irtual
2023-12-04T18:43:41.304221Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: grep irtual
2023-12-04T18:43:41.305738Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Command found: dmesg 
2023-12-04T18:43:41.305856Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Reading txtcmd from "share/cowrie/txtcmds/bin/dmesg"
2023-12-04T18:43:41.445223Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,53,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:43:41.768871Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds
2023-12-04T18:43:41.773814Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds
2023-12-04T18:43:41.777904Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds
2023-12-04T18:43:41.782359Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds
2023-12-04T18:43:41.787438Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 0 seconds
2023-12-04T18:43:41.791615Z [HoneyPotSSHTransport,53,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds
2023-12-04T18:43:41.792227Z [HoneyPotSSHTransport,53,91.92.251.103] avatar 0aduserog34oxf4Bsf4Bsr_wasadmin logging out
2023-12-04T18:43:41.792404Z [HoneyPotSSHTransport,53,91.92.251.103] Connection lost after 8 seconds
2023-12-04T18:46:36.126685Z [HoneyPotSSHTransport,67,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T18:46:36.265826Z [HoneyPotSSHTransport,67,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T18:46:37.089845Z [HoneyPotSSHTransport,67,91.92.251.103] already tried this combination
2023-12-04T18:46:37.135585Z [HoneyPotSSHTransport,67,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b''] failed
2023-12-04T18:46:41.288966Z [HoneyPotSSHTransport,67,91.92.251.103] Found cached: b'0aduserog34oxf4Bsf4Bsr_wasadmin':b'og34oxf4Bsf4Bsr_'
2023-12-04T18:46:41.333846Z [HoneyPotSSHTransport,67,91.92.251.103] login attempt [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_'] succeeded
2023-12-04T18:46:41.335794Z [HoneyPotSSHTransport,67,91.92.251.103] Initialized emulated server as architecture: linux-x64-lsb
2023-12-04T18:46:41.662080Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: uname -a
2023-12-04T18:46:41.662682Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: uname -a
2023-12-04T18:46:41.801674Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:42.143035Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: cat /proc/cpuinfo
2023-12-04T18:46:42.143539Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: cat /proc/cpuinfo
2023-12-04T18:46:42.292881Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:42.591615Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: free -m
2023-12-04T18:46:42.592108Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: free -m
2023-12-04T18:46:42.732547Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:43.096571Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: dmidecode|grep Vendor|head -n 1
2023-12-04T18:46:43.097101Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: head -n 1
2023-12-04T18:46:43.097201Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: grep Vendor
2023-12-04T18:46:43.097430Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Can't find command dmidecode
2023-12-04T18:46:43.097521Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command not found: dmidecode | grep Vendor | head -n 1
2023-12-04T18:46:43.236151Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:43.536844Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: ps -x
2023-12-04T18:46:43.537316Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: ps -x
2023-12-04T18:46:43.680678Z [SSHChannel session (4) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:44.066700Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] CMD: dmesg | grep irtual
2023-12-04T18:46:44.067215Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: grep irtual
2023-12-04T18:46:44.067477Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Command found: dmesg 
2023-12-04T18:46:44.067585Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Reading txtcmd from "share/cowrie/txtcmds/bin/dmesg"
2023-12-04T18:46:44.207488Z [SSHChannel session (5) on SSHService b'ssh-connection' on HoneyPotSSHTransport,67,91.92.251.103] Terminal Size: 80 24
2023-12-04T18:46:44.530526Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds
2023-12-04T18:46:44.535205Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds
2023-12-04T18:46:44.539317Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds
2023-12-04T18:46:44.543454Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds
2023-12-04T18:46:44.548054Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 1 seconds
2023-12-04T18:46:44.552238Z [HoneyPotSSHTransport,67,91.92.251.103] Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds
2023-12-04T18:46:44.552828Z [HoneyPotSSHTransport,67,91.92.251.103] avatar 0aduserog34oxf4Bsf4Bsr_wasadmin logging out
2023-12-04T18:46:44.553006Z [HoneyPotSSHTransport,67,91.92.251.103] Connection lost after 8 seconds
2023-12-04T22:11:08.077021Z [HoneyPotSSHTransport,146,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T22:11:08.216602Z [HoneyPotSSHTransport,146,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T22:11:09.027918Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 3
2023-12-04T22:11:09.028035Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:09.073461Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b''] failed
2023-12-04T22:11:13.255210Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 4
2023-12-04T22:11:13.255389Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:13.301692Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b'wasadmin2020'] failed
2023-12-04T22:11:17.452865Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 5
2023-12-04T22:11:17.452996Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:11:17.498204Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'Admin'/b'wasadmin202020'] failed
2023-12-04T22:11:21.642929Z [HoneyPotSSHTransport,146,91.92.251.103] Connection lost after 13 seconds
2023-12-04T22:14:08.651536Z [HoneyPotSSHTransport,153,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-04T22:14:08.791955Z [HoneyPotSSHTransport,153,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-04T22:14:09.620511Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 6
2023-12-04T22:14:09.620675Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:09.665816Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b''] failed
2023-12-04T22:14:13.822496Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 7
2023-12-04T22:14:13.822652Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:13.867625Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b'wasadmin2020'] failed
2023-12-04T22:14:18.020191Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt: 8
2023-12-04T22:14:18.020333Z [HoneyPotSSHTransport,153,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-04T22:14:18.065554Z [HoneyPotSSHTransport,153,91.92.251.103] login attempt [b'Admin'/b'wasadmin202020'] failed
2023-12-04T22:14:22.207893Z [HoneyPotSSHTransport,153,91.92.251.103] Connection lost after 13 seconds
2023-12-05T01:39:55.713602Z [HoneyPotSSHTransport,17,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T01:39:55.854735Z [HoneyPotSSHTransport,17,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T01:39:56.671292Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 9
2023-12-05T01:39:56.671402Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:39:56.715382Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b''] failed
2023-12-05T01:40:00.865506Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 10
2023-12-05T01:40:00.865623Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:40:00.910177Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b'1234'] failed
2023-12-05T01:40:05.065627Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 11
2023-12-05T01:40:05.065742Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:40:05.109963Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b'pass'] failed
2023-12-05T01:40:09.251007Z [HoneyPotSSHTransport,17,91.92.251.103] Connection lost after 13 seconds
2023-12-05T01:42:54.976085Z [HoneyPotSSHTransport,18,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T01:42:55.120921Z [HoneyPotSSHTransport,18,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T01:42:55.941166Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 12
2023-12-05T01:42:55.941294Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:42:55.986597Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b''] failed
2023-12-05T01:43:00.139676Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 13
2023-12-05T01:43:00.139859Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:43:00.184558Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b'1234'] failed
2023-12-05T01:43:04.334895Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 14
2023-12-05T01:43:04.335045Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:43:04.379651Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b'pass'] failed
2023-12-05T01:43:08.527766Z [HoneyPotSSHTransport,18,91.92.251.103] Connection lost after 13 seconds
2023-12-05T08:47:54.964319Z [HoneyPotSSHTransport,146,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T08:47:55.113804Z [HoneyPotSSHTransport,146,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T08:47:55.910008Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 15
2023-12-05T08:47:55.910124Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:47:55.956633Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b''] failed
2023-12-05T08:48:00.142045Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 16
2023-12-05T08:48:00.142244Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:48:00.189240Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b'1234'] failed
2023-12-05T08:48:04.341247Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 17
2023-12-05T08:48:04.341378Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:48:04.387764Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b'pass'] failed
2023-12-05T08:48:08.527915Z [HoneyPotSSHTransport,146,91.92.251.103] Connection lost after 13 seconds
2023-12-05T08:50:41.740638Z [HoneyPotSSHTransport,152,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T08:50:41.878102Z [HoneyPotSSHTransport,152,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T08:50:42.684427Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 18
2023-12-05T08:50:42.684557Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:42.730929Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b''] failed
2023-12-05T08:50:46.885316Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 19
2023-12-05T08:50:46.885434Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:46.932445Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b'1234'] failed
2023-12-05T08:50:51.082176Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 20
2023-12-05T08:50:51.082431Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:51.129647Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b'pass'] failed
2023-12-05T08:50:55.269193Z [HoneyPotSSHTransport,152,91.92.251.103] Connection lost after 13 seconds
2023-12-05T19:22:35.851410Z [HoneyPotSSHTransport,12,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T19:22:35.988285Z [HoneyPotSSHTransport,12,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T19:22:36.797115Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 21
2023-12-05T19:22:36.797264Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:36.843573Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b''] failed
2023-12-05T19:22:40.991569Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 22
2023-12-05T19:22:40.991702Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:41.038150Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b'1234'] failed
2023-12-05T19:22:45.186778Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 23
2023-12-05T19:22:45.186913Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:45.233711Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b'pass'] failed
2023-12-05T19:22:49.372661Z [HoneyPotSSHTransport,12,91.92.251.103] Connection lost after 13 seconds
2023-12-05T19:25:24.905939Z [HoneyPotSSHTransport,18,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T19:25:25.059467Z [HoneyPotSSHTransport,18,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T19:25:25.942212Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 24
2023-12-05T19:25:25.942334Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:25.989678Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b''] failed
2023-12-05T19:25:30.148357Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 25
2023-12-05T19:25:30.148500Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:30.195473Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b'1234'] failed
2023-12-05T19:25:34.357142Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 26
2023-12-05T19:25:34.357262Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:34.402986Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b'pass'] failed
2023-12-05T19:25:38.559458Z [HoneyPotSSHTransport,18,91.92.251.103] Connection lost after 13 seconds
2023-12-05T22:37:14.808512Z [HoneyPotSSHTransport,41,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T22:37:14.959933Z [HoneyPotSSHTransport,41,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T22:37:15.836718Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 27
2023-12-05T22:37:15.836847Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:15.883403Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b''] failed
2023-12-05T22:37:20.051160Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 28
2023-12-05T22:37:20.051285Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:20.097620Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b'pass'] failed
2023-12-05T22:37:24.264596Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 29
2023-12-05T22:37:24.264709Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:24.310930Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b'test'] failed
2023-12-05T22:37:28.465703Z [HoneyPotSSHTransport,41,91.92.251.103] Connection lost after 13 seconds
2023-12-05T22:40:02.976720Z [HoneyPotSSHTransport,59,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T22:40:03.114396Z [HoneyPotSSHTransport,59,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T22:40:03.922282Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 30
2023-12-05T22:40:03.922429Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:03.969155Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b''] failed
2023-12-05T22:40:08.117604Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 31
2023-12-05T22:40:08.117728Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:08.164482Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b'pass'] failed
2023-12-05T22:40:12.317057Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 32
2023-12-05T22:40:12.317201Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:12.364052Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b'test'] failed
2023-12-05T22:40:16.504224Z [HoneyPotSSHTransport,59,91.92.251.103] Connection lost after 13 seconds
2023-12-05T01:39:55.713602Z [HoneyPotSSHTransport,17,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T01:39:55.854735Z [HoneyPotSSHTransport,17,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T01:39:56.671292Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 9
2023-12-05T01:39:56.671402Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:39:56.715382Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b''] failed
2023-12-05T01:40:00.865506Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 10
2023-12-05T01:40:00.865623Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:40:00.910177Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b'1234'] failed
2023-12-05T01:40:05.065627Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt: 11
2023-12-05T01:40:05.065742Z [HoneyPotSSHTransport,17,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:40:05.109963Z [HoneyPotSSHTransport,17,91.92.251.103] login attempt [b'admin'/b'pass'] failed
2023-12-05T01:40:09.251007Z [HoneyPotSSHTransport,17,91.92.251.103] Connection lost after 13 seconds
2023-12-05T01:42:54.976085Z [HoneyPotSSHTransport,18,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T01:42:55.120921Z [HoneyPotSSHTransport,18,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T01:42:55.941166Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 12
2023-12-05T01:42:55.941294Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:42:55.986597Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b''] failed
2023-12-05T01:43:00.139676Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 13
2023-12-05T01:43:00.139859Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:43:00.184558Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b'1234'] failed
2023-12-05T01:43:04.334895Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 14
2023-12-05T01:43:04.335045Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T01:43:04.379651Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'admin'/b'pass'] failed
2023-12-05T01:43:08.527766Z [HoneyPotSSHTransport,18,91.92.251.103] Connection lost after 13 seconds
2023-12-05T08:47:54.964319Z [HoneyPotSSHTransport,146,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T08:47:55.113804Z [HoneyPotSSHTransport,146,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T08:47:55.910008Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 15
2023-12-05T08:47:55.910124Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:47:55.956633Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b''] failed
2023-12-05T08:48:00.142045Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 16
2023-12-05T08:48:00.142244Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:48:00.189240Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b'1234'] failed
2023-12-05T08:48:04.341247Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt: 17
2023-12-05T08:48:04.341378Z [HoneyPotSSHTransport,146,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:48:04.387764Z [HoneyPotSSHTransport,146,91.92.251.103] login attempt [b'guest'/b'pass'] failed
2023-12-05T08:48:08.527915Z [HoneyPotSSHTransport,146,91.92.251.103] Connection lost after 13 seconds
2023-12-05T08:50:41.740638Z [HoneyPotSSHTransport,152,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T08:50:41.878102Z [HoneyPotSSHTransport,152,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T08:50:42.684427Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 18
2023-12-05T08:50:42.684557Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:42.730929Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b''] failed
2023-12-05T08:50:46.885316Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 19
2023-12-05T08:50:46.885434Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:46.932445Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b'1234'] failed
2023-12-05T08:50:51.082176Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt: 20
2023-12-05T08:50:51.082431Z [HoneyPotSSHTransport,152,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T08:50:51.129647Z [HoneyPotSSHTransport,152,91.92.251.103] login attempt [b'guest'/b'pass'] failed
2023-12-05T08:50:55.269193Z [HoneyPotSSHTransport,152,91.92.251.103] Connection lost after 13 seconds
2023-12-05T19:22:35.851410Z [HoneyPotSSHTransport,12,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T19:22:35.988285Z [HoneyPotSSHTransport,12,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T19:22:36.797115Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 21
2023-12-05T19:22:36.797264Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:36.843573Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b''] failed
2023-12-05T19:22:40.991569Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 22
2023-12-05T19:22:40.991702Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:41.038150Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b'1234'] failed
2023-12-05T19:22:45.186778Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt: 23
2023-12-05T19:22:45.186913Z [HoneyPotSSHTransport,12,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:22:45.233711Z [HoneyPotSSHTransport,12,91.92.251.103] login attempt [b'support'/b'pass'] failed
2023-12-05T19:22:49.372661Z [HoneyPotSSHTransport,12,91.92.251.103] Connection lost after 13 seconds
2023-12-05T19:25:24.905939Z [HoneyPotSSHTransport,18,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T19:25:25.059467Z [HoneyPotSSHTransport,18,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T19:25:25.942212Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 24
2023-12-05T19:25:25.942334Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:25.989678Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b''] failed
2023-12-05T19:25:30.148357Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 25
2023-12-05T19:25:30.148500Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:30.195473Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b'1234'] failed
2023-12-05T19:25:34.357142Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt: 26
2023-12-05T19:25:34.357262Z [HoneyPotSSHTransport,18,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T19:25:34.402986Z [HoneyPotSSHTransport,18,91.92.251.103] login attempt [b'support'/b'pass'] failed
2023-12-05T19:25:38.559458Z [HoneyPotSSHTransport,18,91.92.251.103] Connection lost after 13 seconds
2023-12-05T22:37:14.808512Z [HoneyPotSSHTransport,41,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T22:37:14.959933Z [HoneyPotSSHTransport,41,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T22:37:15.836718Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 27
2023-12-05T22:37:15.836847Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:15.883403Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b''] failed
2023-12-05T22:37:20.051160Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 28
2023-12-05T22:37:20.051285Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:20.097620Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b'pass'] failed
2023-12-05T22:37:24.264596Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt: 29
2023-12-05T22:37:24.264709Z [HoneyPotSSHTransport,41,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:37:24.310930Z [HoneyPotSSHTransport,41,91.92.251.103] login attempt [b'test'/b'test'] failed
2023-12-05T22:37:28.465703Z [HoneyPotSSHTransport,41,91.92.251.103] Connection lost after 13 seconds
2023-12-05T22:40:02.976720Z [HoneyPotSSHTransport,59,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-05T22:40:03.114396Z [HoneyPotSSHTransport,59,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-05T22:40:03.922282Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 30
2023-12-05T22:40:03.922429Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:03.969155Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b''] failed
2023-12-05T22:40:08.117604Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 31
2023-12-05T22:40:08.117728Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:08.164482Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b'pass'] failed
2023-12-05T22:40:12.317057Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt: 32
2023-12-05T22:40:12.317201Z [HoneyPotSSHTransport,59,91.92.251.103] login return, expect: [b'0aduserog34oxf4Bsf4Bsr_wasadmin'/b'og34oxf4Bsf4Bsr_']
2023-12-05T22:40:12.364052Z [HoneyPotSSHTransport,59,91.92.251.103] login attempt [b'test'/b'test'] failed
2023-12-05T22:40:16.504224Z [HoneyPotSSHTransport,59,91.92.251.103] Connection lost after 13 seconds
2023-12-02T19:28:16.498303Z [HoneyPotSSHTransport,44,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-02T19:28:16.639230Z [HoneyPotSSHTransport,44,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-02T19:28:17.432699Z [HoneyPotSSHTransport,44,91.92.251.103] Connection lost after 0 seconds
2023-12-02T19:28:16.498303Z [HoneyPotSSHTransport,44,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-02T19:28:16.639230Z [HoneyPotSSHTransport,44,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-02T19:28:17.432699Z [HoneyPotSSHTransport,44,91.92.251.103] Connection lost after 0 seconds
2023-12-03T11:59:43.481738Z [HoneyPotSSHTransport,95,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-03T11:59:43.623626Z [HoneyPotSSHTransport,95,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-03T11:59:44.417945Z [HoneyPotSSHTransport,95,91.92.251.103] Connection lost after 0 seconds
2023-12-03T16:54:40.669338Z [HoneyPotSSHTransport,88,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-03T16:54:40.807482Z [HoneyPotSSHTransport,88,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-03T16:54:41.598593Z [HoneyPotSSHTransport,88,91.92.251.103] Connection lost after 0 seconds
2023-12-03T11:59:43.481738Z [HoneyPotSSHTransport,95,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-03T11:59:43.623626Z [HoneyPotSSHTransport,95,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-03T11:59:44.417945Z [HoneyPotSSHTransport,95,91.92.251.103] Connection lost after 0 seconds
2023-12-03T16:54:40.669338Z [HoneyPotSSHTransport,88,91.92.251.103] Remote SSH version: SSH-2.0-libssh2_1.8.2
2023-12-03T16:54:40.807482Z [HoneyPotSSHTransport,88,91.92.251.103] SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c
2023-12-03T16:54:41.598593Z [HoneyPotSSHTransport,88,91.92.251.103] Connection lost after 0 seconds

```

</details>

---

COMMENTARY ON LOGS

## Cowrie .json Logs
Total Cowrie logs: `352`

#### First Session With Commands 13da7b98b8d4 Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `13da7b98b8d4` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .json Logs for 13da7b98b8d4</h3>
</summary>


```json
{"eventid":"cowrie.session.connect","src_ip":"91.92.251.103","src_port":48304,"dst_ip":"172.31.5.68","dst_port":2222,"session":"13da7b98b8d4","protocol":"ssh","message":"New connection: 91.92.251.103:48304 (172.31.5.68:2222) [session: 13da7b98b8d4]","sensor":"","timestamp":"2023-12-04T18:43:33.363701Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.8.2","message":"Remote SSH version: SSH-2.0-libssh2_1.8.2","sensor":"","timestamp":"2023-12-04T18:43:33.364475Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.kex","hassh":"a7a87fbe86774c2e40cc4a7ea2ab1b3c","hasshAlgorithms":"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none","kexAlgs":["diffie-hellman-group-exchange-sha256","diffie-hellman-group-exchange-sha1","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1"],"keyAlgs":["ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c","sensor":"","timestamp":"2023-12-04T18:43:33.504077Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.login.failed","username":"0aduserog34oxf4Bsf4Bsr_wasadmin","password":"","message":"login attempt [0aduserog34oxf4Bsf4Bsr_wasadmin/] failed","sensor":"","timestamp":"2023-12-04T18:43:34.362869Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.login.success","username":"0aduserog34oxf4Bsf4Bsr_wasadmin","password":"og34oxf4Bsf4Bsr_","message":"login attempt [0aduserog34oxf4Bsf4Bsr_wasadmin/og34oxf4Bsf4Bsr_] succeeded","sensor":"","timestamp":"2023-12-04T18:43:38.557170Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:38.910413Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"uname -a","message":"CMD: uname -a","sensor":"","timestamp":"2023-12-04T18:43:38.911037Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.049722Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:39.379478Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"cat /proc/cpuinfo","message":"CMD: cat /proc/cpuinfo","sensor":"","timestamp":"2023-12-04T18:43:39.380046Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.524209Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:39.824481Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"free -m","message":"CMD: free -m","sensor":"","timestamp":"2023-12-04T18:43:39.825043Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.964616Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:40.324044Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"dmidecode|grep Vendor|head -n 1","message":"CMD: dmidecode|grep Vendor|head -n 1","sensor":"","timestamp":"2023-12-04T18:43:40.324602Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.failed","input":"dmidecode | grep Vendor | head -n 1","message":"Command not found: dmidecode | grep Vendor | head -n 1","sensor":"","timestamp":"2023-12-04T18:43:40.325600Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:40.463747Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:40.855082Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"ps -x","message":"CMD: ps -x","sensor":"","timestamp":"2023-12-04T18:43:40.855700Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:40.995423Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:41.303135Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"dmesg | grep irtual","message":"CMD: dmesg | grep irtual","sensor":"","timestamp":"2023-12-04T18:43:41.303707Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:41.445223Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15","size":72,"shasum":"28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15","duplicate":true,"duration":2.8586766719818115,"message":"Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.768871Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a","size":1412,"shasum":"52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a","duplicate":true,"duration":2.3945491313934326,"message":"Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.773814Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876","size":204,"shasum":"db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876","duplicate":false,"duration":1.9536006450653076,"message":"Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.777904Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9","size":36,"shasum":"c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9","duplicate":false,"duration":1.458491563796997,"message":"Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.782359Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2","size":169,"shasum":"f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2","duplicate":false,"duration":0.932549238204956,"message":"Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 0 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.787438Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b","size":183,"shasum":"78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b","duplicate":false,"duration":0.4886739253997803,"message":"Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.791615Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.closed","duration":8.428016185760498,"message":"Connection lost after 8 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.792404Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.connect","src_ip":"91.92.251.103","src_port":48304,"dst_ip":"172.31.5.68","dst_port":2222,"session":"13da7b98b8d4","protocol":"ssh","message":"New connection: 91.92.251.103:48304 (172.31.5.68:2222) [session: 13da7b98b8d4]","sensor":"","timestamp":"2023-12-04T18:43:33.363701Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.8.2","message":"Remote SSH version: SSH-2.0-libssh2_1.8.2","sensor":"","timestamp":"2023-12-04T18:43:33.364475Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.kex","hassh":"a7a87fbe86774c2e40cc4a7ea2ab1b3c","hasshAlgorithms":"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none","kexAlgs":["diffie-hellman-group-exchange-sha256","diffie-hellman-group-exchange-sha1","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1"],"keyAlgs":["ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: a7a87fbe86774c2e40cc4a7ea2ab1b3c","sensor":"","timestamp":"2023-12-04T18:43:33.504077Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.login.failed","username":"0aduserog34oxf4Bsf4Bsr_wasadmin","password":"","message":"login attempt [0aduserog34oxf4Bsf4Bsr_wasadmin/] failed","sensor":"","timestamp":"2023-12-04T18:43:34.362869Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.login.success","username":"0aduserog34oxf4Bsf4Bsr_wasadmin","password":"og34oxf4Bsf4Bsr_","message":"login attempt [0aduserog34oxf4Bsf4Bsr_wasadmin/og34oxf4Bsf4Bsr_] succeeded","sensor":"","timestamp":"2023-12-04T18:43:38.557170Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:38.910413Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"uname -a","message":"CMD: uname -a","sensor":"","timestamp":"2023-12-04T18:43:38.911037Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.049722Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:39.379478Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"cat /proc/cpuinfo","message":"CMD: cat /proc/cpuinfo","sensor":"","timestamp":"2023-12-04T18:43:39.380046Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.524209Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:39.824481Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"free -m","message":"CMD: free -m","sensor":"","timestamp":"2023-12-04T18:43:39.825043Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:39.964616Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:40.324044Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"dmidecode|grep Vendor|head -n 1","message":"CMD: dmidecode|grep Vendor|head -n 1","sensor":"","timestamp":"2023-12-04T18:43:40.324602Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.failed","input":"dmidecode | grep Vendor | head -n 1","message":"Command not found: dmidecode | grep Vendor | head -n 1","sensor":"","timestamp":"2023-12-04T18:43:40.325600Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:40.463747Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:40.855082Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"ps -x","message":"CMD: ps -x","sensor":"","timestamp":"2023-12-04T18:43:40.855700Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:40.995423Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-04T18:43:41.303135Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.command.input","input":"dmesg | grep irtual","message":"CMD: dmesg | grep irtual","sensor":"","timestamp":"2023-12-04T18:43:41.303707Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.client.size","width":80,"height":24,"message":"Terminal Size: 80 24","sensor":"","timestamp":"2023-12-04T18:43:41.445223Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15","size":72,"shasum":"28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15","duplicate":true,"duration":2.8586766719818115,"message":"Closing TTY Log: var/lib/cowrie/tty/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 after 2 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.768871Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a","size":1412,"shasum":"52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a","duplicate":true,"duration":2.3945491313934326,"message":"Closing TTY Log: var/lib/cowrie/tty/52a532334011a67d1c41a57eea38ed25893bff4b6c264c748c3f2df576a47f4a after 2 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.773814Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876","size":204,"shasum":"db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876","duplicate":false,"duration":1.9536006450653076,"message":"Closing TTY Log: var/lib/cowrie/tty/db86909fa7661a6ea9461ec8ce31cecb3eeeff27a20b12c06e89811ffd68b876 after 1 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.777904Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9","size":36,"shasum":"c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9","duplicate":false,"duration":1.458491563796997,"message":"Closing TTY Log: var/lib/cowrie/tty/c0f1e5d98a83935d9cb41a1ccacde4cae62272ae59f3f8163e2d97adb3cf47e9 after 1 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.782359Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2","size":169,"shasum":"f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2","duplicate":false,"duration":0.932549238204956,"message":"Closing TTY Log: var/lib/cowrie/tty/f7875f8aa9281065cca1a7de5b7431e2877da19c163e9c1b35829287d54beda2 after 0 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.787438Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b","size":183,"shasum":"78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b","duplicate":false,"duration":0.4886739253997803,"message":"Closing TTY Log: var/lib/cowrie/tty/78392f0cbc7098dbc05c32d2b1846e0868928e2cd7d72c825ad5ac709bebe36b after 0 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.791615Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}
{"eventid":"cowrie.session.closed","duration":8.428016185760498,"message":"Connection lost after 8 seconds","sensor":"","timestamp":"2023-12-04T18:43:41.792404Z","src_ip":"91.92.251.103","session":"13da7b98b8d4"}

```

</details>

---

COMMENTARY ON LOGS

## DShield Logs
Total DShield logs: `52`

#### The `19` sessions in this attack were logged as connection in the following DShield firewall logs:
Here is a sample of the log lines:

```log
1701592740 BigDshield kernel:[68427.492998]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=41146 DF PROTO=TCP SPT=59142 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701604783 BigDshield kernel:[80470.436953]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=26604 DF PROTO=TCP SPT=44494 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701622480 BigDshield kernel:[11765.426921]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=51162 DF PROTO=TCP SPT=58640 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701715595 BigDshield kernel:[18482.461024]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=64106 DF PROTO=TCP SPT=41420 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701727867 BigDshield kernel:[30754.452273]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=22977 DF PROTO=TCP SPT=42226 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701728048 BigDshield kernel:[30935.026609]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=6532 DF PROTO=TCP SPT=48332 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701740395 BigDshield kernel:[43282.130296]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=5350 DF PROTO=TCP SPT=49896 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701740574 BigDshield kernel:[43461.391340]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=35331 DF PROTO=TCP SPT=38270 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701753209 BigDshield kernel:[56095.944170]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=9893 DF PROTO=TCP SPT=44628 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701753413 BigDshield kernel:[56300.366740]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=41265 DF PROTO=TCP SPT=41680 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701766074 BigDshield kernel:[68961.468064]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=60025 DF PROTO=TCP SPT=33622 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701766241 BigDshield kernel:[69128.244432]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=44932 DF PROTO=TCP SPT=41974 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701779064 BigDshield kernel:[81951.343847]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=8897 DF PROTO=TCP SPT=35364 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701779253 BigDshield kernel:[82140.471992]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=13851 DF PROTO=TCP SPT=59512 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701791786 BigDshield kernel:[ 8270.973369]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=43231 DF PROTO=TCP SPT=36426 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701791970 BigDshield kernel:[ 8454.882653]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=58317 DF PROTO=TCP SPT=41768 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701804324 BigDshield kernel:[20809.125745]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=13196 DF PROTO=TCP SPT=58552 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701815834 BigDshield kernel:[32319.072226]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=54393 DF PROTO=TCP SPT=54436 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701828500 BigDshield kernel:[44984.614840]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=52843 DF PROTO=TCP SPT=43250 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701828691 BigDshield kernel:[45175.667884]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=15894 DF PROTO=TCP SPT=60170 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701882819 BigDshield kernel:[12905.916275]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=22431 DF PROTO=TCP SPT=45606 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701883037 BigDshield kernel:[13124.411006]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=45912 DF PROTO=TCP SPT=39378 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701896957 BigDshield kernel:[27044.551819]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=19535 DF PROTO=TCP SPT=44536 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701897159 BigDshield kernel:[27245.788584]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=46605 DF PROTO=TCP SPT=33434 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701911011 BigDshield kernel:[41098.512428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=10200 DF PROTO=TCP SPT=60038 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701911211 BigDshield kernel:[41297.787530]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=65243 DF PROTO=TCP SPT=59472 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701592740 BigDshield kernel:[68427.492998]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=41146 DF PROTO=TCP SPT=59142 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701604783 BigDshield kernel:[80470.436953]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=26604 DF PROTO=TCP SPT=44494 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701622480 BigDshield kernel:[11765.426921]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=51162 DF PROTO=TCP SPT=58640 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701715595 BigDshield kernel:[18482.461024]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=64106 DF PROTO=TCP SPT=41420 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701727867 BigDshield kernel:[30754.452273]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=22977 DF PROTO=TCP SPT=42226 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701728048 BigDshield kernel:[30935.026609]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=6532 DF PROTO=TCP SPT=48332 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701740395 BigDshield kernel:[43282.130296]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=5350 DF PROTO=TCP SPT=49896 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701740574 BigDshield kernel:[43461.391340]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=35331 DF PROTO=TCP SPT=38270 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701753209 BigDshield kernel:[56095.944170]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=9893 DF PROTO=TCP SPT=44628 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701753413 BigDshield kernel:[56300.366740]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=41265 DF PROTO=TCP SPT=41680 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701766074 BigDshield kernel:[68961.468064]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=60025 DF PROTO=TCP SPT=33622 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701766241 BigDshield kernel:[69128.244432]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=44932 DF PROTO=TCP SPT=41974 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701779064 BigDshield kernel:[81951.343847]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=8897 DF PROTO=TCP SPT=35364 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701779253 BigDshield kernel:[82140.471992]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=13851 DF PROTO=TCP SPT=59512 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701791786 BigDshield kernel:[ 8270.973369]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=43231 DF PROTO=TCP SPT=36426 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701791970 BigDshield kernel:[ 8454.882653]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=58317 DF PROTO=TCP SPT=41768 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701804324 BigDshield kernel:[20809.125745]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=13196 DF PROTO=TCP SPT=58552 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701815834 BigDshield kernel:[32319.072226]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=54393 DF PROTO=TCP SPT=54436 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701828500 BigDshield kernel:[44984.614840]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=52843 DF PROTO=TCP SPT=43250 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701828691 BigDshield kernel:[45175.667884]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=15894 DF PROTO=TCP SPT=60170 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701882819 BigDshield kernel:[12905.916275]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=22431 DF PROTO=TCP SPT=45606 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701883037 BigDshield kernel:[13124.411006]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=45912 DF PROTO=TCP SPT=39378 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701896957 BigDshield kernel:[27044.551819]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=19535 DF PROTO=TCP SPT=44536 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701897159 BigDshield kernel:[27245.788584]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=46605 DF PROTO=TCP SPT=33434 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 
1701911011 BigDshield kernel:[41098.512428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=10200 DF PROTO=TCP SPT=60038 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701911211 BigDshield kernel:[41297.787530]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=91.92.251.103 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=65243 DF PROTO=TCP SPT=59472 DPT=2222 WINDOW=64240 RES=0x00 SYN URGP=0 

```
COMMENTARY ON LOGS
</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The attack involved the following IP addresses and ports:

- Source IP: `91.92.251.103`
- Source Ports: `36574`, `44494`, `58640`, `48304`, `41420`, `42226`, `48332`, `49896`, `38270`, `33622`, `41974`, `36728`, `58552`, `54436`, `35896`, `44536`, `33434`, `60038`, `59472`.

- Destination IP: `172.31.5.68`
- Destination Port: `2222` (used across multiple connections). 

The consistent use of destination port `2222` suggests that the honeypot may have been configured to listen on this port, possibly as a substitute for the default SSH port (`22`). The source ports are variable, which is typical for outgoing connections.

<details>
<summary>
<h3>Top 1 Source Ips</h3>
</summary>

Total Source IPs: `19`
Unique: `1`

| Source IP | Times Seen |
| --- | --- |
| `91.92.251.103` | `19` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `19`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `19` |

</details>

---


<details>
<summary>
<h3>Top 10 Source Ports</h3>
</summary>

Total Source Ports: `19`
Unique: `19`

| Source Port | Times Seen |
| --- | --- |
| `36574` | `1` |
| `44494` | `1` |
| `58640` | `1` |
| `48304` | `1` |
| `41420` | `1` |
| `42226` | `1` |
| `48332` | `1` |
| `49896` | `1` |
| `38270` | `1` |
| `33622` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `19`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2222` | `19` |

</details>

---


</details>

---


<details>
<summary>
<h1>SSH Analysis</h1>
</summary>

The SSH data associated with the attack reveals that:

- The SSH HASSH (a unique fingerprint for SSH clients and servers) identifier is `a7a87fbe86774c2e40cc4a7ea2ab1b3c`. This HASSH was consistently used across connections, suggesting that the same SSH client software was used for each attempt.

- The SSH version reported is `SSH-2.0-libssh2_1.8.2`. This indicates that the attacker was using the `libssh2` library version `1.8.2`, a client-side C library implementing the SSH2 protocol. 

This consistent use of a single SSH client version and HASSH across multiple connections shows a systematic approach to accessing the system over SSH. The HASSH can potentially be used to identify the attack pattern or the client software used in the attack within network traffic, but it also implies that the attacker did not attempt to vary their SSH fingerprint to evade detection.

<details>
<summary>
<h3>Top 6 Usernames</h3>
</summary>

Total Usernames: `50`
Unique: `6`

| Username | Times Seen |
| --- | --- |
| `admin` | `22` |
| `Admin` | `6` |
| `guest` | `6` |
| `support` | `6` |
| `test` | `6` |
| `0aduserog34oxf4Bsf4Bsr_wasadmin` | `4` |

</details>

---


![Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-usernames.png)
<details>
<summary>
<h3>Top 10 Passwords</h3>
</summary>

Total Passwords: `50`
Unique: `15`

| Password | Times Seen |
| --- | --- |
| `` | `12` |
| `pass` | `8` |
| `1234` | `6` |
| `og34oxf4Bsf4Bsr_` | `2` |
| `wasadmin2020` | `2` |
| `wasadmin202020` | `2` |
| `test` | `2` |
| `!@#$%^&*` | `2` |
| `!@#$%^qwerty` | `2` |
| `!@#$abcd,` | `2` |

</details>

---


![Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-passwords.png)
<details>
<summary>
<h3>Top 10 Username/Password Pairs</h3>
</summary>

Total Username/Password Pairs: `50`
Unique: `25`

| Username/Password Pair | Times Seen |
| --- | --- |
| `('0aduserog34oxf4Bsf4Bsr_wasadmin', '')` | `2` |
| `('0aduserog34oxf4Bsf4Bsr_wasadmin', 'og34oxf4Bsf4Bsr_')` | `2` |
| `('Admin', '')` | `2` |
| `('Admin', 'wasadmin2020')` | `2` |
| `('Admin', 'wasadmin202020')` | `2` |
| `('admin', '')` | `2` |
| `('admin', '1234')` | `2` |
| `('admin', 'pass')` | `2` |
| `('guest', '')` | `2` |
| `('guest', '1234')` | `2` |

</details>

---


![Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-login_pairs.png)
<details>
<summary>
<h3>Top 1 Successful Usernames</h3>
</summary>

Total Successful Usernames: `2`
Unique: `1`

| Successful Username | Times Seen |
| --- | --- |
| `0aduserog34oxf4Bsf4Bsr_wasadmin` | `2` |

</details>

---


![Successful Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-successful_usernames.png)
<details>
<summary>
<h3>Top 1 Successful Passwords</h3>
</summary>

Total Successful Passwords: `2`
Unique: `1`

| Successful Password | Times Seen |
| --- | --- |
| `og34oxf4Bsf4Bsr_` | `2` |

</details>

---


![Successful Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-successful_passwords.png)
<details>
<summary>
<h3>Top 1 Successful Username/Password Pairs</h3>
</summary>

Total Successful Username/Password Pairs: `2`
Unique: `1`

| Successful Username/Password Pair | Times Seen |
| --- | --- |
| `('0aduserog34oxf4Bsf4Bsr_wasadmin', 'og34oxf4Bsf4Bsr_')` | `2` |

</details>

---


![Successful Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-successful_login_pairs.png)
<details>
<summary>
<h3>Top 1 Ssh Versions</h3>
</summary>

Total SSH Versions: `19`
Unique: `1`

| SSH Version | Times Seen |
| --- | --- |
| `SSH-2.0-libssh2_1.8.2` | `19` |

</details>

---


![SSH Version](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-ssh_versions.png)
<details>
<summary>
<h3>Top 1 Ssh Hasshs</h3>
</summary>

Total SSH Hasshs: `19`
Unique: `1`

| SSH Hassh | Times Seen |
| --- | --- |
| `a7a87fbe86774c2e40cc4a7ea2ab1b3c` | `19` |

</details>

---


![SSH Hassh](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/7bb46aa291cc9ca205b3b181532609eb24c24f05f31923f8d165a322a864b48f/pie-ssh_hasshs.png)
</details>

---


# Commands Used
This attack used a total of `12` inputs to execute the following `12` commands:
The attacker executed the following commands:

1. `uname -a`: This command displays system information including the kernel version, the hostname, the hardware name, and other system details. It is often used to gather information about the target system.

2. `cat /proc/cpuinfo`: By executing this command, an attacker can view detailed information about the CPU, such as the model, vendor, and number of cores. This information can be used to tailor further attacks to the specific hardware.

3. `free -m`: This command reports the total amount of free and used physical memory and swap space on the system, as well as the buffers and caches used by the kernel. The information is displayed in megabytes. This can help the attacker understand the system's resources and identify potential targets for resource depletion attacks.

4. `dmidecode|grep Vendor|head -n 1`: The attacker pipes the output of the `dmidecode` command, which displays hardware information from the system's BIOS, to `grep` to search for the Vendor information and then uses `head -n 1` to display only the first occurrence. The goal is likely to identify the hardware vendor for the target system.

5. `ps -x`: This command lists all running processes without requiring a tty. It's a way for the attacker to see what services and applications are currently running on the system.

6. `dmesg | grep irtual`: This command checks the kernel ring buffer messages for entries containing the string "irtual" by piping the output of `dmesg` into `grep`. The attacker might be looking for virtualization platforms (such as "VirtualBox" or "VMware") that could indicate the system is a virtual machine.

The pattern of these commands suggests that the attacker is in the reconnaissance phase, gathering as much information about the system as possible in order to better understand the environment and prepare for further stages of the attack.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `12` inputs on the honeypot system:

**Input 1:**
```bash
uname -a
```

**Input 2:**
```bash
cat /proc/cpuinfo
```

**Input 3:**
```bash
free -m
```

**Input 4:**
```bash
dmidecode|grep Vendor|head -n 1
```

**Input 5:**
```bash
ps -x
```

**Input 6:**
```bash
dmesg | grep irtual
```

**Input 7:**
```bash
uname -a
```

**Input 8:**
```bash
cat /proc/cpuinfo
```

**Input 9:**
```bash
free -m
```

**Input 10:**
```bash
dmidecode|grep Vendor|head -n 1
```

**Input 11:**
```bash
ps -x
```

**Input 12:**
```bash
dmesg | grep irtual
```

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `12` commands were executed on the honeypot system:

```bash
uname -a
```
The attacker uses `uname -a` to **display all system information** including kernel version, hostname, machine hardware name, processor architecture, among other details.
```bash
cat /proc/cpuinfo
```
The command `cat /proc/cpuinfo` is used to **retrieve CPU information**, such as number of cores, CPU family, model, and features which is useful for tailoring further attacks.
```bash
free -m
```
By running `free -m`, the attacker **checks available and used memory amounts** in megabytes to assess how much resources they can exploit.
```bash
dmidecode|grep Vendor|head -n 1
```
The `dmidecode|grep Vendor|head -n 1` command **searches for the system's vendor information** by filtering through `dmidecode` output, likely to identify the system's manufacturer.
```bash
ps -x
```
Executing `ps -x` is a way for the attacker to **view currently running processes** without requiring elevation of privileges.
```bash
dmesg | grep irtual
```
With `dmesg | grep irtual`, the attacker examines **kernel messages for references to virtualization**. The intent might be to detect if they're operating inside a virtual machine.
```bash
uname -a
cat /proc/cpuinfo
free -m
dmidecode|grep Vendor|head -n 1
ps -x
```
The commands from index 6 to 11 are **identical to the ones from 0 to 5**. It seems the attacker is **repeating the same reconnaissance commands** to gather information about the system for potential exploitation or assessing changes in the system environment after initial exploration.
</details>

---



# Which vulnerability does the attack attempt to exploit?
Based on the information provided so far, there is no direct indication of a specific vulnerability being exploited. The commands executed suggest information gathering rather than the exploitation of a known vulnerability. 

To determine if a vulnerability is being exploited, additional information such as logs showing unexpected or unauthorized behavior, specific exploit code or commands, or details about any files that were uploaded and executed would be required.

If there are logs indicating strange activity, or if an exploit was downloaded or used, please provide those details, and I can offer a more precise analysis. Otherwise, without more information, I cannot identify a specific vulnerability being exploited or provide an exploit name and CVE number.


# MITRE ATT&CK
Based on the reconnaissance commands used by the attacker, the attack can be classified under the MITRE ATT&CK framework as follows:

1. **Reconnaissance [TA0043]**: The attacker is gathering information to plan future operations.
   - **System Service Discovery [T1007]**: The use of commands such as `ps -x` to list running processes.
   - **System Information Discovery [T1082]**: Commands like `uname -a`, `cat /proc/cpuinfo`, and `free -m` were employed, indicating the attacker was trying to learn about the system's configuration and operation.

2. **Resource Development [TA0042]**: Although not directly observed in the provided commands, if the attacker was downloading tools or malware, this would be the stage where those resources were being developed.

3. **Initial Access [TA0001]**: This stage may be represented here, depending on how the attacker gained access to the honeypot. If the attacker used an exposed service like SSH on a non-standard port (evidenced by the persistent use of port `2222`), it would fall under:
   - **Exploit Public-Facing Application [T1190]**: If the attacker exploited a vulnerability to gain initial access.

4. **Discovery [TA0007]**: The main observable activity falls under this tactic, where the attacker is trying to discover information about the system.
   - **System Network Configuration Discovery [T1016]**: The attacker may have tried to glean network-related information with certain commands.
   - **System Owner/User Discovery [T1033]**: The `ps -x` command could potentially reveal the users running various processes.

Without evidence of the exploitation of a vulnerability, installation of malware, command and control activity, or exfiltration of data, the scope of this classification is limited to the reconnaissance and discovery stages of an attack. Further activity logs or evidence of subsequent attack stages would be required to expand this classification within the MITRE ATT&CK framework.

# What Is The Goal Of The Attack?
While I am unable to claim the attacker's specific intentions without insights into their motivations, the observed actions and commands executed suggest that the goal of the attack could be categorized into several potential objectives:

1. **Reconnaissance**: The attacker was gathering information about the system's hardware, software, running services, and resources. This step is often preliminary to identifying vulnerabilities that could be exploited in future attacks.

2. **Expanding Footprint**: By collecting details about the system's configuration, the attacker might be looking to expand their footprint within the compromised network, particularly if the system is part of a larger network or organization.

3. **Identifying Targets for Exploitation**: The collected information might be used to identify potential vulnerabilities such as outdated software versions or misconfigured services that could be exploited.

4. **Planning for Resource Exhaustion or Denial-of-Service**: By determining the system resources available (memory, CPU), the attacker might be laying the groundwork for a resource exhaustion attack or a Distributed Denial of Service (DDoS) if the system serves as an intermediary or part of a botnet.

5. **Searching for Indicators of Virtual Environment**: Commands like `dmesg | grep irtual` suggest the attacker could be looking for evidence of a virtual environment, which could alter their approach, as virtualized systems can sometimes indicate a honeypot or a system with snapshot capabilities.

It is important to note that without direct evidence of exploitation, data extraction, or lateral movement, the intention can only be inferred from the reconnaissance activities. If additional context or evidence of further malicious activities is provided, a more definitive goal of the attack might be determined.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
If the system targeted by the attacker is vulnerable, the chances of a successful attack increase significantly. The success of the attack would largely depend on a few key factors:

1. **Presence of Vulnerabilities**: If the reconnaissance commands identified unpatched software, misconfigurations, or weak security practices, the attacker might exploit these vulnerabilities.

2. **Skill Level of the Attacker**: A knowledgeable and skilled attacker would be more likely to successfully compromise a vulnerable system by exploiting known weaknesses or finding zero-day vulnerabilities.

3. **Security Measures in Place**: If the system lacks adequate security controls, such as firewalls, intrusion detection/prevention systems, or up-to-date antivirus software, it would be easier for the attacker to succeed.

4. **Response Time and Incident Handling**: If the attack or unusual activity is detected in real time and the security team responds quickly, the impact of the attack could be mitigated, reducing its success rate.

5. **Deployment of Exploitation Techniques**: Should the attacker have access to advanced exploitation techniques or tools that can bypass security measures, the probability of a successful attack goes up.

Considering the attacker was engaged in reconnaissance and had targeted a honeypot, it's possible that their true intention was to gather information, without a specific vulnerable system in mind. Honeypots are typically designed to attract attackers and can be intentionally made to appear vulnerable to study the attackers' behavior or tactics. If the system is, in fact, a honeypot, it could be well-monitored and isolated, meaning that an "attack" may only inform defensive strategies without causing real harm.

To conclusively determine the risk of success, further investigation into any vulnerabilities found and subsequent actions taken by the attacker after the reconnaissance phase would be necessary.

# How Can A System Be Protected From This Attack?
To protect a system from the type of attack described, which is primarily reconnaissance-focused, there are several strategies that can be implemented to enhance security:

1. **Patch Management**: Regularly update and patch operating systems, applications, and firmware to address known vulnerabilities that could be exploited.

2. **Configuration Management**: Ensure that systems are securely configured, unnecessary services are disabled, and default settings (such as passwords) are changed.

3. **Firewalls and Network Segmentation**: Use firewalls to restrict inbound and outbound traffic to the necessary minimum, and segment networks to limit an attacker's lateral movement.

4. **Intrusion Detection and Prevention Systems (IDPS)**: Deploy IDPS to monitor network and system activities for malicious actions or policy violations.

5. **User Account Management**: Enforce the principle of least privilege, ensuring users only have the access necessary for their role. Use strong, unique passwords, and implement multi-factor authentication where possible.

6. **Security Monitoring and Logging**: Implement comprehensive logging and monitoring to detect suspicious activities. Regularly review logs and employ a Security Information and Event Management (SIEM) system for real-time analysis.

7. **Endpoint Protection**: Use reputable antivirus and anti-malware solutions to detect and block malicious payloads.

8. **Employee Training and Security Awareness**: Educate users on recognizing phishing attempts and following good security practices, as human error can often be exploited.

9. **Regular Vulnerability Assessments and Penetration Testing**: Periodically assess your environment for vulnerabilities and conduct penetration tests to evaluate the effectiveness of security controls.

10. **Incident Response Plan**: Develop and regularly update an incident response plan to help contain, eradicate, and recover from any security incidents.

11. **Monitoring Access Attempts**: Observe and analyze failed access attempts, as they might indicate reconnaissance or brute-force attack efforts.

12. **Honeypots**: Deploy honeypots as decoys to detect, deflect, or study hacking attempts.

13. **Threat Intelligence**: Leverage threat intelligence feeds to stay informed about the latest threats and apply proactive defenses.

By combining these tactics, organizations can establish a layered defense approach that makes it much harder for an attacker to successfully compromise systems following the reconnaissance phase of an attack.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
Indicators of Compromise (IOCs) for this attack, based on the conducted reconnaissance activities and information gathered from various OSINT sources, may include:

1. **Source IP Address**: `91.92.251.103` – The initiating IP address for the reconnaissance activity which has been reported in various threat intelligence feeds.

2. **SSH Fingerprint (HASSH)**: `a7a87fbe86774c2e40cc4a7ea2ab1b3c` – A unique identifier for the SSH client used in the connection attempts.

3. **SSH Client Version**: `SSH-2.0-libssh2_1.8.2` – The specific SSH client library version used during the attack.

4. **Destination Port**: `2222` – The port targeted by the attack, which may indicate an attempt to exploit a service running on this non-standard SSH port.

5. **Reconnaissance Commands**: The particular commands used (`uname -a`, `cat /proc/cpuinfo`, `free -m`, `dmidecode|grep Vendor|head -n 1`, `ps -x`, `dmesg | grep irtual`) serve as IOCs, indicating an attacker attempting to profile the system.

6. **Connection Patterns**: The repeated and systematic connection attempts to the same destination IP and port can represent an IOC, suggesting a targeted approach.

7. **Blocked or Alerted Attempts**: Interactions from the source IP that were flagged or blocked by security devices or services, as indicated in threat intelligence reports.

8. **Threat Intelligence Listings**: Appearance of the source IP in threat intelligence blocklists such as blocklist.de, dataplane.org, and those reported by CyberGordon's data sources.

Remember, IOCs can evolve as attackers adapt their techniques, so effective security requires continuous monitoring, updating threat intelligence sources, and refining security measures as new evidence emerges. The IOCs listed here are specific to the attack details that have been provided.

# What do you know about the attacker?
The critical findings from the OSINT sources regarding the IP address `91.92.251.103` involved in the attack can be summarized as follows:

- **Location**: The IP is geographically associated with Amsterdam, Netherlands, according to Shodan, and Bulgaria as per IPdata.co provided by CyberGordon.

- **Organization**: The network is managed by Neterra Ltd., with services provided by Limenet, and it holds an Autonomous System Number (ASN) of AS394711.

- **Threat Intelligence and Reports**:
  - Reported 253 times and targeted 127 honeypots, first seen on December 2, 2023, and last active on December 5, 2023, according to ISC data.
  - The IP has been labeled as malicious by GreyNoise and is known for scanning the internet.
  - The IP is rated at a high-risk level and has been reported for malicious activities, including scanners and brute force, by multiple sources, including webroot.com, dataplane.org, blocklist.de, and AbuseIPDB.
  - The threat level associated with this IP is classified as high risk (100% risk score by AbuseIPDB), and it's been involved in SSH brute force attacks according to data from Pulsedive.

- **Blocklist Inclusion**: The IP has been included in various blocklists and has been marked for malicious/attacker activity and abuse/bot activity. Some of the blocklists it appears on include Blocklist.de, Rutgers, Stratosphere, and USTC.edu.cn.

- **Security Platforms Recognition**: The IP is recognized across various security platforms, including:
  - MetaDefender: implicating the IP in web threats.
  - Pulsedive: listing the IP in association with medium-risk activity and SSH brute force lists.
  - BlackList DE: reporting the IP in multiple attacks and reports.
  - AlienVault OTX: identifying the IP in multiple pulse-feeds.
  - Offline Feeds: including IPsum, listing the IP in association with botnets, zombies, and scanners.

Overall, OSINT sources present a comprehensive profile of `91.92.251.103` as being a significant threat actor, heavily involved in malicious internet activities such as scanning, brute force attacks, especially targeting SSH services, and holding a persistent reputation on various security intelligence feeds and blocklists. This paints the picture of an IP address that is frequently used for nefarious purposes with a broad recognition across the cyber security community.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
The IP address `91.92.251.103` involved in the attack is associated with the following location information:

- **Country**: Netherlands
- **City**: Amsterdam
- **Organization**: Neterra Ltd.
- **ISP**: Limenet
- **ASN**: AS394711

It appears that the attack was originated from an IP address located in Amsterdam, Netherlands, with network services provided by Neterra Ltd. through ISP Limenet. No specific information is provided about open ports or running services from the limited data available, except for a mention of port 123 with UDP protocol which service name is unknown.

* This attack involved `1` unique IP addresses. `1` were source IPs.`0` unique IPs and `0` unique URLS were found in the commands.`0` unique IPs and `0` unique URLS were found in malware.
* The most common **Country** of origin was `Netherlands`, which was seen `1` times.
* The most common **City** of origin was `Amsterdam`, which was seen `1` times.
* The most common **ISP** of origin was `Limenet`, which was seen `1` times.
* The most common **Organization** of origin was `Neterra Ltd.`, which was seen `1` times.
* The most common **ASN** of origin was `AS394711`, which was seen `1` times.
* The most common **network** of origin was `91.92.251.0/24`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 91.92.251.103 | Netherlands | Amsterdam | Limenet | Neterra Ltd. | AS394711 | 91.92.251.0/24 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
The CyberGordon database provides a wealth of information about the IP address `91.92.251.103` involved in the attack:

- **[E33] GreyNoise**: The IP was last reported on December 6, 2023, as malicious and actively scanning the internet over the last three months.
  
- **[E26] MetaDefender**: It has been found in three sources with attributes including high risk, brute force, and scanner activities from sources such as webroot.com, dataplane.org, and blocklist.de.

- **[E34] IPdata.co**: Geographically located in Bulgaria, the network is AS394711 and is run by Limenet, categorized as business. There are risks associated with malicious/attacker activity and abuse/bot activity. It is listed on multiple blocklists including Blocklist.de and others.

- **[E2] AbuseIPDB**: The IP is used by LIMENET and tagged for Data Center/Web Hosting/Transit with a risk score of 100%. There have been 631 reports from 178 users, with the last report being on December 7, 2023.

- **[E11] DShield/ISC**: There have been 253 reports listing 127 targets with the last activity on December 5, 2023.

- **[E17] Pulsedive**: The risk level is medium with the last sighting on December 4, 2023. It's been found in threat lists including SSH Brute Force and in feed lists such as Blocklist.de Blocklist, Dictionary SSH Attacks, and Brute Force Hosts. SSH is listed as an opened service.

- **[E24] BlackList DE**: The IP has been implicated in 68 attacks and 4 reports.

- **[E12] AlienVault OTX**: Found in 17 pulse-feeds.

- **[E23] Offline Feeds**: The IP is included in IPsum (3+ blocklists), and is associated with EU botnets, zombies, and scanners.

The evidence provided by CyberGordon suggests that the IP address `91.92.251.103` is part of a larger pattern of malicious activities and is frequently involved in internet scanning, brute force activities, and is widely recognized across various security platforms as a high-risk entity.

* `12` total alerts were found across all engines.
* `5` were **high** priority. 
* `4` were **medium** priority. 
* `3` were **low** priority. 
* The IP address with the **most high priority alerts** was `91.92.251.103` with `5` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E19] ThreatMiner | [E23] Offline Feeds | [E24] BlackList DE | [E26] MetaDefender | [E33] GreyNoise | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 91.92.251.103 | `5` \| `4` \| `3` | <details>`Geo: Amsterdam, North Holland, NL. Network: AS394711 Limenet. `<summary>`low`</summary></details> | <details>` ISP: LIMENET. Usage: Data Center/Web Hosting/Transit. Risk 100%. 631 report(s) by 178 user(s), last on 07 December 2023  `<summary>`high`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 253 report(s) listing 127 target(s), last on 5 Dec 2023 `<summary>`high`</summary></details> | <details>`Found in 17 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: medium. Last seen on 4 Dec 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH. `<summary>`medium`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | <details>`Found in IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners `<summary>`medium`</summary></details> | <details>`Found in 68 attack(s) and 4 report(s) `<summary>`medium`</summary></details> | <details>`Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) `<summary>`high`</summary></details> | <details>`Last report on 06 December 2023 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Bulgaria. Network: AS394711, Limenet, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Blocklist.de, Charles Haley, DataPlane.org, James Brine, Rescure.me, Rutgers, Stratosphere, ToastedSpam.com, USTC.edu.cn. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 91.92.251.103</h3>
</summary>


### Cybergordon results for: 91.92.251.103 [https://cybergordon.com/r/d2f6a0d6-ad4b-43ec-8841-dba80e74c9d9](https://cybergordon.com/r/d2f6a0d6-ad4b-43ec-8841-dba80e74c9d9)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 06 December 2023 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/91.92.251.103 |
| [E26] MetaDefender | Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner)  | https://metadefender.opswat.com |
| [E34] IPdata.co | Geo: Bulgaria. Network: AS394711, Limenet, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Blocklist.de, Charles Haley, DataPlane.org, James Brine, Rescure.me, Rutgers, Stratosphere, ToastedSpam.com, USTC.edu.cn.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: LIMENET. Usage: Data Center/Web Hosting/Transit. Risk 100%. 631 report(s) by 178 user(s), last on 07 December 2023   | https://www.abuseipdb.com/check/91.92.251.103 |
| [E11] DShield/ISC | Found in 253 report(s) listing 127 target(s), last on 5 Dec 2023  | https://isc.sans.edu/ipinfo.html?ip=91.92.251.103 |
| [E17] Pulsedive | Risk: medium. Last seen on 4 Dec 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E24] BlackList DE | Found in 68 attack(s) and 4 report(s)  | https://www.blocklist.de/en/search.html?ip=91.92.251.103 |
| [E12] AlienVault OTX | Found in 17 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/91.92.251.103 |
| [E23] Offline Feeds | Found in IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners  | / |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=103.251.92.91.in-addr.arpa&type=PTR |
| [E1] IPinfo | Geo: Amsterdam, North Holland, NL. Network: AS394711 Limenet.  | https://ipinfo.io/91.92.251.103 |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=91.92.251.103 |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
The information from Shodan regarding the IP address `91.92.251.103` involved in the attack provides the following details:

- The IP address is registered in **Amsterdam, Netherlands**.
- The network is managed by **Neterra Ltd.**
- The Internet Service Provider (ISP) is identified as **Limenet**.
- The Autonomous System Number (ASN) for this IP is **AS394711**.
- Shodan also lists port **123** which is typically used for the Network Time Protocol (NTP), but there's no detailed service information available for this port, as it's labeled "unknown."

This Shodan summary gives a general idea of where the attack originated geographically and which organization is responsible for the network infrastructure of the attacking IP. It also suggests that the attacker might have network services exposed or running, as indicated by the mention of an open port, which might be used either for legitimate purposes or potentially for malicious intent.

- The most common **open port** was `123`, which was seen `1` times.
- The most common **protocol** was `udp`, which was seen `1` times.
- The most common **service name** was `unknown`, which was seen `1` times.
- The most common **service signature** was `NTP`, which was seen `1` times.
- The most common **Country** was `Netherlands`, which was seen `1` times.
- The most common **City** was `Amsterdam`, which was seen `1` times.
- The most common **Organization** was `Neterra Ltd.`, which was seen `1` times.
- The most common **ISP** was `Limenet`, which was seen `1` times.
- The most common **ASN** was `AS394711`, which was seen `1` times.
- The IP address with the **most open ports** was `91.92.251.103` with `1` open ports.

| IP Addresss | # Open Ports | 123 |
| --- | --- | --- |
| 91.92.251.103 | <details>`123`<summary>`1`</summary></details> | unknown |

<details>
<summary>
<h4>Top 1 Open Ports</h4>
</summary>

Total Open Ports: `1`
Unique: `1`

| Open Port | Times Seen |
| --- | --- |
| `123` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `1`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `udp` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Service Names</h4>
</summary>

Total Service Names: `1`
Unique: `1`

| Service Name | Times Seen |
| --- | --- |
| `unknown` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Service Signatures</h4>
</summary>

Total Service Signatures: `1`
Unique: `1`

| Service Signature | Times Seen |
| --- | --- |
| `NTP` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Countrys</h4>
</summary>

Total Countrys: `1`
Unique: `1`

| Country | Times Seen |
| --- | --- |
| `Netherlands` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Citys</h4>
</summary>

Total Citys: `1`
Unique: `1`

| City | Times Seen |
| --- | --- |
| `Amsterdam` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Organizations</h4>
</summary>

Total Organizations: `1`
Unique: `1`

| Organization | Times Seen |
| --- | --- |
| `Neterra Ltd.` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 ISPs</h4>
</summary>

Total ISPs: `1`
Unique: `1`

| ISP | Times Seen |
| --- | --- |
| `Limenet` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 ASNs</h4>
</summary>

Total ASNs: `1`
Unique: `1`

| ASN | Times Seen |
| --- | --- |
| `AS394711` | `1` |

</details>

---


### Shodan Results

<details>
<summary>
<h3>Shodan results for: 91.92.251.103</h3>
</summary>


### Shodan results for: 91.92.251.103 [https://www.shodan.io/host/91.92.251.103](https://www.shodan.io/host/91.92.251.103)

| Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- |
| Netherlands | Amsterdam | Neterra Ltd. | Limenet | AS394711 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 123 | udp | unknown | 2023-11-10T08:28:58.053362 |

#### Port 123 (udp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 123 (udp): unknown</h4>
</summary>


```
NTP
protocolversion: 3
stratum: 2
leap: 0
precision: -22
rootdelay: 0.00474548339844
rootdisp: 0.0238342285156
refid: 764032829
reftime: 3908593206.9
poll: 3
```

</details>

---


| Key | Value |
| --- | --- |
| sig | NTP |
| protocolversion | 3 |
| stratum | 2 |
| leap | 0 |
| precision | -22 |
| rootdelay | 0.00474548339844 |
| rootdisp | 0.0238342285156 |
| refid | 764032829 |
| reftime | 3908593206.9 |
| poll | 3 |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
The ThreatFox database does not contain any information regarding the IP address `91.92.251.103` involved in the attack. This could mean that the IP has not been identified by ThreatFox as associated with any indicators of compromise (IOCs) or that it may not have been reported within their system as part of a known threat or malware campaign.

Without data from ThreatFox, we cannot further associate this IP address with specific malware or threat actors based on their intelligence feeds.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Using ISC (Internet Storm Center) data, the following information is known about the IP address `91.92.251.103` involved in the attack:

- **Total Reports**: The IP address has been reported a total of 253 times.
- **Honeypots Targeted**: It has targeted 127 honeypots.
- **First Seen**: The first record of activity from this IP was on December 2, 2023.
- **Last Seen**: The most recent record of activity was on December 5, 2023.
- **Network**: The IP is part of the `91.92.251.0/24` network segment.
- **AS Name**: The network is managed by LIMENET.
- **Country Code**: The AS is registered in the United States.
- **Threat Feeds**: The IP has appeared in threat feeds, specifically, it has been listed in `blocklistde22`, first seen on the same date as by ISC, December 2, 2023, and last seen on December 6, 2023.

This data suggests that the IP has a history of malicious activity and is likely part of a wider network of IPs involved in similar activity. It has also been flagged by at least one threat feed, indicating that it might be part of a known botnet or associated with other malicious activities.

* `1` of the `1` unique source IPs have reports on the Internet Storm Center (ISC).
* `253` total attacks were reported.
* `127` unique targets were attacked.
* The IP address with the **most reports** was `91.92.251.103` with `253` reports.
* The IP address with the **most targets** was `91.92.251.103` with `127` targets.
* The **first report** was on `2023-12-02` from `91.92.251.103`.
* The **most recent** was on `2023-12-05` from `91.92.251.103`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 91.92.251.103 | 253 | 127 | 2023-12-02 | 2023-12-05 | 2023-12-06 04:06:46 |

<details>
<summary>
<h4>Top 1 As</h4>
</summary>

Total ass: `1`
Unique: `1`

| as | Times Seen |
| --- | --- |
| `394711` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Asnames</h4>
</summary>

Total asnames: `1`
Unique: `1`

| asname | Times Seen |
| --- | --- |
| `LIMENET` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Ascountrys</h4>
</summary>

Total ascountrys: `1`
Unique: `1`

| ascountry | Times Seen |
| --- | --- |
| `US` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Assizes</h4>
</summary>

Total assizes: `1`
Unique: `1`

| assize | Times Seen |
| --- | --- |
| `12800` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Networks</h4>
</summary>

Total networks: `1`
Unique: `1`

| network | Times Seen |
| --- | --- |
| `91.92.251.0/24` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Threatfeeds</h4>
</summary>

Total threatfeedss: `1`
Unique: `1`

| threatfeeds | Times Seen |
| --- | --- |
| `blocklistde22` | `1` |

</details>

---


</details>

---


<details>
<summary>
<h2>Whois</h2>
</summary>


### Whois Results Summary

<details>
<summary>
<h3>Whois data for: 91.92.251.103</h3>
</summary>


### Whois data for: 91.92.251.103 [https://www.whois.com/whois/91.92.251.103](https://www.whois.com/whois/91.92.251.103)

```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '91.92.251.0 - 91.92.251.255'

% Abuse contact for '91.92.251.0 - 91.92.251.255' is '@limenet.io'

inetnum:        91.92.251.0 - 91.92.251.255
netname:        LIME_NET-NET
country:        NL
mnt-domains:    lime-net-mnt
mnt-routes:     lime-net-mnt
org:            ORG-LA1853-RIPE
admin-c:        IT3219-RIPE
tech-c:         IT3219-RIPE
status:         ASSIGNED PA
mnt-by:         MNT-NETERRA
created:        2023-09-25T06:49:42Z
last-modified:  2023-11-09T09:13:04Z
source:         RIPE

organisation:   ORG-LA1853-RIPE
org-name:       Limenet
org-type:       OTHER
address:        84 W Broadway, Ste 200
address:        03038 Derry
address:        United States of America
abuse-c:        ACRO53914-RIPE
mnt-ref:        limenet-mnt
mnt-ref:        MNT-NETERRA
mnt-by:         limenet-mnt
mnt-by:         MNT-NETERRA
created:        2023-08-30T07:21:20Z
last-modified:  2023-09-25T06:42:09Z
source:         RIPE # Filtered

person:         IT Technical
address:        84 W Broadway, Ste 200
address:        03038 Derry
address:        United States of America
phone:          +1-505-297-1370
nic-hdl:        IT3219-RIPE
mnt-by:         limenet-mnt
created:        2023-08-30T07:18:31Z
last-modified:  2023-08-30T07:26:07Z
source:         RIPE

% Information related to '91.92.251.0/24AS394711'

route:          91.92.251.0/24
origin:         AS394711
mnt-by:         lime-net-mnt
created:        2023-10-23T13:59:31Z
last-modified:  2023-10-23T13:59:31Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.109 (DEXTER)
```

</details>

---


</details>

---

