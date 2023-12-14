
# Password Change and System Information Reconnaissance with Unauthorized Curl Installation

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `3` unique source IP address(es): `165.232.188.209`, `104.248.26.212`, `64.227.46.76`
- A total of `14` sessions were logged. `4` sessions were successful logins.
- `14` login attempts were made. `4` were successful.
- `5` unique username/password pairs were attempted. `2` were successful.
- `1` unique destination ports were targeted: `2222`
- `14` unique source ports were used: `33170`, `42470`, `42476`, `42486`, `43510`, `56306`, `56320`, `56328`, `59462`, `59474`, `54138`, `34496`, `34502`, `50172`
- `2` commands were input in total. `0` IP(s) and `1` URL(s) were found in the commands
- `1` unique malware samples were downloaded. `0` IP(s) and `2` URL(s) were found in the malware samples
- This attacks was recorded in `2` log types: `cowrie.log`, `cowrie.json`
- A total of `231` log events were logged in `4` log files: `cowrie.2023-11-06.log`, `cowrie.2023-11-04.log`, `cowrie.2023-11-06.json`, `cowrie.2023-11-04.json`

</details>

---

## Attack Summary Report

### Attack Details:
- **Date of Attack:** Specific dates nto provided, but activity reports date as far back as November 2023.
- **Attack Vector:** The attack was initiated via a network, likely through SSH based on the HASSH and version string (`SSH-2.0-Go`).
- **Target:** A Linux honeypot system with SSH service running on port `2222`.
- **Source of Attack:** Multiple IP addresses were identified as the source of the attack:
  - `165.232.188.209`
  - `104.248.26.212`
  - `64.227.46.76`

### Attack Methods:
- **Initial Access and Persistence:**
  - Utilized SSH for initial access.
  - Changed the root password to `qqr4vyjB`, potentially for maintaining persistent access.
- **Reconnaissance:**
  - Executed `lscpu` to obtain CPU architecture information.
  - Ran `curl` with the `--insecure -s` flags to gather information about the system's network environment from `https://ipinfo.io/org`.
- **Preparation:**
  - Updated the system package lists and installed `curl`, possibly to facilitate further actions or data exfiltration.

### Attack Goals:
Based on the observed behavior, the goals of the attacker may include:
- Establishing and maintaining unauthorized access to the target system.
- Conducting reconnaissance to collect valuable system and network information.
- Preparing the compromised system for subsequent stages of an attack, which could include lateral movement, further exploitation, installation of additional malicious payloads, or staging for botnet campaigns.

### Indicators of Compromise (IOCs):
- **Source IP Addresses**
- **SSH Port `2222` and SSH version `SSH-2.0-Go`**
- **Commands used for system reconnaissance and preparation**
- **SHA256 Hash of the associated malware file**

### Recommendation:
- Immediate isolation and investigation of the compromised system.
- Application of network restrictions and account security measures.
- Deployment of real-time monitoring and alerting based on identified IOCs.
- Conducting a forensic analysis to uncover the full scope of the compromise.

The summary outlines the key aspects of the attack, providing essential data required for understanding the threat, identifying the impact, and guiding the response strategy to address and mitigate the security incident.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `3` unique **source IP** address(es):
	- `SourceIP 165.232.188.209 with 8 sessions, 1 dst_ports 2 successful logins, 2 commands, 0 uploads, 1 downloads`
	- `SourceIP 104.248.26.212 with 3 sessions, 1 dst_ports 1 successful logins, 2 commands, 0 uploads, 1 downloads`
	- `SourceIP 64.227.46.76 with 3 sessions, 1 dst_ports 1 successful logins, 3 commands, 0 uploads, 1 downloads`

- `14` unique **source ports** were used:
	- `Src Port: 33170 Used 1 times`
	- `Src Port: 42470 Used 1 times`
	- `Src Port: 42476 Used 1 times`
	- `Src Port: 42486 Used 1 times`
	- `Src Port: 43510 Used 1 times`
	- `Src Port: 56306 Used 1 times`
	- `Src Port: 56320 Used 1 times`
	- `Src Port: 56328 Used 1 times`
	- `Src Port: 59462 Used 1 times`
	- `Src Port: 59474 Used 1 times`
	- `Src Port: 54138 Used 1 times`
	- `Src Port: 34496 Used 1 times`
	- `Src Port: 34502 Used 1 times`
	- `Src Port: 50172 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2222` Used `14` times`

- A total of `14` sessions were logged:
	- `Session e5c1c780f18c SSH 165.232.188.209:33170 -> 172.31.5.68:2222 Duration: 2.78s`
	- `Session 42b6b64f690a SSH 165.232.188.209:42470 -> 172.31.5.68:2222 Duration: 3.02s`
	- `Session 3ed17ab2f1f8 SSH 165.232.188.209:42476 -> 172.31.5.68:2222 Duration: 3.02s`
	- `Session 2adf02c7f94b SSH 165.232.188.209:42486 -> 172.31.5.68:2222 Duration: 3.21s`
	- `Session 641796365932 SSH 165.232.188.209:43510 -> 172.31.5.68:2222 Login: root:1 Duration: 1.93s`
	- `Session ebcf83719a13 SSH 165.232.188.209:56306 -> 172.31.5.68:2222 Duration: 2.21s`
	- `Session f60c22e74bdb SSH 165.232.188.209:56320 -> 172.31.5.68:2222 Duration: 2.45s`
	- `Session 85a2e6c7746c SSH 165.232.188.209:56328 -> 172.31.5.68:2222 Login: root:root Commands: 2, Malware: 1, Duration: 2.98s`
	- `Session 869121482490 SSH 104.248.26.212:59462 -> 172.31.5.68:2222 Duration: 1.89s`
	- `Session 4da65924ddfb SSH 104.248.26.212:59474 -> 172.31.5.68:2222 Duration: 2.33s`
	- `Session b24ad7ca809e SSH 104.248.26.212:54138 -> 172.31.5.68:2222 Login: root:root Commands: 2, Malware: 1, Duration: 2.15s`
	- `Session 80b613f344f2 SSH 64.227.46.76:34496 -> 172.31.5.68:2222 Duration: 1.81s`
	- `Session 0b6b3f82c74e SSH 64.227.46.76:34502 -> 172.31.5.68:2222 Duration: 1.97s`
	- `Session 6096d0008bed SSH 64.227.46.76:50172 -> 172.31.5.68:2222 Login: root:root Commands: 3, Malware: 1, Duration: 4.18s`

- `4` were **successful logins**, 
- `10` were **failed logins**, 
- `3` had commands, 
- `3` had malware.
- `14` unique username/password pairs were attempted. `4` were successful.
- `2` commands were input in total. `0` IP(s) and `3` URL(s) were found in the commands
- `1` unique malware samples were downloaded. 
- `0` IP(s) and `2` URL(s) were found in the malware samples
- This attacks was recorded in `2` log types: 
	- `cowrie.log`
	- `cowrie.json`

- A total of `231` log events were logged in `4` log files: 
	- `cowrie.2023-11-06.log`
	- `cowrie.2023-11-04.log`
	- `cowrie.2023-11-06.json`
	- `cowrie.2023-11-04.json`


</details>

---


<details>
<summary>
<h1>Custom Scripts Used To Generate This Report</h1>
</summary>


#### [main.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/main.py)
> Main script for running all analyzers through AttackAnalyzer inteface. (IN PROGRESS)

#### [runtests.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/runtests.py)
> Script for running tests from the tests directory

#### [analyzerbase](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase)
> Base classes, utility functions, libraries, and constants for all analyzer modules

| Script | Description |
| --- | --- |
| [attack.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/attack.py) | Attack object for storing all data related to a single attack. Constructed by the loganalyzer scripts then processed by openaianlyzers and ipanalyzers before being passed to markdownwriters |
| [common.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/common.py) | Imports and constants used by all analyzer modules |
| [malware.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/malware.py) | Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object |
| [session.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/session.py) | Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object |
| [sourceip.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/sourceip.py) | SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object |
| [util.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/analyzerbase/util.py) | Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text |

#### [loganalyzers](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers)
> Scripts for analyzing logs to create Attack objects, organizing and read Attack files

| Script | Description |
| --- | --- |
| [logparser.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers/logparser.py) | Classes for reading all logs as json objects with standardized keys |
| [cowrieloganalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers/cowrieloganalyzer.py) | Reads Cowrie logs to create and merge Attack objects |
| [webloganalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers/webloganalyzer.py) | Reads Web logs to create and merge Attack objects (IN PROGRESS) |
| [attackdirorganizer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers/attackdirorganizer.py) | Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading |
| [attackdirreader.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/loganalyzers/attackdirreader.py) | Reads Attack files from directories organized by attackdirorganizer |

#### [openaianalyzers](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/openaianalyzers)
> Scripts for analyzing Attack objects using OpenAI's Completion and Assistant APIs

| Script | Description |
| --- | --- |
| [aibase.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/openaianalyzers/aibase.py) | Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost |
| [completions.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/openaianalyzers/completions.py) | OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code |
| [assistant.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/openaianalyzers/assistant.py) | OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about the attack |
| [tools.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/openaianalyzers/tools.py) | Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects |

#### [osintanalyzers](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers)
> Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object

| Script | Description |
| --- | --- |
| [osintbase.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers/osintbase.py) | Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer |
| [ipanalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers/ipanalyzer.py) | IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois |
| [mwanalyzer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers/mwanalyzer.py) | MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, and Malpedia,  |
| [soupscraper.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers/soupscraper.py) | SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects |
| [getchromedrier.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/osintanalyzers/getchromedrier.py) | Utility script to download correct chromedriver for Selenium |

#### [markdownwriters](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriters)
> Scripts for writing markdown files from Attack objects

| Script | Description |
| --- | --- |
| [markdownwriterbase.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriters/markdownwriterbase.py) | Base class for all markdown writers and markdown shortcut functions |
| [cowrieattackmarkdownwriter.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriters/cowrieattackmarkdownwriter.py) | Markdown writer for Cowrie Attack objects (TODO abstract this to be AttackMarkdownWriter so it can be used for all future Attack objects types, Cowrie, Web, etc.) |
| [ipmarkdownwriter.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriters/ipmarkdownwriter.py) | Markdown writer for ipdata added to Attack objects by IPAnalyzer |
| [visualizer.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/markdownwriters/visualizer.py) | Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts'] |

#### [tests](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests)
> Tests for all analyzer modules

| Script | Description |
| --- | --- |
| [test_analyzerbase.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests/test_analyzerbase.py) | Tests for analyzerbase |
| [test_loganalyzers.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests/test_loganalyzers.py) | Tests for loganalyzers |
| [test_openaianalyzers.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests/test_openaianalyzers.py) | Tests for openaianalyzers |
| [test_osintanalyzers.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests/test_osintanalyzers.py) | Tests for osintanalyzers |
| [test_markdownwriter.py](https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/tests/test_markdownwriter.py) | Tests for markdownwriter |

</details>

---


<details>
<summary>
<h1>Time and Date of Activity</h1>
</summary>

First activity logged: `2023-11-04 03:04:39.726562`
* First session: `e5c1c780f18c`
* `Session e5c1c780f18c SSH 165.232.188.209:33170 -> 172.31.5.68:2222 Duration: 2.78s`

Last activity logged: `2023-11-06 21:20:16.609846`
* Last session: `6096d0008bed`
* `Session 6096d0008bed SSH 64.227.46.76:50172 -> 172.31.5.68:2222 Login: root:root Commands: 3, Malware: 1, Duration: 4.18s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `e5c1c780f18c` | `165.232.188.209` | `33170` | `2222` | `2023-11-04 03:04:39.726562` | `2023-11-04 03:04:42.505244` | `2.7761945724487305` |
| `6096d0008bed` | `64.227.46.76` | `50172` | `2222` | `2023-11-06 21:20:12.433860` | `2023-11-06 21:20:16.609846` | `4.175319194793701` |

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `e5c1c780f18c` | `165.232.188.209` | `33170` | `2222` | `2023-11-04 03:04:39.726562` | `2023-11-04 03:04:42.505244` | `2.7761945724487305` |
| `42b6b64f690a` | `165.232.188.209` | `42470` | `2222` | `2023-11-04 03:04:42.741263` | `2023-11-04 03:04:45.766309` | `3.0243988037109375` |
| `3ed17ab2f1f8` | `165.232.188.209` | `42476` | `2222` | `2023-11-04 03:04:45.996356` | `2023-11-04 03:04:49.020609` | `3.023489236831665` |
| `2adf02c7f94b` | `165.232.188.209` | `42486` | `2222` | `2023-11-04 03:04:49.244847` | `2023-11-04 03:04:52.458079` | `3.212587833404541` |
| `641796365932` | `165.232.188.209` | `43510` | `2222` | `2023-11-04 03:04:52.703706` | `2023-11-04 03:04:54.637265` | `1.9329261779785156` |
| `ebcf83719a13` | `165.232.188.209` | `56306` | `2222` | `2023-11-04 11:46:55.946993` | `2023-11-04 11:46:58.159143` | `2.2114691734313965` |
| `f60c22e74bdb` | `165.232.188.209` | `56320` | `2222` | `2023-11-04 11:46:58.391746` | `2023-11-04 11:47:00.839677` | `2.447192907333374` |
| `85a2e6c7746c` | `165.232.188.209` | `56328` | `2222` | `2023-11-04 11:47:01.075284` | `2023-11-04 11:47:04.053433` | `2.977452039718628` |
| `869121482490` | `104.248.26.212` | `59462` | `2222` | `2023-11-04 23:00:45.927365` | `2023-11-04 23:00:47.819705` | `1.8916726112365723` |
| `4da65924ddfb` | `104.248.26.212` | `59474` | `2222` | `2023-11-04 23:00:47.987593` | `2023-11-04 23:00:50.322369` | `2.334069013595581` |
| `b24ad7ca809e` | `104.248.26.212` | `54138` | `2222` | `2023-11-04 23:00:50.493063` | `2023-11-04 23:00:52.647149` | `2.153447389602661` |
| `80b613f344f2` | `64.227.46.76` | `34496` | `2222` | `2023-11-06 21:20:08.342521` | `2023-11-06 21:20:10.149850` | `1.806603193283081` |
| `0b6b3f82c74e` | `64.227.46.76` | `34502` | `2222` | `2023-11-06 21:20:10.310228` | `2023-11-06 21:20:12.282235` | `1.9713091850280762` |
| `6096d0008bed` | `64.227.46.76` | `50172` | `2222` | `2023-11-06 21:20:12.433860` | `2023-11-06 21:20:16.609846` | `4.175319194793701` |

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
| cowrie.log | 134 |
| cowrie.json | 97 |

## Cowrie .log Logs
Total Cowrie logs: `134`

#### First Session With Commands 85a2e6c7746c Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `85a2e6c7746c` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .log Logs for 85a2e6c7746c</h3>
</summary>


```verilog
2023-11-04T03:04:39.785451Z [HoneyPotSSHTransport,19,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:40.020916Z [HoneyPotSSHTransport,19,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:41.121144Z [HoneyPotSSHTransport,19,165.232.188.209] first time for 165.232.188.209, need: 5
2023-11-04T03:04:41.121778Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt: 1
2023-11-04T03:04:41.124382Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt [b'root'/b'0'] failed
2023-11-04T03:04:42.505244Z [HoneyPotSSHTransport,19,165.232.188.209] Connection lost after 2 seconds
2023-11-04T03:04:42.821053Z [HoneyPotSSHTransport,20,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:43.003255Z [HoneyPotSSHTransport,20,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:44.169627Z [HoneyPotSSHTransport,20,165.232.188.209] login attempt: 2
2023-11-04T03:04:44.172189Z [HoneyPotSSHTransport,20,165.232.188.209] login attempt [b'root'/b'eve'] failed
2023-11-04T03:04:45.766309Z [HoneyPotSSHTransport,20,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:46.092028Z [HoneyPotSSHTransport,21,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:46.295372Z [HoneyPotSSHTransport,21,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:47.671654Z [HoneyPotSSHTransport,21,165.232.188.209] login attempt: 3
2023-11-04T03:04:47.674386Z [HoneyPotSSHTransport,21,165.232.188.209] login attempt [b'root'/b'root'] failed
2023-11-04T03:04:49.020609Z [HoneyPotSSHTransport,21,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:49.349628Z [HoneyPotSSHTransport,22,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:49.600458Z [HoneyPotSSHTransport,22,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:51.125725Z [HoneyPotSSHTransport,22,165.232.188.209] login attempt: 4
2023-11-04T03:04:51.128350Z [HoneyPotSSHTransport,22,165.232.188.209] login attempt [b'ossuser'/b'Changeme_123'] failed
2023-11-04T03:04:52.458079Z [HoneyPotSSHTransport,22,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:52.765401Z [HoneyPotSSHTransport,23,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:52.989634Z [HoneyPotSSHTransport,23,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:54.049670Z [HoneyPotSSHTransport,23,165.232.188.209] login attempt: 5
2023-11-04T03:04:54.052032Z [HoneyPotSSHTransport,23,165.232.188.209] login attempt [b'root'/b'1'] succeeded
2023-11-04T03:04:54.052916Z [HoneyPotSSHTransport,23,165.232.188.209] Initialized emulated server as architecture: linux-x64-lsb
2023-11-04T03:04:54.636972Z [HoneyPotSSHTransport,23,165.232.188.209] avatar root logging out
2023-11-04T03:04:54.637265Z [HoneyPotSSHTransport,23,165.232.188.209] Connection lost after 1 seconds
2023-11-04T11:46:55.947755Z [HoneyPotSSHTransport,17,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:46:56.187070Z [HoneyPotSSHTransport,17,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:46:56.910666Z [HoneyPotSSHTransport,17,165.232.188.209] already tried this combination
2023-11-04T11:46:56.913620Z [HoneyPotSSHTransport,17,165.232.188.209] login attempt [b'root'/b'0'] failed
2023-11-04T11:46:58.159143Z [HoneyPotSSHTransport,17,165.232.188.209] Connection lost after 2 seconds
2023-11-04T11:46:58.396975Z [HoneyPotSSHTransport,18,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:46:58.629128Z [HoneyPotSSHTransport,18,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:46:59.591642Z [HoneyPotSSHTransport,18,165.232.188.209] already tried this combination
2023-11-04T11:46:59.594399Z [HoneyPotSSHTransport,18,165.232.188.209] login attempt [b'root'/b'eve'] failed
2023-11-04T11:47:00.839677Z [HoneyPotSSHTransport,18,165.232.188.209] Connection lost after 2 seconds
2023-11-04T11:47:01.076065Z [HoneyPotSSHTransport,19,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:47:01.311447Z [HoneyPotSSHTransport,19,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:47:02.032389Z [HoneyPotSSHTransport,19,165.232.188.209] Found cached: b'root':b'root'
2023-11-04T11:47:02.035140Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt [b'root'/b'root'] succeeded
2023-11-04T11:47:02.036608Z [HoneyPotSSHTransport,19,165.232.188.209] Initialized emulated server as architecture: linux-x64-lsb
2023-11-04T11:47:02.536162Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] CMD: apt update && apt install curl -y
2023-11-04T11:47:02.536953Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Can't find command apt
2023-11-04T11:47:02.537055Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command not found: apt update
2023-11-04T11:47:02.537847Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Can't find command apt
2023-11-04T11:47:02.537945Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command not found: apt install curl -y
2023-11-04T11:47:02.774600Z [HoneyPotSSHTransport,19,165.232.188.209] Closing TTY Log: var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729 after 0 seconds
2023-11-04T11:47:03.318159Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] CMD: lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd && curl https://ipinfo.io/org --insecure -s && apt
2023-11-04T11:47:03.320607Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: lscpu 
2023-11-04T11:47:03.320781Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Reading txtcmd from "share/cowrie/txtcmds/usr/bin/lscpu"
2023-11-04T11:47:03.321564Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: passwd 
2023-11-04T11:47:03.321666Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: echo -e qqr4vyjB\nqqr4vyjB
2023-11-04T11:47:03.322047Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: curl https://ipinfo.io/org --insecure -s
2023-11-04T11:47:03.567377Z [HoneyPotSSHTransport,19,165.232.188.209] Closing TTY Log: var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438 after 0 seconds
2023-11-04T11:47:04.053204Z [HoneyPotSSHTransport,19,165.232.188.209] avatar root logging out
2023-11-04T11:47:04.053433Z [HoneyPotSSHTransport,19,165.232.188.209] Connection lost after 2 seconds
2023-11-04T03:04:39.785451Z [HoneyPotSSHTransport,19,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:40.020916Z [HoneyPotSSHTransport,19,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:41.121144Z [HoneyPotSSHTransport,19,165.232.188.209] first time for 165.232.188.209, need: 5
2023-11-04T03:04:41.121778Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt: 1
2023-11-04T03:04:41.124382Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt [b'root'/b'0'] failed
2023-11-04T03:04:42.505244Z [HoneyPotSSHTransport,19,165.232.188.209] Connection lost after 2 seconds
2023-11-04T03:04:42.821053Z [HoneyPotSSHTransport,20,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:43.003255Z [HoneyPotSSHTransport,20,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:44.169627Z [HoneyPotSSHTransport,20,165.232.188.209] login attempt: 2
2023-11-04T03:04:44.172189Z [HoneyPotSSHTransport,20,165.232.188.209] login attempt [b'root'/b'eve'] failed
2023-11-04T03:04:45.766309Z [HoneyPotSSHTransport,20,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:46.092028Z [HoneyPotSSHTransport,21,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:46.295372Z [HoneyPotSSHTransport,21,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:47.671654Z [HoneyPotSSHTransport,21,165.232.188.209] login attempt: 3
2023-11-04T03:04:47.674386Z [HoneyPotSSHTransport,21,165.232.188.209] login attempt [b'root'/b'root'] failed
2023-11-04T03:04:49.020609Z [HoneyPotSSHTransport,21,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:49.349628Z [HoneyPotSSHTransport,22,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:49.600458Z [HoneyPotSSHTransport,22,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:51.125725Z [HoneyPotSSHTransport,22,165.232.188.209] login attempt: 4
2023-11-04T03:04:51.128350Z [HoneyPotSSHTransport,22,165.232.188.209] login attempt [b'ossuser'/b'Changeme_123'] failed
2023-11-04T03:04:52.458079Z [HoneyPotSSHTransport,22,165.232.188.209] Connection lost after 3 seconds
2023-11-04T03:04:52.765401Z [HoneyPotSSHTransport,23,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T03:04:52.989634Z [HoneyPotSSHTransport,23,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T03:04:54.049670Z [HoneyPotSSHTransport,23,165.232.188.209] login attempt: 5
2023-11-04T03:04:54.052032Z [HoneyPotSSHTransport,23,165.232.188.209] login attempt [b'root'/b'1'] succeeded
2023-11-04T03:04:54.052916Z [HoneyPotSSHTransport,23,165.232.188.209] Initialized emulated server as architecture: linux-x64-lsb
2023-11-04T03:04:54.636972Z [HoneyPotSSHTransport,23,165.232.188.209] avatar root logging out
2023-11-04T03:04:54.637265Z [HoneyPotSSHTransport,23,165.232.188.209] Connection lost after 1 seconds
2023-11-04T11:46:55.947755Z [HoneyPotSSHTransport,17,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:46:56.187070Z [HoneyPotSSHTransport,17,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:46:56.910666Z [HoneyPotSSHTransport,17,165.232.188.209] already tried this combination
2023-11-04T11:46:56.913620Z [HoneyPotSSHTransport,17,165.232.188.209] login attempt [b'root'/b'0'] failed
2023-11-04T11:46:58.159143Z [HoneyPotSSHTransport,17,165.232.188.209] Connection lost after 2 seconds
2023-11-04T11:46:58.396975Z [HoneyPotSSHTransport,18,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:46:58.629128Z [HoneyPotSSHTransport,18,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:46:59.591642Z [HoneyPotSSHTransport,18,165.232.188.209] already tried this combination
2023-11-04T11:46:59.594399Z [HoneyPotSSHTransport,18,165.232.188.209] login attempt [b'root'/b'eve'] failed
2023-11-04T11:47:00.839677Z [HoneyPotSSHTransport,18,165.232.188.209] Connection lost after 2 seconds
2023-11-04T11:47:01.076065Z [HoneyPotSSHTransport,19,165.232.188.209] Remote SSH version: SSH-2.0-Go
2023-11-04T11:47:01.311447Z [HoneyPotSSHTransport,19,165.232.188.209] SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a
2023-11-04T11:47:02.032389Z [HoneyPotSSHTransport,19,165.232.188.209] Found cached: b'root':b'root'
2023-11-04T11:47:02.035140Z [HoneyPotSSHTransport,19,165.232.188.209] login attempt [b'root'/b'root'] succeeded
2023-11-04T11:47:02.036608Z [HoneyPotSSHTransport,19,165.232.188.209] Initialized emulated server as architecture: linux-x64-lsb
2023-11-04T11:47:02.536162Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] CMD: apt update && apt install curl -y
2023-11-04T11:47:02.536953Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Can't find command apt
2023-11-04T11:47:02.537055Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command not found: apt update
2023-11-04T11:47:02.537847Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Can't find command apt
2023-11-04T11:47:02.537945Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command not found: apt install curl -y
2023-11-04T11:47:02.774600Z [HoneyPotSSHTransport,19,165.232.188.209] Closing TTY Log: var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729 after 0 seconds
2023-11-04T11:47:03.318159Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] CMD: lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd && curl https://ipinfo.io/org --insecure -s && apt
2023-11-04T11:47:03.320607Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: lscpu 
2023-11-04T11:47:03.320781Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Reading txtcmd from "share/cowrie/txtcmds/usr/bin/lscpu"
2023-11-04T11:47:03.321564Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: passwd 
2023-11-04T11:47:03.321666Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: echo -e qqr4vyjB\nqqr4vyjB
2023-11-04T11:47:03.322047Z [SSHChannel session (1) on SSHService b'ssh-connection' on HoneyPotSSHTransport,19,165.232.188.209] Command found: curl https://ipinfo.io/org --insecure -s
2023-11-04T11:47:03.567377Z [HoneyPotSSHTransport,19,165.232.188.209] Closing TTY Log: var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438 after 0 seconds
2023-11-04T11:47:04.053204Z [HoneyPotSSHTransport,19,165.232.188.209] avatar root logging out
2023-11-04T11:47:04.053433Z [HoneyPotSSHTransport,19,165.232.188.209] Connection lost after 2 seconds

```

</details>

---


## Cowrie .json Logs
Total Cowrie logs: `97`

#### First Session With Commands 85a2e6c7746c Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `85a2e6c7746c` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .json Logs for 85a2e6c7746c</h3>
</summary>


```json
{"eventid":"cowrie.session.connect","src_ip":"165.232.188.209","src_port":56328,"dst_ip":"172.31.5.68","dst_port":2222,"session":"85a2e6c7746c","protocol":"ssh","message":"New connection: 165.232.188.209:56328 (172.31.5.68:2222) [session: 85a2e6c7746c]","sensor":"","timestamp":"2023-11-04T11:47:01.075284Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-Go","message":"Remote SSH version: SSH-2.0-Go","sensor":"","timestamp":"2023-11-04T11:47:01.076065Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.client.kex","hassh":"4e066189c3bbeec38c99b1855113733a","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr;hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","ext-info-c"],"keyAlgs":["rsa-sha2-512-cert-v01@openssh.com","rsa-sha2-256-cert-v01@openssh.com","ssh-rsa-cert-v01@openssh.com","ssh-dss-cert-v01@openssh.com","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519-cert-v01@openssh.com","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","rsa-sha2-512","rsa-sha2-256","ssh-rsa","ssh-dss","ssh-ed25519"],"encCS":["aes128-gcm@openssh.com","chacha20-poly1305@openssh.com","aes128-ctr","aes192-ctr","aes256-ctr"],"macCS":["hmac-sha2-256-etm@openssh.com","hmac-sha2-256","hmac-sha1","hmac-sha1-96"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a","sensor":"","timestamp":"2023-11-04T11:47:01.311447Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-04T11:47:02.035140Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-04T11:47:02.535541Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.input","input":"apt update && apt install curl -y","message":"CMD: apt update && apt install curl -y","sensor":"","timestamp":"2023-11-04T11:47:02.536162Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.failed","input":"apt update","message":"Command not found: apt update","sensor":"","timestamp":"2023-11-04T11:47:02.537055Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.failed","input":"apt install curl -y","message":"Command not found: apt install curl -y","sensor":"","timestamp":"2023-11-04T11:47:02.537945Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729","size":60,"shasum":"f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729","duplicate":false,"duration":0.23928594589233398,"message":"Closing TTY Log: var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729 after 0 seconds","sensor":"","timestamp":"2023-11-04T11:47:02.774600Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-04T11:47:03.317590Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.input","input":"lscpu && echo -e \"qqr4vyjB\\nqqr4vyjB\" | passwd && curl https://ipinfo.io/org --insecure -s && apt","message":"CMD: lscpu && echo -e \"qqr4vyjB\\nqqr4vyjB\" | passwd && curl https://ipinfo.io/org --insecure -s && apt","sensor":"","timestamp":"2023-11-04T11:47:03.318159Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.file_download","url":"https://ipinfo.io/org","outfile":"var/lib/cowrie/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","shasum":"8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","sensor":"","timestamp":"2023-11-04T11:47:03.391847Z","message":"Downloaded URL (https://ipinfo.io/org) with SHA-256 8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358 to var/lib/cowrie/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438","size":2483,"shasum":"ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438","duplicate":false,"duration":0.24996399879455566,"message":"Closing TTY Log: var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438 after 0 seconds","sensor":"","timestamp":"2023-11-04T11:47:03.567377Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.closed","duration":2.977452039718628,"message":"Connection lost after 2 seconds","sensor":"","timestamp":"2023-11-04T11:47:04.053433Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.connect","src_ip":"165.232.188.209","src_port":56328,"dst_ip":"172.31.5.68","dst_port":2222,"session":"85a2e6c7746c","protocol":"ssh","message":"New connection: 165.232.188.209:56328 (172.31.5.68:2222) [session: 85a2e6c7746c]","sensor":"","timestamp":"2023-11-04T11:47:01.075284Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-Go","message":"Remote SSH version: SSH-2.0-Go","sensor":"","timestamp":"2023-11-04T11:47:01.076065Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.client.kex","hassh":"4e066189c3bbeec38c99b1855113733a","hasshAlgorithms":"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr;hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96;none","kexAlgs":["curve25519-sha256","curve25519-sha256@libssh.org","ecdh-sha2-nistp256","ecdh-sha2-nistp384","ecdh-sha2-nistp521","diffie-hellman-group14-sha256","diffie-hellman-group14-sha1","ext-info-c"],"keyAlgs":["rsa-sha2-512-cert-v01@openssh.com","rsa-sha2-256-cert-v01@openssh.com","ssh-rsa-cert-v01@openssh.com","ssh-dss-cert-v01@openssh.com","ecdsa-sha2-nistp256-cert-v01@openssh.com","ecdsa-sha2-nistp384-cert-v01@openssh.com","ecdsa-sha2-nistp521-cert-v01@openssh.com","ssh-ed25519-cert-v01@openssh.com","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","rsa-sha2-512","rsa-sha2-256","ssh-rsa","ssh-dss","ssh-ed25519"],"encCS":["aes128-gcm@openssh.com","chacha20-poly1305@openssh.com","aes128-ctr","aes192-ctr","aes256-ctr"],"macCS":["hmac-sha2-256-etm@openssh.com","hmac-sha2-256","hmac-sha1","hmac-sha1-96"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 4e066189c3bbeec38c99b1855113733a","sensor":"","timestamp":"2023-11-04T11:47:01.311447Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.login.success","username":"root","password":"root","message":"login attempt [root/root] succeeded","sensor":"","timestamp":"2023-11-04T11:47:02.035140Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-04T11:47:02.535541Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.input","input":"apt update && apt install curl -y","message":"CMD: apt update && apt install curl -y","sensor":"","timestamp":"2023-11-04T11:47:02.536162Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.failed","input":"apt update","message":"Command not found: apt update","sensor":"","timestamp":"2023-11-04T11:47:02.537055Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.failed","input":"apt install curl -y","message":"Command not found: apt install curl -y","sensor":"","timestamp":"2023-11-04T11:47:02.537945Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729","size":60,"shasum":"f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729","duplicate":false,"duration":0.23928594589233398,"message":"Closing TTY Log: var/lib/cowrie/tty/f16f210eb82afaec76651aa213471f4030e86a10c6fd2540f566adab4d6ff729 after 0 seconds","sensor":"","timestamp":"2023-11-04T11:47:02.774600Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-11-04T11:47:03.317590Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.command.input","input":"lscpu && echo -e \"qqr4vyjB\\nqqr4vyjB\" | passwd && curl https://ipinfo.io/org --insecure -s && apt","message":"CMD: lscpu && echo -e \"qqr4vyjB\\nqqr4vyjB\" | passwd && curl https://ipinfo.io/org --insecure -s && apt","sensor":"","timestamp":"2023-11-04T11:47:03.318159Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.file_download","url":"https://ipinfo.io/org","outfile":"var/lib/cowrie/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","shasum":"8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","sensor":"","timestamp":"2023-11-04T11:47:03.391847Z","message":"Downloaded URL (https://ipinfo.io/org) with SHA-256 8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358 to var/lib/cowrie/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438","size":2483,"shasum":"ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438","duplicate":false,"duration":0.24996399879455566,"message":"Closing TTY Log: var/lib/cowrie/tty/ac6d43999a18126f3ca14368aa47db6cb6b8a8ce42e37945783527ae62680438 after 0 seconds","sensor":"","timestamp":"2023-11-04T11:47:03.567377Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}
{"eventid":"cowrie.session.closed","duration":2.977452039718628,"message":"Connection lost after 2 seconds","sensor":"","timestamp":"2023-11-04T11:47:04.053433Z","src_ip":"165.232.188.209","session":"85a2e6c7746c"}

```

</details>

---


</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The IP addresses and ports involved in the attack are as follows:

**Attacking (source) IPs:**
- 165.232.188.209
- 104.248.26.212
- 64.227.46.76

**Honeypot (destination) IP:**
- 172.31.5.68

**Attacking (source) ports:**
- 33170
- 42470
- 42476
- 42486
- 43510
- 56306
- 56320
- 56328
- 59462
- 59474
- 54138
- 34496
- 34502
- 50172

**Honeypot (destination) port:**
- 2222

<details>
<summary>
<h3>Top 3 Source Ips</h3>
</summary>

Total Source IPs: `14`
Unique: `3`

| Source IP | Times Seen |
| --- | --- |
| `165.232.188.209` | `8` |
| `104.248.26.212` | `3` |
| `64.227.46.76` | `3` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `14`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `14` |

</details>

---


<details>
<summary>
<h3>Top 10 Source Ports</h3>
</summary>

Total Source Ports: `14`
Unique: `14`

| Source Port | Times Seen |
| --- | --- |
| `33170` | `1` |
| `42470` | `1` |
| `42476` | `1` |
| `42486` | `1` |
| `43510` | `1` |
| `56306` | `1` |
| `56320` | `1` |
| `56328` | `1` |
| `59462` | `1` |
| `59474` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `14`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2222` | `14` |

</details>

---


</details>

---


<details>
<summary>
<h1>SSH Analysis</h1>
</summary>

The SSH data obtained from the attack provides the following insights:

**SSH Handshake Hash (HASSH):**
- The unique hash value `4e066189c3bbeec38c99b1855113733a` represents a fingerprint of the SSH client's behavior during the handshake process. This can be used to identify the type of SSH client or potentially malicious software that has initiated the connection to the honeypot. Identifying the SSH Handshake Hash is useful for detecting and analyzing patterns of SSH client behavior across multiple connections and attacks.

**SSH Version:**
- The SSH client identified itself with the version string `SSH-2.0-Go`. This indicates that the client is built using the Go programming language ("Go" is often used for developing modern, cross-platform malware or tools due to its ease of use and static binary compilation features). This information can tie back to specific tools or malware families that utilize Go as their development language.

In the context of this attack, this data suggests that a specific type of SSH client, likely scripted or coded in Go, was used to target the honeypot. The uniqueness of the HASSH value and SSH version could be further investigated for links to known attack tools or malwares. The consistency of the HASSH value across different source IPs and ports implies that the attack could be coordinated using the same tool or script, regardless of the appearing source of the attack.

<details>
<summary>
<h3>Top 2 Usernames</h3>
</summary>

Total Usernames: `14`
Unique: `2`

| Username | Times Seen |
| --- | --- |
| `root` | `13` |
| `ossuser` | `1` |

</details>

---


![Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-usernames.png)
<details>
<summary>
<h3>Top 5 Passwords</h3>
</summary>

Total Passwords: `14`
Unique: `5`

| Password | Times Seen |
| --- | --- |
| `0` | `4` |
| `eve` | `4` |
| `root` | `4` |
| `Changeme_123` | `1` |
| `1` | `1` |

</details>

---


![Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-passwords.png)
<details>
<summary>
<h3>Top 5 Username/Password Pairs</h3>
</summary>

Total Username/Password Pairs: `14`
Unique: `5`

| Username/Password Pair | Times Seen |
| --- | --- |
| `('root', '0')` | `4` |
| `('root', 'eve')` | `4` |
| `('root', 'root')` | `4` |
| `('ossuser', 'Changeme_123')` | `1` |
| `('root', '1')` | `1` |

</details>

---


![Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-login_pairs.png)
<details>
<summary>
<h3>Top 1 Successful Usernames</h3>
</summary>

Total Successful Usernames: `4`
Unique: `1`

| Successful Username | Times Seen |
| --- | --- |
| `root` | `4` |

</details>

---


![Successful Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-successful_usernames.png)
<details>
<summary>
<h3>Top 2 Successful Passwords</h3>
</summary>

Total Successful Passwords: `4`
Unique: `2`

| Successful Password | Times Seen |
| --- | --- |
| `root` | `3` |
| `1` | `1` |

</details>

---


![Successful Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-successful_passwords.png)
<details>
<summary>
<h3>Top 2 Successful Username/Password Pairs</h3>
</summary>

Total Successful Username/Password Pairs: `4`
Unique: `2`

| Successful Username/Password Pair | Times Seen |
| --- | --- |
| `('root', 'root')` | `3` |
| `('root', '1')` | `1` |

</details>

---


![Successful Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-successful_login_pairs.png)
<details>
<summary>
<h3>Top 1 Ssh Versions</h3>
</summary>

Total SSH Versions: `14`
Unique: `1`

| SSH Version | Times Seen |
| --- | --- |
| `SSH-2.0-Go` | `14` |

</details>

---


![SSH Version](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-ssh_versions.png)
<details>
<summary>
<h3>Top 1 Ssh Hasshs</h3>
</summary>

Total SSH Hasshs: `14`
Unique: `1`

| SSH Hassh | Times Seen |
| --- | --- |
| `4e066189c3bbeec38c99b1855113733a` | `14` |

</details>

---


![SSH Hassh](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358/pie-ssh_hasshs.png)
</details>

---


# Commands Used
This attack used a total of `2` inputs to execute the following `2` commands:
The unique commands used in the attack serve specific purposes, which can be explained as follows:

1. `apt update && apt install curl -y`
    - This command performs an update of the package lists on the Debian-based Linux system to ensure the latest references to packages are available. It then proceeds to install `curl`, a command-line tool for transferring data with URLs, with the `-y` flag to automatically confirm the installation without user interaction. It's a common preprocessing step to ensure necessary tools for the attack are present on the system.

2. `lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd && curl https://ipinfo.io/org --insecure -s && apt`
    - This is a composite command that performs multiple actions:
        - `lscpu`: Lists CPU architecture information to the attacker, potentially to identify the type of system they have compromised.
        - `echo -e "qqr4vyjB\nqqr4vyjB" | passwd`: Changes the root password of the system to `qqr4vyjB`. It does so by echoing the password twice into the `passwd` command, simulating the standard password change prompt. This command could be used to secure unauthorized access.
        - `curl https://ipinfo.io/org --insecure -s`: Fetches organization information of the current IP address of the machine, without verifying SSL certificates (due to the `--insecure` flag). The `-s` flag makes `curl` operate in "silent" or "quiet" mode, which causes it to hide error and progress messages. This could be used to gather information about the network environment of the compromised system.
        - `&& apt`: This appears to be an incomplete command, potentially indicating that the attacker's command sequence was interrupted or that there was an error in the input.

In the context of the attack, these commands demonstrate steps taken to prepare the system by ensuring necessary tools like `curl` are installed, gathering system information with `lscpu`, changing the root password to maintain control, and acquiring network-related information about the compromised machine that might be used to further the attack or avoid detection. The use of the `&&` sequence operator indicates that the commands are intended to run one after another, only proceeding if the previous command finishes successfully.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `2` inputs on the honeypot system:

**Input 1:**
```bash
apt update && apt install curl -y
```

**Input 2:**
```bash
lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd && curl https://ipinfo.io/org --insecure -s && apt
```

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `2` commands were executed on the honeypot system:

```bash
apt update && apt install curl -y
```
0The attacker issues a **system update** command `apt update` to refresh the package indexes, followed by **installation of the `curl` utility** with `apt install curl -y`, which can be used for data transfer and might be used for downloading further tools or scripts. The `-y` flag automatically confirms the installation without prompting for user confirmation.
```bash
lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd && curl https://ipinfo.io/org --insecure -s && apt
```
1This command does multiple things:
- `lscpu` is used to **display information about the CPU architecture**, which can be useful for the attacker to understand what kind of system they are dealing with.
- `echo -e "qqr4vyjB\nqqr4vyjB" | passwd` is a likely attempt to **change the root password to `qqr4vyjB`**. The `echo` command with `-e` flag enables interpretation of the backslash escapes and `\n` inserts a newline, simulating a user typing 'qqr4vyjB' twice when prompted by `passwd` command, which is typically required for confirmation.
- `curl https://ipinfo.io/org --insecure -s` uses `curl` to fetch the organizational information for the system's public IP address, which can help in identifying the network or owner of the system. The `--insecure` option allows `curl` to proceed and operate even for server connections otherwise considered insecure and `-s` flags run `curl` in silent mode to hide progress meters and error messages, making the command stealthier.
- The command ends with `apt`, which appears to be incomplete or a typographical error as it is not followed by a command for `apt`. It could be an inadvertent key press before executing the previous commands or part of a chained command that was cut off.
</details>

---



# Malware OSINT

The analysis of the malware and IP addresses involved in the attack returned the following information:

**Malware Hash:** `8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358`
- There is currently no information returned by MalwareBazaar or ThreatFox for this specific hash. This might indicate that the malware is either newly deployed or not widely reported or registered in these databases.

**Attack Source IPs:**
- `165.232.188.209`
- `104.248.26.212`
- `64.227.46.76`
All three IP addresses yielded no specific results from ThreatFox or URLhaus. The absence of data might suggest that these IPs have not been reported or categorized as malicious in these databases, or they might be relatively new or low in the level of activity with respect to known threats.

**Malware URLs and Hosts:**
- The search for URLs and hosts within the malware file did not return any data, or they may be null. This could imply that the malware does not communicate with external servers via hardcoded URLs or hosts, or the malware may employ other means of communication that were not captured in the static attributes.

In conclusion, due to the lack of specific information on the malware hash, source IPs, and absence of URLs and hosts from the known databases, there isn't detailed OSINT data available to describe the exact nature or family of the malware used in this attack. It could either be a relatively new or underreported specimen, or the existing defenses and trackers have not yet identified and categorized it. Further dynamic analysis of the malware in a controlled environment, as well as close monitoring of the source IP addresses for any emerging patterns of malicious behavior, might be needed to fully understand the threat.

# Malware Analysis

The malware associated with the attack has the following attributes:

- **Text:** It contains the string "AS16509 Amazon.com, Inc.", which seems to be information related to an Amazon AS number.
- **SHA-256 Hash:** The malware file has the hash `8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358`.
- **Source Address:** The file was sourced from `https://ipinfo.io/org`, which suggests that the malware may be linked to data gathered from the ipinfo.io service, potentially information about the compromised system's network.
- **Destination File Name:** The destination filename where the malware was intended to be stored was not specified or captured.
- **URLs:** No URLs were found within the malware file, indicating it may not communicate with external servers via hardcoded URLs.
- **Hosts:** No IP addresses or domain names were found in the file, indicating it may not connect to specific remote hosts.
- **File Size:** The malware file is very small, only 25 bytes in size.
- **MIME Type:** The file is of type "text/plain", indicating that it is a plain text file.

Given these attributes, the "malware" in question does not appear to exhibit typical characteristics of malicious software. Instead, it appears to be a very small text file with content that references Amazon's Autonomous System (AS). This might suggest that the text file is part of exploration or reconnaissance activity, potentially used as a marker or part of a larger attack routine to identify the compromised host's affiliation with Amazon services. However, without additional text, executables, scripts, or commands, this file alone does not show conventional functionalities of malware.

It should be noted that it's possible this file is a small component or the result of a reconnaissance command rather than the malware itself, or possibly even a misleading decoy. Full clarification of this file's role in the attack context might require more extensive investigation into related attack activities and artifacts.
This attack downloaded `1` raw malware samples which can be standardized into `1` samples:

### Raw Malware Sample

<details>
<summary>
<h4>Raw Malware Sample 0/1 Sha256 HASH: 8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358</h4>
</summary>

**Standardized** Sha256 HASH: `8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358`

**Sample Below** Sha256 HASH: `8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358`
```plaintext
AS16509 Amazon.com, Inc.

```

</details>

---


### Commented Malware Sample & Explanation

<details>
<summary>
<h4>
Standardized Malware Sample 0/1 Sha256 HASH: 8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358</h4>
</summary>


```plaintext
# This string is not an executable piece of code, but appears to be a piece of text or comment.
AS16509 Amazon.com, Inc.

```

</details>

---

The provided `malware_source_code` does not contain executable source code or a script, but rather a string with the text `AS16509 Amazon.com, Inc.`. This string seems to be an Autonomous System Number (ASN) followed by a company name, and by itself, it does not have any functionality in the context of malicious activity. The commands provided, however, suggest a different picture when it comes to malicious intent. The provided commands appear to be initializing an environment and setting up for possible infection or reconnaissance:

1. `apt update && apt install curl -y` - This command updates the package lists for upgrades for packages that need upgrading, as well as new package versions, and installs `curl`, which is a tool to transfer data from or to a server using various protocols.
2. `lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd` - The `lscpu` command displays information about the CPU architecture, but its purpose here is unclear and could be just for checking the system's CPU details. The `echo` command changes the password of the root user to `qqr4vyjB` by piping it into the `passwd` command. This could be part of the attacker's efforts to secure access to the compromised system by changing the root password.
3. `curl https://ipinfo.io/org --insecure -s` - This curl command fetches information about the organization associated with the system's IP address and does it with the `--insecure` flag, which allows connections to SSL sites without certificates, and `-s` for silent mode, so it doesn't show progress or error messages. This can be used to gather information about the compromised host.
4. The final `apt` command seems incomplete and without further content, its purpose cannot be determined.

Overall, while the `malware_source_code` provided is not actual code, the commands hint at an attacker setting up a compromised system by installing necessary tools, securing access through password change, and gathering information using `curl`. It's important to note that without additional context or content, the true intent cannot be fully ascertained.

# Which vulnerability does the attack attempt to exploit?
The information provided so far does not detail specific vulnerabilities being exploited in the attack or mention any exploit names or CVE (Common Vulnerabilities and Exposures) numbers. Exploitation of vulnerabilities usually involves attacking known weaknesses in software applications, operating systems, or network protocols, typically leveraging bugs or flaws to gain unauthorized access or perform unauthorized actions.

The commands executed by the attacker show activities like updating and installing packages, changing passwords, and gathering system information. While these actions can be preparatory steps for exploitation, they do not inherently indicate the use of specific exploits or vulnerabilities.

Similarly, the malware details point to a text file that contains a reference to an Amazon AS number but does not provide evidence of an exploit being deployed or a vulnerability being targeted.

To determine the specific vulnerabilities exploited in an attack, one would need indicators such as:

- Error messages or crash reports indicative of buffer overflows, injection flaws, or other vulnerabilities being triggered.
- Specific filenames, hashes, or contents of exploit scripts, toolkits, or binaries.
- Logs or other data showing the usage of exploit code or abnormal system behavior.
- Network traffic capturing the exploit payloads or attack signatures.

If such data is available, it can be correlated with known CVEs or other vulnerability databases to identify the exploited vulnerabilities. Without this information, it is not possible to accurately state which vulnerabilities, if any, are being exploited in this attack.


# MITRE ATT&CK
The MITRE ATT&CK framework is a comprehensive matrix of tactics and techniques used by threat actors during cyber attacks. Based on the information from the commands executed and the malware file attributes, we can identify several ATT&CK techniques that may apply to this attack:

### Initial Access
- **T1133: External Remote Services** — If the attacker accessed the system over the internet via an exposed SSH service, this technique would apply.

### Execution
- **T1059: Command and Scripting Interpreter** — Running shell commands is a clear example of using the command line interface for execution.

### Persistence
- **T1098: Account Manipulation** — Changing the root password to maintain access to a compromised system is an example of account manipulation.

### Privilege Escalation
- *(No clear evidence has been shown in the provided data that indicates privilege escalation)*

### Defense Evasion
- *(No clear evidence has been shown in the provided data that indicates defense evasion techniques)*

### Credential Access
- *(No clear evidence has been shown in the provided data that indicates credentials were accessed or stolen)*

### Discovery
- **T1082: System Information Discovery** — Using the `lscpu` command to get information about the CPU suggests system information discovery.
- **T1016: System Network Configuration Discovery** — Using `curl` to fetch data from `https://ipinfo.io/org` implies an attempt to discover network configuration information.

### Lateral Movement
- *(No clear evidence has been shown in the provided data that indicates lateral movement within the network)*

### Collection
- *(No clear evidence has been shown in the provided data that indicates data was collected from the target environment)*

### Command and Control
- *(No clear evidence has been shown in the provided data that indicates a command and control channel was established)*

### Exfiltration
- *(No clear evidence has been shown in the provided data that indicates data was exfiltrated from the target system)*

### Impact
- *(No clear evidence has been shown in the provided data that indicates an attack on availability, integrity, or confidentiality)*

Based on the information provided and the typical scope of each tactic, the attack can be preliminarily classified under 'Initial Access,' 'Execution,' 'Persistence,' and 'Discovery' within the MITRE ATT&CK framework. Further details on the attacker's actions, such as evidence of successive stages of the attack or additional attack behaviors, would be needed to fully classify the attack within the MITRE ATT&CK framework.

# What Is The Goal Of The Attack?
Based on the information gathered so far, the goals of the attack could encompass the following:

1. **Gaining and Maintaining Access:** By utilizing SSH to connect to the compromised system, updating software packages, and installing `curl`, the attacker appears to be establishing and maintaining access to the system. Changing the root password is indicative of efforts to ensure persistent access.

2. **Reconnaissance:** The execution of the `lscpu` command suggests that the attacker is collecting information about the CPU architecture of the compromised system. Additionally, the use of `curl` to fetch data from `https://ipinfo.io/org` implies that the attacker is gathering information about the network environment of the compromised host.

3. **Preparation for Further Actions:** The commands run by the attacker indicate preparation for additional activities, which might include exploiting the system further, staging for lateral movement, or using the compromised host for other malicious purposes.

The specific goals beyond preparation and reconnaissance aren't entirely clear, given the limited context. However, the nature of the commands and the malware file does not point toward immediate data exfiltration, deployment of ransomware, or direct disruption. The attacker may also be goal-oriented towards building a foothold inside the network from which to launch further attacks or as a staging ground for other malicious activities.

It's possible that the attack is in an early phase, with the attacker exploring the system's capabilities and network position to lay the groundwork for future campaigns. Alternatively, this might be part of a broader botnet operation, where compromised machines are used for larger-scale activities such as distributed denial-of-service (DDoS) attacks or crypto mining operations. The real intent could be masked by the seemingly innocuous nature of the commands and the malware file content identified. Further monitoring and investigating the compromised system and malicious activity would be necessary to uncover the full intention behind the attack.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
The success of an attack often depends on a combination of factors, including the attacker's capabilities, the presence of vulnerabilities, and the effectiveness of the system's defenses. Based on the provided data:

1. **Attacker's Capabilities:** The attacker has been able to execute commands on the system, indicating a certain level of access. They have also demonstrated reconnaissance activities and attempts to maintain access by changing the root password.

2. **Presence of Vulnerabilities:** If there are additional unpatched vulnerabilities on the system, especially those that can elevate privileges or provide further system access, the attacker might exploit these to enhance their foothold or perform more damaging activities.

3. **Effectiveness of Defenses:** The effectiveness of a system's security measures, such as intrusion detection/prevention systems, firewalls, regular patching practices, and monitoring, also play a crucial role in mitigating attacks. Weak or inadequate defenses might allow an attacker to be successful.

Given the attacker's ability to run commands and potentially install tools (such as `curl`), if the system contains unmitigated vulnerabilities and inadequate defenses, the attack could progress to further stages, potentially leading to:

- **Lateral movement:** Spreading to other systems within the network.
- **Data exfiltration:** Stealing sensitive information.
- **Deployment of additional payloads:** Such as ransomware, crypto miners, or establishing command and control (C2) infrastructure.
  
At this stage, we do not have evidence of specific vulnerabilities being targeted or exploited. However, if the system is improperly secured or unmaintained (running outdated or vulnerable software), the observed activities can lead to more serious security breaches, and the attack is more likely to be successful. 

An in-depth security analysis, including vulnerability assessments and security audits, would be required to accurately gauge the system's susceptibility to further successful attacks.

# How Can A System Be Protected From This Attack?
To protect a system from this type of attack, several proactive security measures should be implemented. Here is a set of recommended actions:

### Network Security
1. **Restrict Remote Access:** Limit SSH access to known IP addresses and networks using firewalls.
2. **Use Strong Authentication Mechanisms:** Implement strong password policies and preferably use multi-factor authentication (MFA) for remote access.
3. **Regularly Update and Patch Systems:** Keep the operating system and all software up-to-date with the latest security patches to mitigate known vulnerabilities.

### Host Security
1. **Use Account Management Practices:** Implement least-privilege principles and carefully manage user accounts and permissions.
2. **Change Default Credentials:** Always change default usernames and passwords to custom, strong credentials.
3. **Monitor and Control the Use of Privileged Accounts:** Be particularly vigilant with root or admin accounts.

### System Monitoring and Incident Response
1. **Implement Intrusion Detection/Prevention Systems (IDS/IPS):** Use these systems to monitor network traffic for suspicious activity.
2. **Enable Comprehensive Logging:** Collect and monitor system logs to detect and investigate suspicious activities.
3. **Regular Security Audits:** Review system configurations and security measures to identify and address potential weaknesses.

### Endpoint Protection
1. **Deploy Antivirus and Anti-Malware Solutions:** Ensure all systems are protected with updated antivirus software to detect and prevent malware infections.
2. **Application Whitelisting:** Use application whitelisting to prevent unauthorized programs from executing.

### Security Awareness and Training
1. **User Education:** Provide users with training on security best practices, such as recognizing phishing attempts and safe web browsing.
2. **Security Policies:** Implement clear and effective security policies and ensure that all staff are aware of their roles in maintaining security.

### Response Strategy
1. **Have an Incident Response Plan:** Prepare a plan with clear procedures for responding to incidents, including how to isolate affected systems and communicate with relevant stakeholders.

### System Hardening
1. **Regularly Scan and Assess for Vulnerabilities:** Periodic vulnerability scanning can help identify weak points that could be exploited.
2. **Remove Unnecessary Services:** Disable any services and applications that are not essential to reduce potential attack surfaces.
3. **Implement File Integrity Monitoring:** Track changes to critical system files and configuration files.

By integrating a layered approach that includes robust policies, procedures, technical solutions, and user education, a system can be well-protected against many common forms of cyberattacks.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
Indicators of Compromise (IOCs) are forensic data found in system logs, files, or observed network traffic that indicate potentially malicious activity on a system or network. Based on the information provided about the attack, the following could be considered IOCs:

1. **Source IP Addresses:** The IP addresses that initiated the attack can be used as network-based IOCs:
   - `165.232.188.209`
   - `104.248.26.212`
   - `64.227.46.76`

2. **SSH Port and Service Usage:** Specifically, the use of non-standard SSH port `2222` and SSH version string `SSH-2.0-Go` can be a sign of a non-standard configuration, which might be indicative of malicious use.

3. **Changed Credentials:** Changing the root user's password, as indicated by the `passwd` command with an echoed password, can serve as a behavioral IOC.

4. **Commands Run:** The specific commands that were run by the attacker:
   - `apt update && apt install curl -y`
   - `lscpu && echo -e "qqr4vyjB\nqqr4vyjB" | passwd`
   - Any other unusual or unauthorized commands that were executed on the system.

5. **Network Requests:** Requests to `https://ipinfo.io/org` or similar informational services from a server environment, which aren't typically made in such contexts, can be seen as IOCs.

6. **Malware Hash:** The SHA256 hash of the malware file:
   - `8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358`

7. **Unexpected System Changes:** Unusual system changes that were not made by authorized personnel or processes, possibly identified through file integrity monitoring systems.

8. **Destfile (file downloaded/saved on the system):** If the destination file that malware was saved as on the honeypot is identified later, its path and filename can serve as an IOC.

9. **Network Traffic:** Outbound network connections to unexpected or untrusted external addresses, especially if they involved data transmission, could be an indicator of exfiltration or command-and-control communication.

These IOCs can be used in forensic analysis, threat hunting, and intrusion detection systems to identify similar attack patterns, verify if a breach has occurred, or monitor for further suspicious activities. It is important to continually update and refine IOCs as attackers evolve their tactics and as new information about their techniques becomes available.

# What do you know about the attacker?
The critical findings from the OSINT sources about the IP addresses involved in the attack are as follows:

### Geolocation and Network Details:
- All attacking IP addresses (`165.232.188.209`, `104.248.26.212`, `64.227.46.76`) are associated with DigitalOcean, a popular cloud services provider, indicating that the attackers may be using cloud-based infrastructure.
- The IP addresses are geographically distributed across Bengaluru, India; Frankfurt, Germany; and Slough, United Kingdom.

### Reported Activities and Risks:
- Each IP address has been reported for malicious activities, including scanning and brute force attacks, particularly over SSH.
- Multiple reports from different sources such as AbuseIPDB, DShield, ISC, and blocklists indicate that these IPs have a significant history of abuse, implying a high risk associated with them.
- The IPs are listed on various blocklists and have been flagged for malicious/attacker activity and bot abuse.

### Service Information and Open Ports:
- Shodan revealed open services on these IPs, such as Apache web servers and SSH services, suggesting that they host active services which could facilitate the attack.
- Specific services identified include Apache httpd 2.4.52 and Nginx web servers, and OpenSSH 8.9p1, indicating potentially vulnerable services that hackers could exploit.

### Involvement in Previous Reports:
- The IP addresses have targeted multiple honeypots according to ISC data, with hundreds of reports indicating patterns of attacking behavior.
- The IPs have been marked in multiple threat feeds indicating a widespread recognition of their malicious use.
- CyberGordon and ISC records signify that these IPs have been actively involved in cyber threats and have been categorized as high-risk entities by various threat intelligence sources.

### Malware Information:
- There was a malware hash associated with the attack, but no specific information about this malware was obtained from MalwareBazaar or ThreatFox. This could point to novel malware or a low reporting volume for this specimen.
- No definitive malware family or behavior could be linked from the provided hash, indicating a potential gap that requires further analysis.

### Lack of Specific ThreatFox Data:
- No specific information was returned by ThreatFox for the attacking IPs, suggesting that they may not have been reported or linked to known malware incidents within this particular database.

Overall, the OSINT sources used to gather information about the attacking IPs and malware reveal that the attack originated from a cloud-hosted environment with a history of associated malicious activities. The consistent reporting across various intelligence platforms underscores the reputation of these IPs as high-risk entities in the cybersecurity landscape. Further investigation, including dynamic analysis of the malware, would be necessary for a comprehensive understanding of the threat posed by these IPs and the nature of the attack.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
Based on the data from Cybergordon, Shodan, and ISC, here's a summary of what is known about the locations of the IP addresses involved in the attack:

### IP Address: 165.232.188.209
- **Location:** Bengaluru, Karnataka, India.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** Malicious and scanning, involved in brute force and bot activity.
- **Blocklists:** Included on multiple blocklists, indicating a history of malicious activities.
- **Open Services:** SSH (port 22), HTTP (port 80), and HTTPS (port 443) on Apache httpd 2.4.52.
  
### IP Address: 104.248.26.212
- **Location:** Frankfurt am Main, Hessen, Germany.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** Malicious behavior and scanning activities.
- **Blocklists:** Found on several blocklists related to brute force and SSH attacks.
- **Open Services:** SSH service identified (OpenSSH 8.9p1).

### IP Address: 64.227.46.76
- **Location:** Slough, England, United Kingdom.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** Identified as conducting malicious activities including SSH brute force attacks.
- **Blocklists:** Featured on a blocklist, signifying malicious behavior.
- **Open Services:** HTTPS service identified (Nginx).

Overall, all these IP addresses have been associated with malicious activities and reported by various sources. They all are within the DigitalOcean network and have been listed as involving SSH brute force attacks, bot activity, and other abuse. Such IPs are often part of a broader network of compromised machines or virtual private servers (VPS) that are utilized for cyberattacks, often without the knowledge of the legitimate owner of the IP space.

* This attack involved `3` unique IP addresses. `3` were source IPs.`0` unique IPs and `0` unique URLS were found in the commands.`0` unique IPs and `0` unique URLS were found in malware.
* The most common **Country** of origin was `India`, which was seen `1` times.
* The most common **City** of origin was `Doddaballapura`, which was seen `1` times.
* The most common **ISP** of origin was `DigitalOcean, LLC`, which was seen `3` times.
* The most common **Organization** of origin was `DigitalOcean, LLC`, which was seen `3` times.
* The most common **ASN** of origin was `AS14061`, which was seen `3` times.
* The most common **network** of origin was `165.232.176.0/20`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 165.232.188.209 | India | Doddaballapura | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 | 165.232.176.0/20 |
| 104.248.26.212 | Germany | Frankfurt am Main | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 | 104.248.16.0/20 |
| 64.227.46.76 | United Kingdom | London | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 | 64.227.32.0/20 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
Based on the CyberGordon data, here is a summary of what is known about the IP addresses involved in the attack:

### IP Address: 165.232.188.209
- **Location:** Bengaluru, Karnataka, India.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** Scanning and malicious activities reported in the last 3 months.
- **Security Risks:** Malicious/attacker activity, abuse/bot activity.
- **Blocklists:** Included on multiple blocklists such as Bruteforce Blocker, Emerging Threats, and others.
- **Reports:**
  - AbuseIPDB and other sources indicate a high risk rating and involvement in a significant number of abuse reports.
  - Found in various threat lists, including those concerning SSH brute force.
  - Identified in a number of threat feeds and open service lists for SSH.

### IP Address: 104.248.26.212
- **Location:** Frankfurt am Main, Hessen, Germany.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** Malicious and scanning activities reported within the last 3 months.
- **Security Risks:** Similar to the first IP, it has been ascribed malicious activities and is present on several blocklists.
- **Reports:**
  - Extensively reported for malicious activities in AbuseIPDB.
  - Registered in threat lists related to SSH brute force and noted in feed lists.
  - Found in sources that track malware and botnet scanning activities.

### IP Address: 64.227.46.76
- **Location:** Slough, England, United Kingdom.
- **Network Provider:** DigitalOcean LLC.
- **Reported Activities:** This IP has also been reported as malicious, particularly in the last 3 months.
- **Security Risks:** Engages in malicious/attacker behavior and abuse/bot activity.
- **Blocklists:** Noted on a blocklist by Charles Haley.
- **Reports:**
  - AbuseIPDB lists this IP with a high risk, based on many reports.
  - Listed in threat and feed lists mainly related to SSH brute force activities.

The CyberGordon data reveals that all three IPs have been consistently reported as participating in malicious activities, including scanning the internet and engaging in attacker behavior. They have also been flagged on various threat and block lists due to their reported activities. It is evident that these IPs have a widespread reputation for involvement in cyber threats, particularly associated with the DigitalOcean network and widely distributed geographically.

* `34` total alerts were found across all engines.
* `12` were **high** priority. 
* `13` were **medium** priority. 
* `9` were **low** priority. 
* The IP address with the **most high priority alerts** was `165.232.188.209` with `4` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E19] ThreatMiner | [E23] Offline Feeds | [E24] BlackList DE | [E26] MetaDefender | [E33] GreyNoise | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 165.232.188.209 | `4` \| `5` \| `3` | <details>`Geo: Doddaballapura, Karnataka, IN. Network: AS14061 DigitalOcean, LLC. `<summary>`low`</summary></details> | <details>` ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1760 report(s) by 683 user(s), last on 23 November 2023  `<summary>`high`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 816 report(s) listing 227 target(s), last on 5 Nov 2023 `<summary>`high`</summary></details> | <details>`Found in 18 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 27 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Brute Force Blocker, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH. `<summary>`medium`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | <details>`Found in FireHOL Level 3 (last 30 days), EmergingThreats - Compromised hosts, IPsum (3+ blocklists) `<summary>`medium`</summary></details> | <details>`Found in 254 attack(s) and 3 report(s) `<summary>`medium`</summary></details> | <details>`Found in 2 sources: emergingthreats.net (malware), danger.rulez.sk (bruteforce, scanner) `<summary>`medium`</summary></details> | <details>`Last report on 05 November 2023 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Bengaluru, Karnataka, India. Network: AS14061, Digitalocean LLC, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Bruteforce Blocker, Charles Haley, Emerging Threats, James Brine, Scriptz Team. `<summary>`high`</summary></details> |
| 104.248.26.212 | `4` \| `5` \| `3` | <details>`Geo: Frankfurt am Main, Hesse, DE. Network: AS14061 DigitalOcean, LLC. `<summary>`low`</summary></details> | <details>` ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1370 report(s) by 643 user(s), last on 23 November 2023  `<summary>`high`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 470 report(s) listing 126 target(s), last on 5 Nov 2023 `<summary>`high`</summary></details> | <details>`Found in 14 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 27 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Brute Force Blocker, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH. `<summary>`medium`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | <details>`Found in FireHOL Level 3 (last 30 days), EmergingThreats - Compromised hosts, IPsum (3+ blocklists) `<summary>`medium`</summary></details> | <details>`Found in 175 attack(s) and 3 report(s) `<summary>`medium`</summary></details> | <details>`Found in 2 sources: emergingthreats.net (malware), danger.rulez.sk (bruteforce, scanner) `<summary>`medium`</summary></details> | <details>`Last report on 05 November 2023 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Frankfurt am Main, Hessen, Germany. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Bruteforce Blocker, Charles Haley, Emerging Threats, James Brine, Scriptz Team. `<summary>`high`</summary></details> |
| 64.227.46.76 | `4` \| `3` \| `3` | <details>`Geo: London, England, GB. Network: AS14061 DigitalOcean, LLC. `<summary>`low`</summary></details> | <details>` ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 340 report(s) by 248 user(s), last on 23 November 2023  `<summary>`high`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 87 report(s) listing 40 target(s), last on 27 Nov 2023 `<summary>`high`</summary></details> | <details>`Found in 3 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 25 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks. Opened service(s): SSH. `<summary>`medium`</summary></details> | <details>`Engine request error,Engine request error,Engine request error `<summary>`low`</summary></details> | None | <details>`Found in 52 attack(s) and 1 report(s) `<summary>`medium`</summary></details> | None | <details>`Last report on 07 November 2023 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Slough, England, United Kingdom. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 165.232.188.209</h3>
</summary>


### Cybergordon results for: 165.232.188.209 [https://cybergordon.com/r/38ee6b18-4312-4e98-951a-05c01752134b](https://cybergordon.com/r/38ee6b18-4312-4e98-951a-05c01752134b)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 05 November 2023 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/165.232.188.209 |
| [E34] IPdata.co | Geo: Bengaluru, Karnataka, India. Network: AS14061, Digitalocean LLC, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Bruteforce Blocker, Charles Haley, Emerging Threats, James Brine, Scriptz Team.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1760 report(s) by 683 user(s), last on 23 November 2023   | https://www.abuseipdb.com/check/165.232.188.209 |
| [E11] DShield/ISC | Found in 816 report(s) listing 227 target(s), last on 5 Nov 2023  | https://isc.sans.edu/ipinfo.html?ip=165.232.188.209 |
| [E26] MetaDefender | Found in 2 sources: emergingthreats.net (malware), danger.rulez.sk (bruteforce, scanner)  | https://metadefender.opswat.com |
| [E17] Pulsedive | Risk: low. Last seen on 27 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Brute Force Blocker, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E24] BlackList DE | Found in 254 attack(s) and 3 report(s)  | https://www.blocklist.de/en/search.html?ip=165.232.188.209 |
| [E12] AlienVault OTX | Found in 18 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/165.232.188.209 |
| [E23] Offline Feeds | Found in FireHOL Level 3 (last 30 days), EmergingThreats - Compromised hosts, IPsum (3+ blocklists)  | / |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=209.188.232.165.in-addr.arpa&type=PTR |
| [E1] IPinfo | Geo: Doddaballapura, Karnataka, IN. Network: AS14061 DigitalOcean, LLC.  | https://ipinfo.io/165.232.188.209 |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=165.232.188.209 |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 104.248.26.212</h3>
</summary>


### Cybergordon results for: 104.248.26.212 [https://cybergordon.com/r/4cd1a43e-2896-42d9-8e92-94708fb160e6](https://cybergordon.com/r/4cd1a43e-2896-42d9-8e92-94708fb160e6)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 05 November 2023 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/104.248.26.212 |
| [E34] IPdata.co | Geo: Frankfurt am Main, Hessen, Germany. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Bruteforce Blocker, Charles Haley, Emerging Threats, James Brine, Scriptz Team.  | https://ipdata.co |
| [E11] DShield/ISC | Found in 470 report(s) listing 126 target(s), last on 5 Nov 2023  | https://isc.sans.edu/ipinfo.html?ip=104.248.26.212 |
| [E2] AbuseIPDB |  ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 1370 report(s) by 643 user(s), last on 23 November 2023   | https://www.abuseipdb.com/check/104.248.26.212 |
| [E17] Pulsedive | Risk: low. Last seen on 27 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Brute Force Blocker, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E26] MetaDefender | Found in 2 sources: emergingthreats.net (malware), danger.rulez.sk (bruteforce, scanner)  | https://metadefender.opswat.com |
| [E24] BlackList DE | Found in 175 attack(s) and 3 report(s)  | https://www.blocklist.de/en/search.html?ip=104.248.26.212 |
| [E12] AlienVault OTX | Found in 14 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/104.248.26.212 |
| [E23] Offline Feeds | Found in FireHOL Level 3 (last 30 days), EmergingThreats - Compromised hosts, IPsum (3+ blocklists)  | / |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=212.26.248.104.in-addr.arpa&type=PTR |
| [E1] IPinfo | Geo: Frankfurt am Main, Hesse, DE. Network: AS14061 DigitalOcean, LLC.  | https://ipinfo.io/104.248.26.212 |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=104.248.26.212 |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 64.227.46.76</h3>
</summary>


### Cybergordon results for: 64.227.46.76 [https://cybergordon.com/r/c64ee7f3-9d35-4694-b823-7b7cfd8f2b3e](https://cybergordon.com/r/c64ee7f3-9d35-4694-b823-7b7cfd8f2b3e)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 07 November 2023 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/64.227.46.76 |
| [E34] IPdata.co | Geo: Slough, England, United Kingdom. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 340 report(s) by 248 user(s), last on 23 November 2023   | https://www.abuseipdb.com/check/64.227.46.76 |
| [E11] DShield/ISC | Found in 87 report(s) listing 40 target(s), last on 27 Nov 2023  | https://isc.sans.edu/ipinfo.html?ip=64.227.46.76 |
| [E17] Pulsedive | Risk: low. Last seen on 25 Nov 2023. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E24] BlackList DE | Found in 52 attack(s) and 1 report(s)  | https://www.blocklist.de/en/search.html?ip=64.227.46.76 |
| [E12] AlienVault OTX | Found in 3 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/64.227.46.76 |
| [E1] IPinfo | Geo: London, England, GB. Network: AS14061 DigitalOcean, LLC.  | https://ipinfo.io/64.227.46.76 |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=76.46.227.64.in-addr.arpa&type=PTR |
| [E19] ThreatMiner | Engine request error,Engine request error,Engine request error  | https://www.threatminer.org/host.php?q=64.227.46.76 |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
Based on Shodan data, here is the summary for each IP address involved in the attack:

### IP Address: 165.232.188.209
- **Cloud Provider:** DigitalOcean
- **Cloud Region:** Karnataka, India (in-ka)
- **Country:** India
- **City:** Doddaballapura
- **Organization:** DigitalOcean, LLC
- **ISP:** DigitalOcean, LLC
- **ASN:** AS14061
- **Hostnames:** admin.spacesbyblank.com
- **Domains:** spacesbyblank.com
- **Open Services:**
  - **Port 80 (HTTP):** Running Apache httpd 2.4.52
  - **Port 443 (HTTPS):** Running Apache httpd 2.4.52

### IP Address: 104.248.26.212
- **Cloud Provider:** DigitalOcean
- **Cloud Region:** Hessen, Germany (de-he)
- **Country:** Germany
- **City:** Frankfurt am Main
- **Organization:** DigitalOcean, LLC
- **ISP:** DigitalOcean, LLC
- **ASN:** AS14061
- **Open Services:**
  - **Port 22 (SSH):** Running OpenSSH 8.9p1 Ubuntu-3ubuntu0.4

### IP Address: 64.227.46.76
- **Cloud Provider:** DigitalOcean
- **Cloud Region:** England, United Kingdom (gb-slg)
- **Country:** United Kingdom
- **City:** London
- **Organization:** DigitalOcean, LLC
- **ISP:** DigitalOcean, LLC
- **ASN:** AS14061
- **Hostnames:** uksan54.hudu.app
- **Domains:** hudu.app
- **Open Services:**
  - **Port 443 (HTTPS):** Running Nginx

Shodan data indicates that all the attacking IPs are associated with DigitalOcean, suggesting they may be from cloud-hosted virtual servers. The presence of open web servers (Apache and Nginx) and SSH services on these IPs indicates they are hosting active services, which could potentially be leveraged in the attack campaign. The geographical locations cover India, Germany, and the United Kingdom, reflective of the global distribution of cloud infrastructure.

- The most common **open port** was `443`, which was seen `2` times.
- The most common **protocol** was `tcp`, which was seen `4` times.
- The most common **service name** was `Apache httpd2.4.52`, which was seen `2` times.
- The most common **service signature** was `HTTP/1.1 200 OK`, which was seen `2` times.
- The most common **Hostnames** was `admin.spacesbyblank.com`, which was seen `1` times.
- The most common **Domains** was `spacesbyblank.com`, which was seen `1` times.
- The most common **Cloud Provider** was `DigitalOcean`, which was seen `3` times.
- The most common **Cloud Region** was `in-ka`, which was seen `1` times.
- The most common **Country** was `India`, which was seen `1` times.
- The most common **City** was `Doddaballapura`, which was seen `1` times.
- The most common **Organization** was `DigitalOcean, LLC`, which was seen `3` times.
- The most common **ISP** was `DigitalOcean, LLC`, which was seen `3` times.
- The most common **ASN** was `AS14061`, which was seen `3` times.
- The IP address with the **most open ports** was `165.232.188.209` with `2` open ports.

| IP Addresss | # Open Ports | 22 | 80 | 443 |
| --- | --- | --- | --- | --- |
| 165.232.188.209 | <details>`80`, `443`<summary>`2`</summary></details> | - | Apache httpd2.4.52 | Apache httpd2.4.52 |
| 104.248.26.212 | <details>`22`<summary>`1`</summary></details> | OpenSSH8.9p1 Ubuntu-3ubuntu0.4 | - | - |
| 64.227.46.76 | <details>`443`<summary>`1`</summary></details> | - | - | nginx |

<details>
<summary>
<h4>Top 3 Open Ports</h4>
</summary>

Total Open Ports: `4`
Unique: `3`

| Open Port | Times Seen |
| --- | --- |
| `443` | `2` |
| `80` | `1` |
| `22` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `4`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `tcp` | `4` |

</details>

---




<details>
<summary>
<h4>Top 3 Service Names</h4>
</summary>

Total Service Names: `4`
Unique: `3`

| Service Name | Times Seen |
| --- | --- |
| `Apache httpd2.4.52` | `2` |
| `OpenSSH8.9p1 Ubuntu-3ubuntu0.4` | `1` |
| `nginx` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Service Signatures</h4>
</summary>

Total Service Signatures: `4`
Unique: `3`

| Service Signature | Times Seen |
| --- | --- |
| `HTTP/1.1 200 OK` | `2` |
| `HTTP/1.1 301 Moved Permanently` | `1` |
| `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Hostnames</h4>
</summary>

Total Hostnamess: `2`
Unique: `2`

| Hostnames | Times Seen |
| --- | --- |
| `admin.spacesbyblank.com` | `1` |
| `uksan54.hudu.app` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Domains</h4>
</summary>

Total Domainss: `2`
Unique: `2`

| Domains | Times Seen |
| --- | --- |
| `spacesbyblank.com` | `1` |
| `hudu.app` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Cloud Providers</h4>
</summary>

Total Cloud Providers: `3`
Unique: `1`

| Cloud Provider | Times Seen |
| --- | --- |
| `DigitalOcean` | `3` |

</details>

---




<details>
<summary>
<h4>Top 3 Cloud Regions</h4>
</summary>

Total Cloud Regions: `3`
Unique: `3`

| Cloud Region | Times Seen |
| --- | --- |
| `in-ka` | `1` |
| `de-he` | `1` |
| `gb-slg` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Countrys</h4>
</summary>

Total Countrys: `3`
Unique: `3`

| Country | Times Seen |
| --- | --- |
| `India` | `1` |
| `Germany` | `1` |
| `United Kingdom` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Citys</h4>
</summary>

Total Citys: `3`
Unique: `3`

| City | Times Seen |
| --- | --- |
| `Doddaballapura` | `1` |
| `Frankfurt am Main` | `1` |
| `London` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Organizations</h4>
</summary>

Total Organizations: `3`
Unique: `1`

| Organization | Times Seen |
| --- | --- |
| `DigitalOcean, LLC` | `3` |

</details>

---




<details>
<summary>
<h4>Top 1 ISPs</h4>
</summary>

Total ISPs: `3`
Unique: `1`

| ISP | Times Seen |
| --- | --- |
| `DigitalOcean, LLC` | `3` |

</details>

---




<details>
<summary>
<h4>Top 1 ASNs</h4>
</summary>

Total ASNs: `3`
Unique: `1`

| ASN | Times Seen |
| --- | --- |
| `AS14061` | `3` |

</details>

---


### Shodan Results

<details>
<summary>
<h3>Shodan results for: 165.232.188.209</h3>
</summary>


### Shodan results for: 165.232.188.209 [https://www.shodan.io/host/165.232.188.209](https://www.shodan.io/host/165.232.188.209)

| Hostnames | Domains | Cloud Provider | Cloud Region | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| admin.spacesbyblank.com | spacesbyblank.com | DigitalOcean | in-ka | India | Doddaballapura | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 80 | tcp | Apache httpd2.4.52 | 2023-11-28T12:46:46.789344 |
| 443 | tcp | Apache httpd2.4.52 | 2023-11-28T12:46:51.719410 |

#### Port 80 (tcp): Apache httpd2.4.52

<details>
<summary>
<h4>Raw Service Data for Port 80 (tcp): Apache httpd2.4.52</h4>
</summary>


```
HTTP/1.1 301 Moved Permanently
Date: Tue, 28 Nov 2023 12:46:46 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: https://admin.spacesbyblank.com/
Content-Length: 329
Content-Type: text/html; charset=iso-8859-1
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 301 Moved Permanently |
| Date | Tue, 28 Nov 2023 12:46:46 GMT |
| Server | Apache/2.4.52 (Ubuntu) |
| Location | https://admin.spacesbyblank.com/ |
| Content-Length | 329 |
| Content-Type | text/html; charset=iso-8859-1 |

#### Port 443 (tcp): Apache httpd2.4.52

<details>
<summary>
<h4>Raw Service Data for Port 443 (tcp): Apache httpd2.4.52</h4>
</summary>


```
HTTP/1.1 200 OK
Date: Tue, 28 Nov 2023 12:46:51 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/; secure
X-Frame-Options: SAMEORIGIN
Set-Cookie: wordpress_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/wp-admin
Set-Cookie: wordpress_sec_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/wp-admin
Set-Cookie: wordpress_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/wp-content/plugins
Set-Cookie: wordpress_sec_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/wp-content/plugins
Set-Cookie: wordpress_logged_in_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpress_logged_in_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wp-settings-0=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wp-settings-time-0=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpress_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpress_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpress_sec_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpress_sec_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpressuser_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpresspass_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpressuser_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wordpresspass_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Set-Cookie: wp-postpass_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/
Vary: Accept-Encoding
Content-Length: 5434
Content-Type: text/html; charset=UTF-8
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 200 OK |
| Date | Tue, 28 Nov 2023 12:46:51 GMT |
| Server | Apache/2.4.52 (Ubuntu) |
| Expires | Wed, 11 Jan 1984 05:00:00 GMT |
| Cache-Control | no-cache, must-revalidate, max-age=0 |
| Set-Cookie | wp-postpass_55c292ae5818ca75254c29d76512e8bc=%20; expires=Mon, 28-Nov-2022 12:46:51 GMT; Max-Age=0; path=/ |
| X-Frame-Options | SAMEORIGIN |
| Vary | Accept-Encoding |
| Content-Length | 5434 |
| Content-Type | text/html; charset=UTF-8 |

</details>

---


<details>
<summary>
<h3>Shodan results for: 104.248.26.212</h3>
</summary>


### Shodan results for: 104.248.26.212 [https://www.shodan.io/host/104.248.26.212](https://www.shodan.io/host/104.248.26.212)

| Cloud Provider | Cloud Region | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- |
| DigitalOcean | de-he | Germany | Frankfurt am Main | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH8.9p1 Ubuntu-3ubuntu0.4 | 2023-11-08T04:37:58.009277 |

#### Port 22 (tcp): OpenSSH8.9p1 Ubuntu-3ubuntu0.4

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH8.9p1 Ubuntu-3ubuntu0.4</h4>
</summary>


```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
Key type: ecdsa-sha2-nistp256
Key: AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC9CDyaNpsrQmzv5vv5ILzDm
p1aL/9H2Gqnx7ZT+mBi5xkKBBkFR3k7jyAKRq2PuevpJSfjo3t2gSsq4qQ+2sCc=
Fingerprint: 33:9e:e5:78:12:13:05:09:42:84:5d:c5:4c:59:a7:76

Kex Algorithms:
	curve25519-sha256
	curve25519-sha256@libssh.org
	ecdh-sha2-nistp256
	ecdh-sha2-nistp384
	ecdh-sha2-nistp521
	sntrup761x25519-sha512@openssh.com
	diffie-hellman-group-exchange-sha256
	diffie-hellman-group16-sha512
	diffie-hellman-group18-sha512
	diffie-hellman-group14-sha256

Server Host Key Algorithms:
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
| sig | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4 |
| Key type | ecdsa-sha2-nistp256 |
| Key | AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC9CDyaNpsrQmzv5vv5ILzDmp1aL/9H2Gqnx7ZT+mBi5xkKBBkFR3k7jyAKRq2PuevpJSfjo3t2gSsq4qQ+2sCc= |
| Fingerprint | 33:9e:e5:78:12:13:05:09:42:84:5d:c5:4c:59:a7:76 |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'sntrup761x25519-sha512@openssh.com', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256'] |
| Server Host Key Algorithms | ['rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

</details>

---


<details>
<summary>
<h3>Shodan results for: 64.227.46.76</h3>
</summary>


### Shodan results for: 64.227.46.76 [https://www.shodan.io/host/64.227.46.76](https://www.shodan.io/host/64.227.46.76)

| Hostnames | Domains | Cloud Provider | Cloud Region | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| uksan54.hudu.app | hudu.app | DigitalOcean | gb-slg | United Kingdom | London | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 443 | tcp | nginx | 2023-11-08T23:41:44.902431 |

#### Port 443 (tcp): nginx

<details>
<summary>
<h4>Raw Service Data for Port 443 (tcp): nginx</h4>
</summary>


```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 08 Nov 2023 23:41:43 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store
Pragma: no-cache
Expires: Mon, 01 Jan 1990 00:00:00 GMT
Link: </app_assets/application-9c35bbeb37831be34938ceb321ff98b0a8b9ae93353a8db6a6cfe6290be984d5.css>; rel=preload; as=style; nopush,</app_assets/application-241723b695a6d3be0a717f5a468b6e9510f321d1764e1b6b68c80e3d24017848.js>; rel=preload; as=script; nopush
ETag: W/"b53731dec8017caa51927179b7c49678"
Content-Security-Policy: default-src 'self' https: http:; font-src 'self' https: data:; object-src 'self' https: http:; form-action 'self' https: http:; img-src 'self' http: https: blob: data:; child-src 'self' blob: https: https://www.youtube.com https://player.vimeo.com https://fast.wistia.net; frame-src 'unsafe-eval' 'unsafe-inline' https: http: https://js.stripe.com https://hooks.stripe.com; script-src 'self' 'unsafe-inline' blob: 'unsafe-eval' https: http: ajax.cloudflare.com https://canny.io/sdk.js https://api.duosecurity.com; style-src 'self' https: 'unsafe-inline' blob:; connect-src 'self' https: http: data: http://localhost:3035 ws://localhost:3035
Set-Cookie: _hudu_session=ofGpYYFFTkctHRC3aTHklp8r8EbZW6jDk3MOKJr%2ByvzqYFXfm%2B%2BfmKHWkp3t3BgUedlHfV4fnrq9kMuzFnzbULCy1HhjCBtRbNbcI6DQ61k4aFVcXqzf2DnwserLUAAriCr1fh5lAzcGAAaXFtpAzUupsRqddHjKY2bGIg1PbQ9R4oVCHZYV3%2BDgbKZEX2XvLZ8K4ARI%2F%2BqKWzWPJTSScIFn%2BtLcguRbjB0WjSbnbIsorUYcwxCm8A%2BlxI4WYWLqyzVTLO60yPYJr%2FsQfpjp0sFDibci--z%2FRuETrcgFFExtP2--Cw6t6dLuJtjfJyV8ejjlaQ%3D%3D; path=/; secure; HttpOnly; SameSite=Lax
X-Request-Id: 582805d2-d518-4cc8-a583-e69caf80a5d1
X-Runtime: 0.178728
Strict-Transport-Security: max-age=31556952; includeSubDomains; preload
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 200 OK |
| Server | nginx |
| Date | Wed, 08 Nov 2023 23:41:43 GMT |
| Content-Type | text/html; charset=utf-8 |
| Transfer-Encoding | chunked |
| Connection | keep-alive |
| X-Frame-Options | SAMEORIGIN |
| X-XSS-Protection | 1; mode=block |
| X-Content-Type-Options | nosniff |
| X-Download-Options | noopen |
| X-Permitted-Cross-Domain-Policies | none |
| Referrer-Policy | strict-origin-when-cross-origin |
| Cache-Control | no-store |
| Pragma | no-cache |
| Expires | Mon, 01 Jan 1990 00:00:00 GMT |
| Link | </app_assets/application-9c35bbeb37831be34938ceb321ff98b0a8b9ae93353a8db6a6cfe6290be984d5.css>; rel=preload; as=style; nopush,</app_assets/application-241723b695a6d3be0a717f5a468b6e9510f321d1764e1b6b68c80e3d24017848.js>; rel=preload; as=script; nopush |
| ETag | W/"b53731dec8017caa51927179b7c49678" |
| Content-Security-Policy | default-src 'self' https: http:; font-src 'self' https: data:; object-src 'self' https: http:; form-action 'self' https: http:; img-src 'self' http: https: blob: data:; child-src 'self' blob: https: https://www.youtube.com https://player.vimeo.com https://fast.wistia.net; frame-src 'unsafe-eval' 'unsafe-inline' https: http: https://js.stripe.com https://hooks.stripe.com; script-src 'self' 'unsafe-inline' blob: 'unsafe-eval' https: http: ajax.cloudflare.com https://canny.io/sdk.js https://api.duosecurity.com; style-src 'self' https: 'unsafe-inline' blob:; connect-src 'self' https: http: data: http://localhost:3035 ws://localhost:3035 |
| Set-Cookie | _hudu_session=ofGpYYFFTkctHRC3aTHklp8r8EbZW6jDk3MOKJr%2ByvzqYFXfm%2B%2BfmKHWkp3t3BgUedlHfV4fnrq9kMuzFnzbULCy1HhjCBtRbNbcI6DQ61k4aFVcXqzf2DnwserLUAAriCr1fh5lAzcGAAaXFtpAzUupsRqddHjKY2bGIg1PbQ9R4oVCHZYV3%2BDgbKZEX2XvLZ8K4ARI%2F%2BqKWzWPJTSScIFn%2BtLcguRbjB0WjSbnbIsorUYcwxCm8A%2BlxI4WYWLqyzVTLO60yPYJr%2FsQfpjp0sFDibci--z%2FRuETrcgFFExtP2--Cw6t6dLuJtjfJyV8ejjlaQ%3D%3D; path=/; secure; HttpOnly; SameSite=Lax |
| X-Request-Id | 582805d2-d518-4cc8-a583-e69caf80a5d1 |
| X-Runtime | 0.178728 |
| Strict-Transport-Security | max-age=31556952; includeSubDomains; preload |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
Unfortunately, the data from ThreatFox did not yield specific results for the IP addresses (`165.232.188.209`, `104.248.26.212`, `64.227.46.76`) involved in the attack. The lack of reported information from ThreatFox implies that these IPs may not have been submitted or associated with indicators of compromise (IoCs) in the ThreatFox database at the time of this query.

ThreatFox is a database that generally contains indicators of compromise related to malware incidents, and the absence of data here could suggest either that these IPs have not been tied to known malware families or their associated campaigns, or they are new or relatively low in observable malicious activities from the perspective of the ThreatFox community.

To get a more detailed understanding of these IPs and any potential malicious activities associated with them, it would be necessary to rely on other sources of threat intelligence or conduct live monitoring and analysis.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Based on the data from ISC (Internet Storm Center), here is a summary of what is known about the IP addresses involved in the attack:

### IP Address: 165.232.188.209
- **Total Reports:** Involved in 816 reports
- **Honeypots Targeted:** Targeted 227 honeypots
- **First Seen:** November 3, 2023
- **Last Seen:** November 5, 2023
- **Network:** 165.232.176.0/20
- **AS Name:** DIGITALOCEAN-ASN
- **AS Country Code:** US
- **Threat Feeds:**
  - Listed in the Blocklist.de22 and EmerginCompromised threat feeds.
  
### IP Address: 104.248.26.212
- **Total Reports:** Involved in 470 reports
- **Honeypots Targeted:** Targeted 126 honeypots
- **First Seen:** November 3, 2023
- **Last Seen:** November 5, 2023
- **Network:** 104.248.16.0/20
- **AS Name:** DIGITALOCEAN-ASN
- **AS Country Code:** US
- **Threat Feeds:**
  - Listed in the Blocklist.de22 and EmerginCompromised threat feeds.
  
### IP Address: 64.227.46.76
- **Total Reports:** Involved in 87 reports
- **Honeypots Targeted:** Targeted 40 honeypots
- **First Seen:** November 6, 2023
- **Last Seen:** November 27, 2023
- **Network:** 64.227.32.0/20
- **AS Name:** DIGITALOCEAN-ASN
- **AS Country Code:** US
- **Threat Feeds:**
  - Listed in the Blocklist.de22 threat feed.

The ISC data confirms that all three IP addresses have been actively involved in malicious activities and have targeted multiple honeypots over a period of time. They are all associated with the DigitalOcean network and have been reported multiple times as posing a risk. These IP addresses have been linked to threat feeds known for reporting on compromised hosts and brute force activity. The high number of reports reflects a significant level of malicious activity associated with these IPs.

* `3` of the `3` unique source IPs have reports on the Internet Storm Center (ISC).
* `1373` total attacks were reported.
* `393` unique targets were attacked.
* The IP address with the **most reports** was `165.232.188.209` with `816` reports.
* The IP address with the **most targets** was `165.232.188.209` with `227` targets.
* The **first report** was on `2023-11-03` from `165.232.188.209`.
* The **most recent** was on `2023-11-27` from `64.227.46.76`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 165.232.188.209 | 816 | 227 | 2023-11-03 | 2023-11-05 | 2023-11-06 04:07:26 |
| 104.248.26.212 | 470 | 126 | 2023-11-03 | 2023-11-05 | 2023-11-06 04:07:26 |
| 64.227.46.76 | 87 | 40 | 2023-11-06 | 2023-11-27 | 2023-11-28 04:07:29 |

<details>
<summary>
<h4>Top 1 Asabusecontacts</h4>
</summary>

Total asabusecontacts: `3`
Unique: `1`

| asabusecontact | Times Seen |
| --- | --- |
| `abuse@digitalocean.com` | `3` |

</details>

---


<details>
<summary>
<h4>Top 1 As</h4>
</summary>

Total ass: `3`
Unique: `1`

| as | Times Seen |
| --- | --- |
| `14061` | `3` |

</details>

---


<details>
<summary>
<h4>Top 1 Asnames</h4>
</summary>

Total asnames: `3`
Unique: `1`

| asname | Times Seen |
| --- | --- |
| `DIGITALOCEAN-ASN` | `3` |

</details>

---


<details>
<summary>
<h4>Top 1 Ascountrys</h4>
</summary>

Total ascountrys: `3`
Unique: `1`

| ascountry | Times Seen |
| --- | --- |
| `US` | `3` |

</details>

---


<details>
<summary>
<h4>Top 1 Assizes</h4>
</summary>

Total assizes: `3`
Unique: `1`

| assize | Times Seen |
| --- | --- |
| `2877952` | `3` |

</details>

---


<details>
<summary>
<h4>Top 3 Networks</h4>
</summary>

Total networks: `3`
Unique: `3`

| network | Times Seen |
| --- | --- |
| `165.232.176.0/20` | `1` |
| `104.248.16.0/20` | `1` |
| `64.227.32.0/20` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Threatfeeds</h4>
</summary>

Total threatfeedss: `5`
Unique: `2`

| threatfeeds | Times Seen |
| --- | --- |
| `blocklistde22` | `3` |
| `emergincompromised` | `2` |

</details>

---


<details>
<summary>
<h4>Top 1 Clouds</h4>
</summary>

Total clouds: `3`
Unique: `1`

| cloud | Times Seen |
| --- | --- |
| `digitalocean` | `3` |

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
<h3>Whois data for: 165.232.188.209</h3>
</summary>


### Whois data for: 165.232.188.209 [https://www.whois.com/whois/165.232.188.209](https://www.whois.com/whois/165.232.188.209)

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


NetRange:       165.232.32.0 - 165.232.191.255
CIDR:           165.232.32.0/19, 165.232.128.0/18, 165.232.64.0/18
NetName:        DIGITALOCEAN-165-232-32-0
NetHandle:      NET-165-232-32-0-1
Parent:         NET165 (NET-165-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS14061
Organization:   DigitalOcean, LLC (DO-13)
RegDate:        2019-12-27
Updated:        2020-04-03
Comment:        Routing and Peering Policy can be found at https://www.as14061.net
Comment:        
Comment:        Please submit abuse reports at https://www.digitalocean.com/company/contact/#abuse
Ref:            https://rdap.arin.net/registry/ip/165.232.32.0



OrgName:        DigitalOcean, LLC
OrgId:          DO-13
Address:        101 Ave of the Americas
Address:        FL2
City:           New York
StateProv:      NY
PostalCode:     10013
Country:        US
RegDate:        2012-05-14
Updated:        2023-10-23
Ref:            https://rdap.arin.net/registry/entity/DO-13


OrgAbuseHandle: ABUSE5232-ARIN
OrgAbuseName:   Abuse, DigitalOcean 
OrgAbusePhone:  +1-347-875-6044 
OrgAbuseEmail:  @digitalocean.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5232-ARIN

OrgNOCHandle: NOC32014-ARIN
OrgNOCName:   Network Operations Center
OrgNOCPhone:  +1-347-875-6044 
OrgNOCEmail:  @digitalocean.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN

OrgTechHandle: NOC32014-ARIN
OrgTechName:   Network Operations Center
OrgTechPhone:  +1-347-875-6044 
OrgTechEmail:  @digitalocean.com
OrgTechRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN


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
<h3>Whois data for: 104.248.26.212</h3>
</summary>


### Whois data for: 104.248.26.212 [https://www.whois.com/whois/104.248.26.212](https://www.whois.com/whois/104.248.26.212)

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


NetRange:       104.248.0.0 - 104.248.255.255
CIDR:           104.248.0.0/16
NetName:        DIGITALOCEAN-104-248-0-0
NetHandle:      NET-104-248-0-0-1
Parent:         NET104 (NET-104-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS14061
Organization:   DigitalOcean, LLC (DO-13)
RegDate:        2018-08-06
Updated:        2020-04-03
Comment:        Routing and Peering Policy can be found at https://www.as14061.net
Comment:        
Comment:        Please submit abuse reports at https://www.digitalocean.com/company/contact/#abuse
Ref:            https://rdap.arin.net/registry/ip/104.248.0.0



OrgName:        DigitalOcean, LLC
OrgId:          DO-13
Address:        101 Ave of the Americas
Address:        FL2
City:           New York
StateProv:      NY
PostalCode:     10013
Country:        US
RegDate:        2012-05-14
Updated:        2023-10-23
Ref:            https://rdap.arin.net/registry/entity/DO-13


OrgAbuseHandle: ABUSE5232-ARIN
OrgAbuseName:   Abuse, DigitalOcean 
OrgAbusePhone:  +1-347-875-6044 
OrgAbuseEmail:  @digitalocean.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5232-ARIN

OrgTechHandle: NOC32014-ARIN
OrgTechName:   Network Operations Center
OrgTechPhone:  +1-347-875-6044 
OrgTechEmail:  @digitalocean.com
OrgTechRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN

OrgNOCHandle: NOC32014-ARIN
OrgNOCName:   Network Operations Center
OrgNOCPhone:  +1-347-875-6044 
OrgNOCEmail:  @digitalocean.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN


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
<h3>Whois data for: 64.227.46.76</h3>
</summary>


### Whois data for: 64.227.46.76 [https://www.whois.com/whois/64.227.46.76](https://www.whois.com/whois/64.227.46.76)

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


NetRange:       64.227.0.0 - 64.227.127.255
CIDR:           64.227.0.0/17
NetName:        DIGITALOCEAN-64-227-0-0
NetHandle:      NET-64-227-0-0-2
Parent:         NET64 (NET-64-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS14061
Organization:   DigitalOcean, LLC (DO-13)
RegDate:        2019-08-14
Updated:        2020-04-03
Comment:        Routing and Peering Policy can be found at https://www.as14061.net
Comment:        
Comment:        Please submit abuse reports at https://www.digitalocean.com/company/contact/#abuse
Ref:            https://rdap.arin.net/registry/ip/64.227.0.0



OrgName:        DigitalOcean, LLC
OrgId:          DO-13
Address:        101 Ave of the Americas
Address:        FL2
City:           New York
StateProv:      NY
PostalCode:     10013
Country:        US
RegDate:        2012-05-14
Updated:        2023-10-23
Ref:            https://rdap.arin.net/registry/entity/DO-13


OrgNOCHandle: NOC32014-ARIN
OrgNOCName:   Network Operations Center
OrgNOCPhone:  +1-347-875-6044 
OrgNOCEmail:  @digitalocean.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN

OrgAbuseHandle: ABUSE5232-ARIN
OrgAbuseName:   Abuse, DigitalOcean 
OrgAbusePhone:  +1-347-875-6044 
OrgAbuseEmail:  @digitalocean.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5232-ARIN

OrgTechHandle: NOC32014-ARIN
OrgTechName:   Network Operations Center
OrgTechPhone:  +1-347-875-6044 
OrgTechEmail:  @digitalocean.com
OrgTechRef:    https://rdap.arin.net/registry/entity/NOC32014-ARIN


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

