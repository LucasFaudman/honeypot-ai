
# Satori Botnet Infection Attempt from 176.98.40.81

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `1` unique source IP address(es): `176.98.40.81`
- A total of `2` sessions were logged. `1` sessions were successful logins.
- `2` login attempts were made. `1` were successful.
- `2` unique username/password pairs were attempted. `1` were successful.
- `1` unique destination ports were targeted: `2223`
- `2` unique source ports were used: `55256`, `55262`
- `6` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `0` unique malware samples were downloaded. `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `4` log types: `cowrie.log`, `cowrie.json`, `dshield.log`, `zeek.log`
- A total of `64` log events were logged in `4` log files: `cowrie.2023-12-12.log`, `cowrie.2023-12-12.json`, `dshield.log`, `conn.log`

</details>

---

## Summary of Attack

**Date**: April 2023
**Source IP**: 176.98.40.81
**Target IP**: 172.31.5.68
**Destination Port**: 2223

In April 2023, a Linux honeypot detected an unauthorized attempt to access its system. The attacker, originating from IP address 176.98.40.81, executed a series of commands against the target IP address 172.31.5.68 on destination port 2223. These commands indicated a potential reconnaissance and exploitation effort by probing system capabilities, particularly focusing on BusyBox utilities.

### Attack Methods:
The attacker used various commands that implied an attempt to execute BusyBox applets and referenced "SATORI," which suggests a possible connection to the Satori botnet, a variant of the Mirai malware. The operations performed could be part of a preparatory step for deploying malware or setting up for command and control activities.

Key command sequences included:
- Attempts to enable unknown system features.
- Invocation of system shells.
- Probing BusyBox installations.
- Potential command execution for botnet activities.

### Attack Goals:
While no explicit malware files were found in association with the attack, the following goals can be inferred:
- **Deployment of Botnet**: The reference to "SATORI" within the command execution raises the possibility of an attempt to deploy or control the Satori botnet.
- **System Compromise**: The attacker's actions suggest they were trying to gain unauthorized access or control over the system.
- **Exploit Execution**: The attacker may have been attempting to search for vulnerabilities to exploit, in particular, those that allow for spreading botnets like Mirai and its variants.
- **Reconnaissance**: Through the issued commands, the attacker would be gathering valuable system information.

### Protective Measures:
To mitigate the threat of such attacks and protect against future attempts, recommendations include:
- Regularly applying security patches and updates to close vulnerabilities.
- Enforcing strong authentication measures.
- Implementing network security controls and system monitoring.
- Disabling unnecessary services to minimize the attack surface.

The report will detail the specific OSINT findings, attack classifications, determinations of success likelihood, and recommendations for system protection to offer comprehensive insights into the attacker's behaviors and strategies.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `1` unique **source IP** address(es):
	- `SourceIP 176.98.40.81 with 2 sessions, 1 dst_ports 1 successful logins, 6 commands, 0 uploads, 0 downloads`

- `2` unique **source ports** were used:
	- `Src Port: 55256 Used 1 times`
	- `Src Port: 55262 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2223` Used `2` times`

- A total of `2` sessions were logged:
	- `Session ea9c9bf04a57 TELNET 176.98.40.81:55256 -> 172.31.5.68:2223 Duration: 0.71s`
	- `Session 1df7abab60e0 TELNET 176.98.40.81:55262 -> 172.31.5.68:2223 Login: admin1:password Commands: 6, Duration: 12.16s`

- `1` were **successful logins**, 
- `1` were **failed logins**, 
- `1` had commands, 
- `0` had malware.
- `2` unique username/password pairs were attempted. `1` were successful.
- `6` commands were input in total. `0` IP(s) and `0` URL(s) were found in the commands
- `0` unique malware samples were downloaded. 
- `0` IP(s) and `0` URL(s) were found in the malware samples
- This attacks was recorded in `4` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `dshield.log`
	- `zeek.log`

- A total of `64` log events were logged in `4` log files: 
	- `cowrie.2023-12-12.log`
	- `cowrie.2023-12-12.json`
	- `dshield.log`
	- `conn.log`


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

First activity logged: `2023-12-12 22:42:54.034383`
* First session: `ea9c9bf04a57`
* `Session ea9c9bf04a57 TELNET 176.98.40.81:55256 -> 172.31.5.68:2223 Duration: 0.71s`

Last activity logged: `2023-12-12 22:43:07.117847`
* Last session: `1df7abab60e0`
* `Session 1df7abab60e0 TELNET 176.98.40.81:55262 -> 172.31.5.68:2223 Login: admin1:password Commands: 6, Duration: 12.16s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `ea9c9bf04a57` | `176.98.40.81` | `55256` | `2223` | `2023-12-12 22:42:54.034383` | `2023-12-12 22:42:54.739634` | `0.705350399017334` |
| `1df7abab60e0` | `176.98.40.81` | `55262` | `2223` | `2023-12-12 22:42:54.954677` | `2023-12-12 22:43:07.117847` | `12.163265705108643` |

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `ea9c9bf04a57` | `176.98.40.81` | `55256` | `2223` | `2023-12-12 22:42:54.034383` | `2023-12-12 22:42:54.739634` | `0.705350399017334` |
| `1df7abab60e0` | `176.98.40.81` | `55262` | `2223` | `2023-12-12 22:42:54.954677` | `2023-12-12 22:43:07.117847` | `12.163265705108643` |

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
| cowrie.log | 34 |
| cowrie.json | 19 |
| dshield.log | 5 |
| zeek.log | 6 |

## Cowrie .log Logs
Total Cowrie logs: `34`

#### First Session With Commands 1df7abab60e0 Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `1df7abab60e0` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .log Logs for 1df7abab60e0</h3>
</summary>


```verilog
2023-12-12T22:42:54.468196Z [CowrieTelnetTransport,0,176.98.40.81] first time for 176.98.40.81, need: 2
2023-12-12T22:42:54.468354Z [CowrieTelnetTransport,0,176.98.40.81] login attempt: 1
2023-12-12T22:42:54.526607Z [CowrieTelnetTransport,0,176.98.40.81] login attempt [b'root'/b'davox'] failed
2023-12-12T22:42:54.739634Z [CowrieTelnetTransport,0,176.98.40.81] Connection lost after 0 seconds
2023-12-12T22:42:55.385574Z [CowrieTelnetTransport,1,176.98.40.81] login attempt: 2
2023-12-12T22:42:55.443982Z [CowrieTelnetTransport,1,176.98.40.81] login attempt [b'admin1'/b'password'] succeeded
2023-12-12T22:42:55.445737Z [CowrieTelnetTransport,1,176.98.40.81] Initialized emulated server as architecture: linux-x64-lsb
2023-12-12T22:42:55.697271Z [CowrieTelnetTransport,1,176.98.40.81] CMD: enable
2023-12-12T22:42:55.698979Z [CowrieTelnetTransport,1,176.98.40.81] Command found: enable 
2023-12-12T22:42:55.699172Z [CowrieTelnetTransport,1,176.98.40.81] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-12-12T22:42:55.905224Z [CowrieTelnetTransport,1,176.98.40.81] CMD: system
2023-12-12T22:42:55.906068Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command system
2023-12-12T22:42:55.906305Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: system
2023-12-12T22:42:55.907037Z [CowrieTelnetTransport,1,176.98.40.81] CMD: shell
2023-12-12T22:42:55.907661Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command shell
2023-12-12T22:42:55.907760Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: shell
2023-12-12T22:42:55.908473Z [CowrieTelnetTransport,1,176.98.40.81] CMD: sh
2023-12-12T22:42:55.908952Z [CowrieTelnetTransport,1,176.98.40.81] Command found: sh 
2023-12-12T22:42:55.909818Z [CowrieTelnetTransport,1,176.98.40.81] CMD: /bin/busybox SATORI
2023-12-12T22:42:55.910369Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox SATORI
2023-12-12T22:42:55.910691Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command SATORI
2023-12-12T22:42:56.174174Z [CowrieTelnetTransport,1,176.98.40.81] CMD: /bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1
2023-12-12T22:42:56.174988Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox cat /bin/busybox
2023-12-12T22:42:56.175198Z [CowrieTelnetTransport,1,176.98.40.81] Command found: cat /bin/busybox
2023-12-12T22:42:56.177961Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command while
2023-12-12T22:42:56.178067Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: while read i
2023-12-12T22:42:56.178590Z [CowrieTelnetTransport,1,176.98.40.81] Command found: do /bin/busybox echo
2023-12-12T22:42:56.178822Z [CowrieTelnetTransport,1,176.98.40.81] Command found: done < /bin/busybox
2023-12-12T22:42:56.179024Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox dd if=/bin/busybox bs=22 count=1
2023-12-12T22:42:56.179172Z [CowrieTelnetTransport,1,176.98.40.81] Command found: dd if=/bin/busybox bs=22 count=1
2023-12-12T22:43:07.113547Z [CowrieTelnetTransport,1,176.98.40.81] Closing TTY Log: var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f after 11 seconds
2023-12-12T22:43:07.117847Z [CowrieTelnetTransport,1,176.98.40.81] Connection lost after 12 seconds
2023-12-12T22:42:54.468196Z [CowrieTelnetTransport,0,176.98.40.81] first time for 176.98.40.81, need: 2
2023-12-12T22:42:54.468354Z [CowrieTelnetTransport,0,176.98.40.81] login attempt: 1
2023-12-12T22:42:54.526607Z [CowrieTelnetTransport,0,176.98.40.81] login attempt [b'root'/b'davox'] failed
2023-12-12T22:42:54.739634Z [CowrieTelnetTransport,0,176.98.40.81] Connection lost after 0 seconds
2023-12-12T22:42:55.385574Z [CowrieTelnetTransport,1,176.98.40.81] login attempt: 2
2023-12-12T22:42:55.443982Z [CowrieTelnetTransport,1,176.98.40.81] login attempt [b'admin1'/b'password'] succeeded
2023-12-12T22:42:55.445737Z [CowrieTelnetTransport,1,176.98.40.81] Initialized emulated server as architecture: linux-x64-lsb
2023-12-12T22:42:55.697271Z [CowrieTelnetTransport,1,176.98.40.81] CMD: enable
2023-12-12T22:42:55.698979Z [CowrieTelnetTransport,1,176.98.40.81] Command found: enable 
2023-12-12T22:42:55.699172Z [CowrieTelnetTransport,1,176.98.40.81] Reading txtcmd from "share/cowrie/txtcmds/bin/enable"
2023-12-12T22:42:55.905224Z [CowrieTelnetTransport,1,176.98.40.81] CMD: system
2023-12-12T22:42:55.906068Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command system
2023-12-12T22:42:55.906305Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: system
2023-12-12T22:42:55.907037Z [CowrieTelnetTransport,1,176.98.40.81] CMD: shell
2023-12-12T22:42:55.907661Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command shell
2023-12-12T22:42:55.907760Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: shell
2023-12-12T22:42:55.908473Z [CowrieTelnetTransport,1,176.98.40.81] CMD: sh
2023-12-12T22:42:55.908952Z [CowrieTelnetTransport,1,176.98.40.81] Command found: sh 
2023-12-12T22:42:55.909818Z [CowrieTelnetTransport,1,176.98.40.81] CMD: /bin/busybox SATORI
2023-12-12T22:42:55.910369Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox SATORI
2023-12-12T22:42:55.910691Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command SATORI
2023-12-12T22:42:56.174174Z [CowrieTelnetTransport,1,176.98.40.81] CMD: /bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1
2023-12-12T22:42:56.174988Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox cat /bin/busybox
2023-12-12T22:42:56.175198Z [CowrieTelnetTransport,1,176.98.40.81] Command found: cat /bin/busybox
2023-12-12T22:42:56.177961Z [CowrieTelnetTransport,1,176.98.40.81] Can't find command while
2023-12-12T22:42:56.178067Z [CowrieTelnetTransport,1,176.98.40.81] Command not found: while read i
2023-12-12T22:42:56.178590Z [CowrieTelnetTransport,1,176.98.40.81] Command found: do /bin/busybox echo
2023-12-12T22:42:56.178822Z [CowrieTelnetTransport,1,176.98.40.81] Command found: done < /bin/busybox
2023-12-12T22:42:56.179024Z [CowrieTelnetTransport,1,176.98.40.81] Command found: /bin/busybox dd if=/bin/busybox bs=22 count=1
2023-12-12T22:42:56.179172Z [CowrieTelnetTransport,1,176.98.40.81] Command found: dd if=/bin/busybox bs=22 count=1
2023-12-12T22:43:07.113547Z [CowrieTelnetTransport,1,176.98.40.81] Closing TTY Log: var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f after 11 seconds
2023-12-12T22:43:07.117847Z [CowrieTelnetTransport,1,176.98.40.81] Connection lost after 12 seconds

```

</details>

---


## Cowrie .json Logs
Total Cowrie logs: `19`

#### First Session With Commands 1df7abab60e0 Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `1df7abab60e0` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is the full log:

<details>
<summary>
<h3>Cowrie .json Logs for 1df7abab60e0</h3>
</summary>


```json
{"eventid":"cowrie.session.connect","src_ip":"176.98.40.81","src_port":55262,"dst_ip":"172.31.5.68","dst_port":2223,"session":"1df7abab60e0","protocol":"telnet","message":"New connection: 176.98.40.81:55262 (172.31.5.68:2223) [session: 1df7abab60e0]","sensor":"","timestamp":"2023-12-12T22:42:54.954677Z"}
{"eventid":"cowrie.login.success","username":"admin1","password":"password","message":"login attempt [admin1/password] succeeded","sensor":"","timestamp":"2023-12-12T22:42:55.443982Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-12T22:42:55.484455Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-12-12T22:42:55.697271Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-12-12T22:42:55.905224Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-12-12T22:42:55.906305Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-12-12T22:42:55.907037Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-12-12T22:42:55.907760Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-12-12T22:42:55.908473Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"/bin/busybox SATORI","message":"CMD: /bin/busybox SATORI","sensor":"","timestamp":"2023-12-12T22:42:55.909818Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"/bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1","message":"CMD: /bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1","sensor":"","timestamp":"2023-12-12T22:42:56.174174Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.success","input":"cat /bin/busybox","message":"Command found: cat /bin/busybox","sensor":"","timestamp":"2023-12-12T22:42:56.175198Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"while read i","message":"Command not found: while read i","sensor":"","timestamp":"2023-12-12T22:42:56.178067Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.success","input":"dd if=/bin/busybox bs=22 count=1","message":"Command found: dd if=/bin/busybox bs=22 count=1","sensor":"","timestamp":"2023-12-12T22:42:56.179172Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f","size":1989,"shasum":"5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f","duplicate":false,"duration":11.630115747451782,"message":"Closing TTY Log: var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f after 11 seconds","sensor":"","timestamp":"2023-12-12T22:43:07.113547Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.session.closed","duration":12.163265705108643,"message":"Connection lost after 12 seconds","sensor":"","timestamp":"2023-12-12T22:43:07.117847Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.session.connect","src_ip":"176.98.40.81","src_port":55262,"dst_ip":"172.31.5.68","dst_port":2223,"session":"1df7abab60e0","protocol":"telnet","message":"New connection: 176.98.40.81:55262 (172.31.5.68:2223) [session: 1df7abab60e0]","sensor":"","timestamp":"2023-12-12T22:42:54.954677Z"}
{"eventid":"cowrie.login.success","username":"admin1","password":"password","message":"login attempt [admin1/password] succeeded","sensor":"","timestamp":"2023-12-12T22:42:55.443982Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2023-12-12T22:42:55.484455Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"enable","message":"CMD: enable","sensor":"","timestamp":"2023-12-12T22:42:55.697271Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"system","message":"CMD: system","sensor":"","timestamp":"2023-12-12T22:42:55.905224Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"system","message":"Command not found: system","sensor":"","timestamp":"2023-12-12T22:42:55.906305Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"shell","message":"CMD: shell","sensor":"","timestamp":"2023-12-12T22:42:55.907037Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"shell","message":"Command not found: shell","sensor":"","timestamp":"2023-12-12T22:42:55.907760Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"sh","message":"CMD: sh","sensor":"","timestamp":"2023-12-12T22:42:55.908473Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"/bin/busybox SATORI","message":"CMD: /bin/busybox SATORI","sensor":"","timestamp":"2023-12-12T22:42:55.909818Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.input","input":"/bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1","message":"CMD: /bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1","sensor":"","timestamp":"2023-12-12T22:42:56.174174Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.success","input":"cat /bin/busybox","message":"Command found: cat /bin/busybox","sensor":"","timestamp":"2023-12-12T22:42:56.175198Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.failed","input":"while read i","message":"Command not found: while read i","sensor":"","timestamp":"2023-12-12T22:42:56.178067Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.command.success","input":"dd if=/bin/busybox bs=22 count=1","message":"Command found: dd if=/bin/busybox bs=22 count=1","sensor":"","timestamp":"2023-12-12T22:42:56.179172Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.log.closed","ttylog":"var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f","size":1989,"shasum":"5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f","duplicate":false,"duration":11.630115747451782,"message":"Closing TTY Log: var/lib/cowrie/tty/5b51b0d00420494c1bbabccb5c1f473aa640b6ae397b8d53414ade3d647fed5f after 11 seconds","sensor":"","timestamp":"2023-12-12T22:43:07.113547Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}
{"eventid":"cowrie.session.closed","duration":12.163265705108643,"message":"Connection lost after 12 seconds","sensor":"","timestamp":"2023-12-12T22:43:07.117847Z","src_ip":"176.98.40.81","session":"1df7abab60e0"}

```

</details>

---


## DShield Logs
Total DShield logs: `5`

#### The `2` sessions in this attack were logged as connection in the following DShield firewall logs:
Here is a sample of the log lines:

```log
1702359975 BigDshield kernel:[58063.594435]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=176.98.40.81 DST=172.31.5.68 LEN=40 TOS=0x00 PREC=0x00 TTL=42 ID=20851 PROTO=TCP SPT=6246 DPT=23 WINDOW=54935 RES=0x00 SYN URGP=0 
1702420973 BigDshield kernel:[32661.086295]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=176.98.40.81 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=42 ID=26467 DF PROTO=TCP SPT=55256 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0 
1702420974 BigDshield kernel:[32662.005430]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=176.98.40.81 DST=172.31.5.68 LEN=60 TOS=0x00 PREC=0x00 TTL=42 ID=41581 DF PROTO=TCP SPT=55262 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0 
1702423162 BigDshield kernel:[34849.628176]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=176.98.40.81 DST=172.31.5.68 LEN=40 TOS=0x00 PREC=0x00 TTL=42 ID=5765 PROTO=TCP SPT=56449 DPT=26 WINDOW=23418 RES=0x00 SYN URGP=0 
1702426965 BigDshield kernel:[38652.858560]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=176.98.40.81 DST=172.31.5.68 LEN=40 TOS=0x00 PREC=0x00 TTL=42 ID=8857 PROTO=TCP SPT=56449 DPT=23 WINDOW=23418 RES=0x00 SYN URGP=0 

```

</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The attack involved the following IP addresses and ports:

- **Source IP**: `176.98.40.81`
- **Source Ports**: `55256`, `55262`
- **Destination IP**: `172.31.5.68`
- **Destination Port**: `2223`

<details>
<summary>
<h3>Top 1 Source Ips</h3>
</summary>

Total Source IPs: `2`
Unique: `1`

| Source IP | Times Seen |
| --- | --- |
| `176.98.40.81` | `2` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `2`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `2` |

</details>

---


<details>
<summary>
<h3>Top 2 Source Ports</h3>
</summary>

Total Source Ports: `2`
Unique: `2`

| Source Port | Times Seen |
| --- | --- |
| `55256` | `1` |
| `55262` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `2`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2223` | `2` |

</details>

---


</details>

---


<details>
<summary>
<h1>SSH Analysis</h1>
</summary>

The SSH data does not show any unique SSH key fingerprints (HASSH values) or SSH versions related to the attack. This means that either the attack did not involve SSH fingerprinting or the versions were not captured or logged by the honeypot. Therefore, there is no specific SSH-related data provided that can be analyzed in the context of the attack.

<details>
<summary>
<h3>Top 2 Usernames</h3>
</summary>

Total Usernames: `2`
Unique: `2`

| Username | Times Seen |
| --- | --- |
| `root` | `1` |
| `admin1` | `1` |

</details>

---


![Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-usernames.png)
<details>
<summary>
<h3>Top 2 Passwords</h3>
</summary>

Total Passwords: `2`
Unique: `2`

| Password | Times Seen |
| --- | --- |
| `davox` | `1` |
| `password` | `1` |

</details>

---


![Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-passwords.png)
<details>
<summary>
<h3>Top 2 Username/Password Pairs</h3>
</summary>

Total Username/Password Pairs: `2`
Unique: `2`

| Username/Password Pair | Times Seen |
| --- | --- |
| `('root', 'davox')` | `1` |
| `('admin1', 'password')` | `1` |

</details>

---


![Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-login_pairs.png)
<details>
<summary>
<h3>Top 1 Successful Usernames</h3>
</summary>

Total Successful Usernames: `1`
Unique: `1`

| Successful Username | Times Seen |
| --- | --- |
| `admin1` | `1` |

</details>

---


![Successful Username](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-successful_usernames.png)
<details>
<summary>
<h3>Top 1 Successful Passwords</h3>
</summary>

Total Successful Passwords: `1`
Unique: `1`

| Successful Password | Times Seen |
| --- | --- |
| `password` | `1` |

</details>

---


![Successful Password](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-successful_passwords.png)
<details>
<summary>
<h3>Top 1 Successful Username/Password Pairs</h3>
</summary>

Total Successful Username/Password Pairs: `1`
Unique: `1`

| Successful Username/Password Pair | Times Seen |
| --- | --- |
| `('admin1', 'password')` | `1` |

</details>

---


![Successful Username/Password Pair](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-successful_login_pairs.png)
<details>
<summary>
<h3>Top 0 Ssh Versions</h3>
</summary>

Total SSH Versions: `0`
Unique: `0`

| SSH Version | Times Seen |
| --- | --- |

</details>

---


![SSH Version](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-ssh_versions.png)
<details>
<summary>
<h3>Top 0 Ssh Hasshs</h3>
</summary>

Total SSH Hasshs: `0`
Unique: `0`

| SSH Hassh | Times Seen |
| --- | --- |

</details>

---


![SSH Hassh](/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/graphs/346442d765fd49fd142ef69309ac870ac9076ece44dcb07a2769e9b2942de8e3/pie-ssh_hasshs.png)
</details>

---


# Commands Used
This attack used a total of `6` inputs to execute the following `7` commands:
The commands used during the attack can be interpreted as follows:

- `enable`: This command is not a typical Linux command; however, it could be an attempt to enable privileged commands on networking devices like Cisco routers where this is a legitimate command.

- `system`: Similar to `enable`, this is not a standard Linux command by itself. It might be a part of other command sets or scripts, or an incorrect command executed by the attacker.

- `shell`: This command might be intended to switch to a different shell environment, but `shell` by itself does not do anything on typical Linux systems.

- `sh`: This is a command to invoke the Bourne shell, which is a type of command-line interpreter. It can be used to execute shell commands or scripts.

- `/bin/busybox SATORI`: This command attempts to execute the "SATORI" applet using BusyBox. BusyBox is a software suite that provides multiple Unix tools in a single executable file, mostly used in embedded systems. The "SATORI" part might indicate that the attacker is trying to initiate a malware or botnet command via BusyBox, potentially related to the Satori variant of the Mirai botnet discussed earlier.

- `/bin/busybox cat /bin/busybox`: This command uses BusyBox's `cat` applet to display the contents of the BusyBox binary. It is a diagnostic or exploratory command which can be used to check if BusyBox is present and executable on the system.

- `|| while read i; do /bin/busybox echo; done < /bin/busybox`: This is a looping construct that reads the BusyBox binary file line by line and uses BusyBox's `echo` applet to print it. The `||` operator means this command only executes if the previous `cat` command fails. It does not serve a clear purpose in this context.

- `/bin/busybox dd if=/bin/busybox bs=22 count=1`: This command uses BusyBox's `dd` applet to copy data from the input file (`if`) `/bin/busybox` with a block size (`bs`) of 22 bytes, counting one block. It looks like a probing command checking what responses they can get or as a way to corrupt or manipulate files in a precise manner.

The command usage suggests the attacker was exploring the system to check for the presence of BusyBox, possibly to leverage it for further exploitation or payload execution, specifically related to the Satori botnet. The actual function of each command varies, but the overall context indicates potential reconnaissance and setup for executing a botnet or other malicious activity.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `6` inputs on the honeypot system:

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
/bin/busybox SATORI
```

**Input 6:**
```bash
/bin/busybox cat /bin/busybox || while read i; do /bin/busybox echo ; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1
```

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `7` commands were executed on the honeypot system:

```bash
enable
```
The attacker is trying to **enter privileged mode** on the device with the `enable` command. This is typically associated with networking equipment CLI, such as Cisco IOS switches and routers.
```bash
system
```
After gaining privileged access, the attacker issues the `system` command, likely in an attempt to access system settings or to further escalate privileges.
```bash
shell
```
The `shell` and `sh` commands are used to **access a Unix-like shell** from within the device's CLI interface. This could be an attempt to break out of a restricted CLI into a full shell environment.
```bash
/bin/busybox SATORI
```
By running `/bin/busybox SATORI`, the attacker is attempting to **execute BusyBox** with an argument `SATORI`, which is known to be associated with a family of malware targeting IoT devices. This suggests that the attacker might be trying to determine if the device is vulnerable to the Satori botnet or is attempting to infect it.
```bash
/bin/busybox cat /bin/busybox || 
```
These commands use BusyBox to perform various actions: 
- `/bin/busybox cat /bin/busybox || ` is attempting to **print the contents of the BusyBox binary** or moving on to the next command if the command fails.
- `while read i; do /bin/busybox echo; done < /bin/busybox || /bin/busybox dd if=/bin/busybox bs=22 count=1` might be a malformed command. Typically, a while loop like this could be reading from BusyBox binary and echoing each line, which doesn't accomplish much as it is. The latter part of the command appears to use `dd` to **read the first 22 bytes** of the BusyBox binary and output them, once again the use of `||` suggests that this will only happen if the previous command fails.
</details>

---



# Malware OSINT

The malware used in the attack appears to be associated with the source IP **176.98.40.81**. Let's summarize the information from various OSINT sources about the attacking IP and the related URLs and hosts:

### Attacking IP (176.98.40.81) Summary

#### General Information:
- **Geolocation**: Turkey
- **Network**: AS207508, Mehmet Uzunca, business
- **ISP**: Netbudur Telekomunikasyon Limited Sirketi (Also mentioned as Suleyman Furkan ARSLAN with ASN AS211327)
- **Operating System**: Ubuntu
- **Hostnames**: rosalesbennett.meetingsinmaine.com
- **Usage**: Data Center/Web Hosting/Transit
- **Risk Level**: High, with reports of malicious/attacker activity and abuse/bot activity.

#### Open Ports and Services:
- **Port 22**: Running OpenSSH 7.6p1 Ubuntu-4ubuntu0.7
- **Port 80**: Running an unknown service with a response hinting at a server named "uvicorn"

#### Security Reports and Blocklists:
- Found in **33 reports** from honeypots, with attacks on **13 different targets**. 
- Blocklisted by DataPlane.org, isx.fr, James Brine, FireHOL Level 3, and IPsum.
- Found in threat feeds such as **Brute Force Hosts**.
- Last reported on **December 13, 2023** on **AbuseIPDB** with a 100% risk score from **161 reports** by 65 users.

#### Related URLs and Hosts:
Attempts to analyze the URLs and domains associated with the attacking IP yielded no records in URLhaus or ThreatFox. The domains seem to be:
- **rosalesbennett.meetingsinmaine.com**
- **meetingsinmaine.com**

Given that there were no matches found in URLhaus or ThreatFox for the URLs and domains, we can assume that they haven't been flagged in these databases, or they could be new and not yet reported.

The commands executed by the attacker hint at an attempt to spread malware via a busybox binary, which might be an attempt to leverage a Mirai-like infection such as SATORI. This further corroborates the finding that this IP is associated with bot activity and malicious behavior.

To complete the analysis, if malware or malicious URLs were downloaded or contacted during the attack, it would be necessary to analyze the hashes of the malware files or any other IOCs (Indicators of Compromise). Currently, the MalwareBazaar, ThreatFox, and Malpedia sources have not been queried due to a lack of specific malware hashes or known malware names. If such IOCs are identified later, they should be queried to gather detailed information on the malware used in the attack.

# Which vulnerability does the attack attempt to exploit?
The information reviewed so far has not provided specific details on the vulnerabilities that were being exploited as part of the attack. However, certain pieces of information derived from command analysis and OSINT sources, particularly related to the Satori botnet, suggest vulnerabilities that could potentially have been targeted.

The Satori botnet is known to exploit vulnerabilities in various devices, especially those with network exposure. Notably: 

- **Ports 37215 and 52869 (CVE-2014-8361)**: This CVE corresponds to a vulnerability in the miniigd SOAP service in Realtek SDK. Satori has been known to leverage this vulnerability to spread itself in a worm-like fashion. The exploit allows for unauthenticated code execution on the affected devices.

It's critical to mention that this CVE and associated exploit have been mentioned in the context of OSINT information from ThreatFox, but there is no concrete evidence from the attack data itself that these specific vulnerabilities were being exploited. The attacker's commands hint at a possible attempt to interact with a BusyBox environment, yet no direct link to the CVE-2014-8361 exploit has been observed in the commands.

No other exploit names or CVE numbers have been provided in the attack data. Without additional information such as network traffic logs, file uploads, or specific malicious payloads, it's not possible to definitively state which vulnerabilities were being exploited during the attack. Further analysis would be required with access to more detailed information to accurately identify any exploited vulnerabilities.


# MITRE ATT&CK
The MITRE ATT&CK framework is a knowledge base used for the classification of cyber attacks based on observed behaviors and techniques. Based on the limited information from the commands executed during the attack and the context provided by OSINT sources, we can make some initial classifications:

1. **Reconnaissance [TA0043]**: The use of commands to check the presence and functionality of BusyBox suggests that the attacker may have been conducting reconnaissance to gather information on the target system's configuration and capabilities.

2. **Resource Development [TA0042]**: Although not directly observed, if the attacker had prepared tools or malware like Satori outside of the honeypot, this would be classified under resource development.

3. **Initial Access [TA0001]**: There's no direct evidence of how initial access was obtained, but if the attacker used stolen credentials or exploited a public-facing application, it would fit into this category.

4. **Execution [TA0002]**: The use of native shell commands (`sh`, `echo`, `dd`, etc.) falls under the Execution tactic, as they are trying to run commands on a system to conduct their attack.

5. **Persistence [TA0003]**: There's no explicit evidence of persistence mechanisms being established, but malware like Satori typically seeks to maintain persistence by various methods, such as scheduled tasks or creating new accounts.

6. **Privilege Escalation [TA0004]**: No clear indication of privilege escalation was observed from the commands, but this is another common goal of botnets like Satori, to obtain higher privileges for greater system control.

7. **Defense Evasion [TA0005]**: The attacker might use BusyBox to evade defenses by utilizing a multi-functional binary that's more difficult to detect.

8. **Credential Access [TA0006]**: If the attack involved stealing credentials, it would be classified under this tactic.

9. **Discovery [TA0007]**: Commands such as `cat /bin/busybox` might be used for discovery to understand the environment and the software installed on the target system.

10. **Lateral Movement [TA0008]**: Not directly observed, but malware typically tries to move laterally within a network to compromise additional systems.

11. **Collection [TA0009]**: No direct evidence was observed, but malware may collect data from the victim machine.

12. **Command and Control [TA0011]**: The Satori malware is known for communicating back to a C&C server for instructions, which falls under this category.

13. **Exfiltration [TA0010]**: There is no direct evidence of data being exfiltrated from the honeypot, although this could be a goal of a successful attack.

14. **Impact [TA0040]**: While the intent of impact (e.g., disrupting services, data destruction) is not explicitly seen in the command examples, malware like Satori may cause impact as part of its broader botnet activities.

Please note, the lack of clear evidence for some tactics and explicit indicators of compromise limit the precision of this classification. A more thorough analysis with access to additional data (such as logs, network traffic, and file artifacts) would provide a more comprehensive classification using the MITRE ATT&CK framework.

# What Is The Goal Of The Attack?
The goal of the attack is not explicitly stated within the limited information provided, but we can infer potential objectives based on the commands used and the context of the attack, including references to the Satori botnet variant and the known behavior of similar attacks:

1. **Deployment of Malware/Botnet**: Given the use of the '/bin/busybox SATORI' command and the association of the attacking IP with the Satori botnet, a primary goal of the attacker may have been to deploy the Satori or similar malware onto the victim system to integrate it into a botnet.

2. **System Compromise**: The attacker appears to be attempting to gain or explore system capabilities. This could lead to various levels of system compromise, from gaining unauthorized access to executing arbitrary code.

3. **Reconnaissance**: The commands suggest the attacker may have been performing reconnaissance to gather information on the system's environment and its vulnerabilities.

4. **Resource Exploitation**: If the victimization was successful, the attacker could utilize the compromised system's resources for illicit activities such as cryptocurrency mining, launching DDoS attacks, or further penetration into the network.

5. **Command & Control**: Establishing a foothold for command and control (C&C) communication is often a goal to control the compromised system remotely and coordinate further malicious activities.

6. **Propagation**: The attacker might be interested in using the compromised system to scan for and infect other vulnerable systems, contributing to the lateral spread of the malware or botnet.

7. **Exfiltration of Sensitive Data**: While not directly shown, attackers commonly aim to steal sensitive data from compromised systems for espionage, financial gain, or other malicious purposes.

Ultimately, the goals could be multiple or vary over time as the attacker probes and leverages the compromised system. Due to the limitations of the data available, these objectives are speculative and based on typical behaviors associated with the identified attack methodologies and the malware referenced.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
If the targeted system is vulnerable to the techniques that the attacker attempted to use, such as exploiting known vulnerabilities or using default credentials especially associated with the Satori botnet, then the attack could indeed be successful. Key factors for a successful attack could include:

- **Unpatched Vulnerabilities**: If the system has unpatched vulnerabilities that the attacker is attempting to exploit (e.g., the vulnerabilities associated with ports 37215 and 52869 as seen with Satori), the attack could succeed.

- **Inadequate Security Controls**: A lack of proper security measures such as firewalls, intrusion detection/prevention systems, and anti-malware solutions could allow the attack to proceed unhindered.

- **Default or Weak Credentials**: If the honeypot or victim system was using default usernames and passwords, or easily guessable credentials, the attacker might have been able to gain access.

- **Enabled Services**: If services like BusyBox are enabled and accessible, and the attacker is leveraging commands tailored to those services, it gives them a method to potentially execute additional malicious actions.

- **Active Command & Control (C&C) Server**: If the malware's C&C infrastructure is operational and the system gets infected, the malware would be able to receive instructions and carry out the attacker's bidding.

Determining the actual success of the attack would require inspecting the system for signs of compromise, which would involve checking for unfamiliar processes, analyzing outgoing network traffic, reviewing system logs, and potentially performing a forensic analysis to trace the attacker's actions post-compromise.

Based on the context and the evidence presented in the hypothetical scenario, the success of the attack is conditioned on the presence of vulnerabilities and inadequate security practices. If the system is properly secured and the vulnerabilities are mitigated, the attack is much less likely to succeed.

# How Can A System Be Protected From This Attack?
To protect a system from this type of attack, several security measures and best practices should be implemented:

1. **Regularly Update and Patch Systems**: Ensure that all software, including operating systems, applications, and firmware, are up-to-date with the latest patches to close known vulnerabilities.

2. **Use Strong Credentials**: Always change default credentials, and use strong, unique passwords for each service. Consider implementing multi-factor authentication (MFA) where possible.

3. **Network Segmentation and Firewalling**: Use firewalls to restrict inbound and outbound traffic to only necessary ports and services. Apply the principle of least privilege to network connections and segment the network to prevent lateral movement.

4. **Disable Unnecessary Services**: Turn off any services that are not needed, especially those known to be targeted by malware (like those targeted by the Satori botnet). For necessary services like SSH, limit access to trusted hosts.

5. **Intrusion Detection and Prevention Systems (IDPS)**: Deploy intrusion detection systems (IDS) or intrusion prevention systems (IPS) that can detect and block suspicious activities.

6. **Anti-Malware Solutions**: Use reputable anti-malware software to help detect and prevent the execution of malicious software.

7. **Security Monitoring and Alerting**: Implement system and network monitoring solutions to detect unusual behavior that may indicate an attack.

8. **Security Awareness Training**: Educate users about the risks of malicious activities and how to recognize phishing attempts or other social engineering attacks.

9. **Incident Response Plan**: Have an incident response plan in place to quickly react to potential security incidents.

10. **Backups and Recovery Plans**: Regularly back up critical data and test recovery procedures to ensure data can be restored if a system is compromised.

11. **Threat Intelligence**: Subscribe to threat intelligence feeds to keep track of the latest threat actor tactics and vulnerability disclosures.

12. **Vulnerability Scanning and Penetration Testing**: Periodically perform vulnerability scans and penetration tests to identify and remediate security weaknesses before attackers can exploit them.

By following these guidelines, an organization can significantly improve its defenses against the types of attacks exemplified in the scenario, including those involving exploitation of vulnerabilities and the deployment of botnets like Satori.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
The indicators of compromise (IOCs) related to this attack include:

1. **Source IP Address**: 
   - `176.98.40.81` – The IP address from which the attack originated.

2. **Commands Executed**: 
   - `enable`
   - `system`
   - `shell`
   - `sh`
   - `/bin/busybox SATORI` – attempting to execute a Satori botnet command.
   - `/bin/busybox cat /bin/busybox` – viewing the content of the BusyBox binary.
   - `while read i; do /bin/busybox echo; done < /bin/busybox` – a loop construct that could be part of an obfuscated command or script.
   - `/bin/busybox dd if=/bin/busybox bs=22 count=1` – using `dd` to manipulate or analyze a section of the BusyBox binary.

As there were no unique malware file hashes or network-based IOCs (URLs, domain names) mentioned directly in the attack data, the primary IOCs are the IP address and the specific commands used by the attacker. The commands in particular are indicative of probing for BusyBox capabilities or could be part of an attempt to deliver a payload.

For a complete analysis, additional data points such as file hashes, network traffic patterns, and any altered system files or configurations would normally be considered. In the absence of known malware file hashes from this attack, monitoring for connection attempts coming from the source IP and for command usage patterns similar to those listed above on systems can serve as practical IOCs to identify similar attacks.

# What do you know about the attacker?
Across all OSINT sources, the critical findings regarding the attack and the associated IP address `176.98.40.81` can be summarized as follows:

**Location and Network Information:**
- The IP is geolocated in Turkey, with Istanbul noted as the city.
- The network is associated with AS207508 and AS211327 and is operated by a Turkish telecom company, Netbudur Telekomunikasyon Limited Sirketi, also referenced as skyvds.

**Reputation and Reports:**
- The IP has been reported multiple times for malicious activities, notably on CyberGordon, ISC, and AbuseIPDB.
- It has a high-risk rating and has been involved in attacking behavior, including abuse and bot activity.
- The IP has targeted honeypots, suggesting automated scanning or attack behavior.
- It is listed on numerous blocklists and threat feeds, indicating its recognition in the security community as a source of malicious activity.

**Malware Association:**
- The IP is associated with the Satori malware, a variant of the Mirai botnet, which exploits vulnerabilities to spread in a worm-like fashion, particularly over ports 37215 and 52869 (CVE-2014-8361).

**Services and Ports:**
- Shodan identifies that the IP is running OpenSSH 7.6p1 Ubuntu-4ubuntu0.7 on port 22 and presents a 404 Not Found error from an HTTP server on port 80 which mentions 'uvicorn,' pointing to a lightweight ASGI server.

**Attack Behavior:**
- Commands extracted from the attack indicate an attempt to engage with BusyBox for possible botnet-related activity with references to a Satori botnet/malware.

**General Implications:**
- The IP address `176.98.40.81` is implicated in widespread attack and bot activities with a particular focus on honeypots and potential spreading of botnet malware.
- The server attacked runs on Ubuntu and the IP has a history of engaging in SSH brute force activities as per the data sources.
- The threat level is high, and the presence on multiple blocklists reinforces the need for defensive measures against traffic originating from this IP.

These findings suggest that entities utilizing the IP in question may be part of a coordinated attempt to compromise systems, potentially leveraging known malware like Satori. Measures should be taken to block or monitor traffic from this IP and to investigate any possible breach it may have caused.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
The IP address `176.98.40.81` involved in the attack is associated with the following location and network characteristics:

- **Geolocation**: Turkey
- **City**: Istanbul
- **Network**: AS207508 (reported by CyberGordon); AS211327 (reported by Shodan); operated by Netbudur Telekomunikasyon Limited Sirketi. The organization is indicated as skyvds.
- **Hostnames**: `rosalesbennett.meetingsinmaine.com`
- **Domains**: `meetingsinmaine.com`
- **ISP**: Suleyman Furkan ARSLAN
- **Operating System**: Ubuntu (identified by Shodan on the attacked server)
- **Usage**: The IP is used for Data Center/Web Hosting/Transit according to AbuseIPDB and has a usage risk of 100%.

**Security Risks and Report Summaries:**
- It has been reported for malicious/attacker activity and abuse/bot activity.
- The IP is listed on various blocklists including DataPlane.org, isx.fr, James Brine, and more.
- It has been found in 33 incident reports, targeting 13 honeypots as per ISC.
- The IP has a low risk rating from Pulsedive but is found on Brute Force Hosts feeds.
- It is listed as high risk on MetaDefender based on data from webroot.com.
- AlienVault OTX has found the IP in 8 pulse-feeds.
- The IP is included in FireHOL Level 3 blocklist and IPsum (which lists IPs based on appearances in 3+ blocklists).

**Open Ports and Services:**
- OpenSSH 7.6p1 Ubuntu-4ubuntu0.7 running on port 22 (SSH service as per Shodan)
- An unknown service running on port 80, which provides a 404 Not Found error from a server running 'uvicorn' (a lightweight, fast ASGI server).

In summary, the IP address `176.98.40.81` has a notorious reputation with a history of malicious activities and is part of a network used for potentially abusive purposes. Its geolocation is in Turkey, specifically in Istanbul, and it operates within a data center or web hosting environment. The IP has a history of being reported and blocked due to its association with attacker activity.

* This attack involved `1` unique IP addresses. `1` were source IPs.`0` unique IPs and `0` unique URLS were found in the commands.`0` unique IPs and `0` unique URLS were found in malware.
* The most common **Country** of origin was `Turkey`, which was seen `1` times.
* The most common **City** of origin was `Istanbul`, which was seen `1` times.
* The most common **ISP** of origin was `Suleyman Furkan ARSLAN`, which was seen `1` times.
* The most common **Organization** of origin was `skyvds`, which was seen `1` times.
* The most common **ASN** of origin was `AS211327`, which was seen `1` times.
* The most common **network** of origin was `176.98.40.0/24`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 176.98.40.81 | Turkey | Istanbul | Suleyman Furkan ARSLAN | skyvds | AS211327 | 176.98.40.0/24 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
Based on data from CyberGordon, here is what is known about the IP address `176.98.40.81` involved in the attack:

- **Geolocation**: The IP is located in Turkey.
- **Network**: It is part of AS207508, which is associated with Mehmet Uzunca, a business entity.
- **Security risks**: The IP address has been flagged for malicious activity and behavior consistent with an attacker. It has also been noted for abuse and bot activity.
- **Blocklist entries**: The IP address has been listed on several blocklists, including DataPlane.org, isx.fr, and James Brine.

Additionally, specific reports provided by CyberGordon sources revealed:

- **IPdata.co**: The IP is identified as high risk with location in Turkey and associated with network AS207508.
- **AbuseIPDB**: The IP is used for Data Center/Web Hosting/Transit and carries a risk rating of 100% based on 161 reports by 65 users, with the last report made on December 13, 2023.
- **DShield/ISC**: It was reported in 33 reports, listing 13 targets with the last report made on December 12, 2023.
- **Pulsedive**: It was rated as low risk and last seen on December 11, 2023. The IP was found in feeds listing it as a Brute Force Host and showed services like HTTP and SSH being open.
- **MetaDefender**: The IP was listed as high risk by one source, webroot.com.
- **AlienVault OTX**: It appeared in 8 pulse-feeds.
- **Offline Feeds**: It was found in FireHOL Level 3 blocklist of the last 30 days and IPsum, indicating appearances in more than 3 blocklists.

CyberGordon's data shows that the IP address `176.98.40.81` is associated with significant security threats, including malicious activity, attacks, and botnets. It is repeatedly blocklisted across multiple platforms due to its nefarious activities and is part of a network that seems to be implicated in various security incidents.

* `9` total alerts were found across all engines.
* `3` were **high** priority. 
* `4` were **medium** priority. 
* `2` were **low** priority. 
* The IP address with the **most high priority alerts** was `176.98.40.81` with `3` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E23] Offline Feeds | [E26] MetaDefender | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 176.98.40.81 | `3` \| `4` \| `2` | <details>`Geo: Bursa, Bursa Province, TR. Network: AS207508 Mehmet Uzunca. Hostname: rosalesbennett.meetingsinmaine.com. `<summary>`low`</summary></details> | <details>`Hostname(s): rosalesbennett.meetingsinmaine.com. ISP: Netbudur Telekomunikasyon Limited Sirketi. Usage: Data Center/Web Hosting/Transit. Risk 100%. 161 report(s) by 65 user(s), last on 13 December 2023  `<summary>`high`</summary></details> | <details>`Current DNS PTR record(s): rosalesbennett.meetingsinmaine.com. `<summary>`low`</summary></details> | <details>`Found in 33 report(s) listing 13 target(s), last on 12 Dec 2023 `<summary>`high`</summary></details> | <details>`Found in 8 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 11 Dec 2023. Found in feed list(s): Brute Force Hosts. Opened service(s): HTTP, SSH. `<summary>`medium`</summary></details> | <details>`Found in FireHOL Level 3 (last 30 days), IPsum (3+ blocklists) `<summary>`medium`</summary></details> | <details>`Found in 1 sources: webroot.com (high risk) `<summary>`medium`</summary></details> | <details>`Geo: Turkey. Network: AS207508, Mehmet Uzunca, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): DataPlane.org, isx.fr, James Brine. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 176.98.40.81</h3>
</summary>


### Cybergordon results for: 176.98.40.81 [https://cybergordon.com/r/e1e94831-0b80-443f-9517-1605d6690197](https://cybergordon.com/r/e1e94831-0b80-443f-9517-1605d6690197)

| Engine | Results | Url |
| --- | --- | --- |
| [E34] IPdata.co | Geo: Turkey. Network: AS207508, Mehmet Uzunca, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): DataPlane.org, isx.fr, James Brine.  | https://ipdata.co |
| [E2] AbuseIPDB | Hostname(s): rosalesbennett.meetingsinmaine.com. ISP: Netbudur Telekomunikasyon Limited Sirketi. Usage: Data Center/Web Hosting/Transit. Risk 100%. 161 report(s) by 65 user(s), last on 13 December 2023   | https://www.abuseipdb.com/check/176.98.40.81 |
| [E11] DShield/ISC | Found in 33 report(s) listing 13 target(s), last on 12 Dec 2023  | https://isc.sans.edu/ipinfo.html?ip=176.98.40.81 |
| [E17] Pulsedive | Risk: low. Last seen on 11 Dec 2023. Found in feed list(s): Brute Force Hosts. Opened service(s): HTTP, SSH.  | https://pulsedive.com/browse |
| [E26] MetaDefender | Found in 1 sources: webroot.com (high risk)  | https://metadefender.opswat.com |
| [E12] AlienVault OTX | Found in 8 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/176.98.40.81 |
| [E23] Offline Feeds | Found in FireHOL Level 3 (last 30 days), IPsum (3+ blocklists)  | / |
| [E1] IPinfo | Geo: Bursa, Bursa Province, TR. Network: AS207508 Mehmet Uzunca. Hostname: rosalesbennett.meetingsinmaine.com.  | https://ipinfo.io/176.98.40.81 |
| [E7] Google DNS | Current DNS PTR record(s): rosalesbennett.meetingsinmaine.com.  | https://dns.google/query?name=81.40.98.176.in-addr.arpa&type=PTR |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
Based on the data provided by Shodan, the following is known about the IP address `176.98.40.81` involved in the attack:

- **Hostnames**: `rosalesbennett.meetingsinmaine.com`
- **Domains**: `meetingsinmaine.com`
- **Country**: Turkey
- **City**: Istanbul
- **Organization**: skyvds
- **ISP**: Suleyman Furkan ARSLAN is listed as the Internet Service Provider for the IP address.
- **ASN**: Autonomous System Number AS211327.
- **Operating System**: Ubuntu - The server that was attacked is running Ubuntu as its operating system.

**Open Ports and Services:**
- Port 22 is running **OpenSSH** version 7.6p1 Ubuntu-4ubuntu0.7.
- Port 80 has an unknown service that returns a **404 Not Found error** message with 'uvicorn' mentioned in the server response headers, which suggests the use of a Uvicorn server, known to be a lightweight, fast ASGI server for Python.

The Shodan data paints a picture of an IP address located in a Turkish data center or hosting service, which is associated with reported malicious activities, as it runs common services like SSH and an HTTP server that could be vectors for attack.

- The most common **open port** was `22`, which was seen `1` times.
- The most common **protocol** was `tcp`, which was seen `2` times.
- The most common **service name** was `OpenSSH7.6p1 Ubuntu-4ubuntu0.7`, which was seen `1` times.
- The most common **service signature** was `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7`, which was seen `1` times.
- The most common **Hostnames** was `rosalesbennett.meetingsinmaine.com`, which was seen `1` times.
- The most common **Domains** was `meetingsinmaine.com`, which was seen `1` times.
- The most common **Country** was `Turkey`, which was seen `1` times.
- The most common **City** was `Istanbul`, which was seen `1` times.
- The most common **Organization** was `skyvds`, which was seen `1` times.
- The most common **ISP** was `Suleyman Furkan ARSLAN`, which was seen `1` times.
- The most common **ASN** was `AS211327`, which was seen `1` times.
- The most common **Operating System** was `Ubuntu`, which was seen `1` times.
- The IP address with the **most open ports** was `176.98.40.81` with `2` open ports.

| IP Addresss | # Open Ports | 22 | 80 |
| --- | --- | --- | --- |
| 176.98.40.81 | <details>`22`, `80`<summary>`2`</summary></details> | OpenSSH7.6p1 Ubuntu-4ubuntu0.7 | unknown |

<details>
<summary>
<h4>Top 2 Open Ports</h4>
</summary>

Total Open Ports: `2`
Unique: `2`

| Open Port | Times Seen |
| --- | --- |
| `22` | `1` |
| `80` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `2`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `tcp` | `2` |

</details>

---




<details>
<summary>
<h4>Top 2 Service Names</h4>
</summary>

Total Service Names: `2`
Unique: `2`

| Service Name | Times Seen |
| --- | --- |
| `OpenSSH7.6p1 Ubuntu-4ubuntu0.7` | `1` |
| `unknown` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Service Signatures</h4>
</summary>

Total Service Signatures: `2`
Unique: `2`

| Service Signature | Times Seen |
| --- | --- |
| `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7` | `1` |
| `HTTP/1.1 404 Not Found` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Hostnames</h4>
</summary>

Total Hostnamess: `1`
Unique: `1`

| Hostnames | Times Seen |
| --- | --- |
| `rosalesbennett.meetingsinmaine.com` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Domains</h4>
</summary>

Total Domainss: `1`
Unique: `1`

| Domains | Times Seen |
| --- | --- |
| `meetingsinmaine.com` | `1` |

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
| `Turkey` | `1` |

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
| `Istanbul` | `1` |

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
| `skyvds` | `1` |

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
| `Suleyman Furkan ARSLAN` | `1` |

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
| `AS211327` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Operating Systems</h4>
</summary>

Total Operating Systems: `1`
Unique: `1`

| Operating System | Times Seen |
| --- | --- |
| `Ubuntu` | `1` |

</details>

---


### Shodan Results

<details>
<summary>
<h3>Shodan results for: 176.98.40.81</h3>
</summary>


### Shodan results for: 176.98.40.81 [https://www.shodan.io/host/176.98.40.81](https://www.shodan.io/host/176.98.40.81)

| Hostnames | Domains | Country | City | Organization | ISP | ASN | Operating System |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rosalesbennett.meetingsinmaine.com | meetingsinmaine.com | Turkey | Istanbul | skyvds | Suleyman Furkan ARSLAN | AS211327 | Ubuntu |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH7.6p1 Ubuntu-4ubuntu0.7 | 2023-12-09T13:30:54.670857 |
| 80 | tcp | unknown | 2023-12-04T07:50:59.898313 |

#### Port 22 (tcp): OpenSSH7.6p1 Ubuntu-4ubuntu0.7

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH7.6p1 Ubuntu-4ubuntu0.7</h4>
</summary>


```
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQCqN41uJ+9Eprr43T4ZC7Cx5+LkL4A7xUlLRx4zYFv2tqzJ
o8IqMW+4v57he45yhqoJZRmPgpsdWu9dc1IoeVnT4j5tWt6S+r5f2e1C1RxO8NiOTqQLAw0Snrt5
MByaBI77EZgo95v8QsNsnCSXPnH/u0MBVdPEBERTcUatibIbnVkL2REynXxNrD78Ii0Xy/8e14sq
KY5gX6/2QGUqGZ/K2bcEPAnXxnButZrJa6z6PKrcFrRzvHBm5GEppNxW7x5XVZB4lN61iJXQWerS
RdVL9G5iAedk8Q4RNEHauyyj532TIBiDrrJfqJpAmxUt7Q8RXUiFRXYkeuwkShVp8raV
Fingerprint: 4b:26:2f:8e:45:b1:3c:ab:65:93:62:06:c1:86:1d:12

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
| sig | SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABAQCqN41uJ+9Eprr43T4ZC7Cx5+LkL4A7xUlLRx4zYFv2tqzJo8IqMW+4v57he45yhqoJZRmPgpsdWu9dc1IoeVnT4j5tWt6S+r5f2e1C1RxO8NiOTqQLAw0Snrt5MByaBI77EZgo95v8QsNsnCSXPnH/u0MBVdPEBERTcUatibIbnVkL2REynXxNrD78Ii0Xy/8e14sqKY5gX6/2QGUqGZ/K2bcEPAnXxnButZrJa6z6PKrcFrRzvHBm5GEppNxW7x5XVZB4lN61iJXQWerSRdVL9G5iAedk8Q4RNEHauyyj532TIBiDrrJfqJpAmxUt7Q8RXUiFRXYkeuwkShVp8raV |
| Fingerprint | 4b:26:2f:8e:45:b1:3c:ab:65:93:62:06:c1:86:1d:12 |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'] |
| Server Host Key Algorithms | ['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

#### Port 80 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 80 (tcp): unknown</h4>
</summary>


```
HTTP/1.1 404 Not Found
date: Mon, 04 Dec 2023 07:50:59 GMT
server: uvicorn
content-length: 22
content-type: application/json
```

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 404 Not Found |
| date | Mon, 04 Dec 2023 07:50:59 GMT |
| server | uvicorn |
| content-length | 22 |
| content-type | application/json |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
Using ThreatFox, it is known that the IP address `176.98.40.81` is associated with the Satori malware, which is a variant of elf.mirai. The malware was first detected by 360 Netlab on around November 27, 2017. Satori leverages an exploit to exhibit worm-like behavior, enabling it to spread across networks, specifically targeting vulnerabilities on ports 37215 and 52869 (CVE-2014-8361).

This information from ThreatFox correlates with the earlier mention of the 'SATORI' command in the attack data, suggesting that the attacker might have been attempting to use or spread the Satori malware, indicative of the threat this IP poses due to its association with known malware activity.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Based on data from the Internet Storm Center (ISC), the following is known about the IP address `176.98.40.81` involved in the attack:

- **Total Reports**: The IP address has been mentioned in 33 total reports.
- **Honeypots Targeted**: It has targeted 13 different honeypot sensors.
- **First Seen**: The first incident report involving this IP was recorded on December 7, 2023.
- **Last Seen**: The most recent activity was noted on December 12, 2023.
- **Network**: The network associated with this IP address is `176.98.40.0/24`.
- **Autonomous System Name (ASName)**: The IP operates under the ASName "SKYVDS."
- **AS Country Code**: The country code associated with this AS is "TR" (Turkey).

**ThreatFeeds**:
- The IP address has been listed on threat feeds, such as the **ciarmy** threat feed, with the last sighting on December 13, 2023, and the first sighting on December 9, 2023.

The ISC data suggests that the IP address `176.98.40.81` is known for targeting honeypots and has been active in attacker behaviors throughout early December 2023. Being listed in threat feeds corroborates its malicious nature and involvement in cybersecurity incidents. The consistent targeting of honeypots indicates that the IP address is potentially part of an automated scanning or attack operation.

* `1` of the `1` unique source IPs have reports on the Internet Storm Center (ISC).
* `33` total attacks were reported.
* `13` unique targets were attacked.
* The IP address with the **most reports** was `176.98.40.81` with `33` reports.
* The IP address with the **most targets** was `176.98.40.81` with `13` targets.
* The **first report** was on `2023-12-07` from `176.98.40.81`.
* The **most recent** was on `2023-12-12` from `176.98.40.81`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 176.98.40.81 | 33 | 13 | 2023-12-07 | 2023-12-12 | 2023-12-13 04:06:50 |

<details>
<summary>
<h4>Top 1 Asabusecontacts</h4>
</summary>

Total asabusecontacts: `1`
Unique: `1`

| asabusecontact | Times Seen |
| --- | --- |
| `info@fiberserver.net.tr` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 As</h4>
</summary>

Total ass: `1`
Unique: `1`

| as | Times Seen |
| --- | --- |
| `207508` | `1` |

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
| `SKYVDS` | `1` |

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
| `TR` | `1` |

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
| `1024` | `1` |

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
| `176.98.40.0/24` | `1` |

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
<h3>Whois data for: 176.98.40.81</h3>
</summary>


### Whois data for: 176.98.40.81 [https://www.whois.com/whois/176.98.40.81](https://www.whois.com/whois/176.98.40.81)

```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '176.98.40.0 - 176.98.40.255'

% Abuse contact for '176.98.40.0 - 176.98.40.255' is '@skyvds.com'

inetnum:        176.98.40.0 - 176.98.40.255
netname:        Skyvds
country:        TR
org:            ORG-SA4539-RIPE
admin-c:        SFA64-RIPE
tech-c:         SFA64-RIPE
mnt-domains:    tr-online-net-1-mnt
mnt-by:         tr-sercan-1-mnt
status:         SUB-ALLOCATED PA
mnt-by:         tr-online-net-1-mnt
created:        2018-09-04T05:20:43Z
last-modified:  2021-12-04T07:25:11Z
source:         RIPE

organisation:   ORG-SA4539-RIPE
org-name:       skyvds
org-type:       OTHER
address:        skyvds sokak
abuse-c:        SA40186-RIPE
mnt-ref:        tr-online-net-1-mnt
mnt-ref:        tr-sercan-1-mnt
mnt-by:         tr-sercan-1-mnt
mnt-by:         onlinenet-mnt
created:        2020-03-13T14:05:36Z
last-modified:  2020-11-24T08:47:29Z
source:         RIPE # Filtered

person:         Skyvds internet Hizmetleri
address:        Kartaltepe mahallesi mevlana sokak no:7/5
phone:          +905541407308
nic-hdl:        SFA64-RIPE
mnt-by:         tr-sercan-1-mnt
mnt-by:         onlinenet-mnt
created:        2020-03-12T09:27:22Z
last-modified:  2020-03-13T14:01:15Z
source:         RIPE # Filtered

% Information related to '176.98.40.0/24AS207508'

route:          176.98.40.0/24
origin:         AS207508
mnt-by:         tr-online-net-1-mnt
mnt-by:         onlinenet-mnt
created:        2023-04-03T09:48:30Z
last-modified:  2023-04-03T09:48:30Z
source:         RIPE

% Information related to '176.98.40.0/24AS43260'

route:          176.98.40.0/24
origin:         AS43260
mnt-by:         tr-online-net-1-mnt
mnt-by:         onlinenet-mnt
created:        2022-03-15T11:39:47Z
last-modified:  2022-03-15T11:39:47Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.109 (BUSA)
```

</details>

---


</details>

---

