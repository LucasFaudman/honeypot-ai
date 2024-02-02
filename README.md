
# honeypot-ai

#### A modular honeypot log analyzer and OSINT collector with OpenAI integration to easily create ISC style reports and interactively chat with AI about attacks. Currently supports Cowrie, DShield and Zeek logs. 
> Built by Lucas Faudman for SANS ISC/DShield

## Attack Examples

| Attack | AI Run Steps |
| --- | --- |
| [Unauthenticated Command Execution Attack Exploiting Vulnerable Netgear Devices from IP 178.72.69.244 for Malware Deployment](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Unauthenticated%20Command%20Execution%20Attack%20Exploiting%20Vulnerable%20Netgear%20Devices%20from%20IP%20178.72.69.244%20for%20Malware%20Deployment) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Unauthenticated%20Command%20Execution%20Attack%20Exploiting%20Vulnerable%20Netgear%20Devices%20from%20IP%20178.72.69.244%20for%20Malware%20Deployment/run-steps.md) |
| [Multi-Stage SSH Brute Force Attack with Possible Botnet Indications Launched from Compromised DigitalOcean Server](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Stage%20SSH%20Brute%20Force%20Attack%20with%20Possible%20Botnet%20Indications%20Launched%20from%20Compromised%20DigitalOcean%20Server) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Stage%20SSH%20Brute%20Force%20Attack%20with%20Possible%20Botnet%20Indications%20Launched%20from%20Compromised%20DigitalOcean%20Server/run-steps.md) |
| [Multi-Vector Cyber Attack Exploiting Shellshock and Targeting Apache Tomcat via Compromised IP Addresses](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Vector%20Cyber%20Attack%20Exploiting%20Shellshock%20and%20Targeting%20Apache%20Tomcat%20via%20Compromised%20IP%20Addresses) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Vector%20Cyber%20Attack%20Exploiting%20Shellshock%20and%20Targeting%20Apache%20Tomcat%20via%20Compromised%20IP%20Addresses/run-steps.md) |
| [Malicious IP 204.76.203.13: Unauthorized Access, Malware Deployment, and Persistence](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Malicious%20IP%20204.76.203.13%3A%20Unauthorized%20Access%2C%20Malware%20Deployment%2C%20and%20Persistence) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Malicious%20IP%20204.76.203.13%3A%20Unauthorized%20Access%2C%20Malware%20Deployment%2C%20and%20Persistence/run-steps.md) |
| [Telnet Compromise and Shell Script Malware Deployment on Linux Honeypot by Organized Attacker](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Telnet%20Compromise%20and%20Shell%20Script%20Malware%20Deployment%20on%20Linux%20Honeypot%20by%20Organized%20Attacker) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Telnet%20Compromise%20and%20Shell%20Script%20Malware%20Deployment%20on%20Linux%20Honeypot%20by%20Organized%20Attacker/run-steps.md) |

<details>
<summary>
<h2>Setup</h2>
</summary>


#### Step 1: Clone the Repository

```bash
git clone https://github.com/LucasFaudman/honeypot-ai
```

#### Step 2: Run the Setup Script [setup.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup.sh)

```bash
chmod +x honeypot-ai/setup.sh && honeypot-ai/setup.sh
```
> This will install all required packages in a virtual environment and walk you through setting up your config.json file. 

> You will need your honeypot IP and login credentials to create [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh) and [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh).

#### Optional: Install Zeek on your Honeypot using [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh)

```bash
honeypot-ai/install-zeek-on-honeypot.sh
```

#### Step 3: Sync Logs from Honeypot to local logs directory using [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh)

```bash
honeypot-ai/sync-logs.sh
```

#### Step 4: Run Honeypot-AI with --help to see all command line arguments and options.

```bash
honeypot-ai/run.sh --help
```

OR

```bash
python3 honeypot-ai/main.py --help
```

</details>

---


<details>
<summary>
<h2>Basic Usage</h2>
</summary>

> Load attacks from logs then list all attacks

```bash
honeypot-ai/run.sh --load-from-logs --list-attacks
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Load attacks from logs then list first 5 attacks sorted in descending order by number of commands, then start time. Then print the commands for each attack

```bash
honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Organize attacks with at most 10 source IPs into attack directories for faster loading and to prepare for storing analysis results

```bash
honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Load attacks from the attacks directory with at least 2 commands, or at least 5 HTTP requests then print the commands, malware, and HTTP requests for each attack

```bash
honeypot-ai/run.sh --load-from-attacks-dir --min-commands 2 --min-http-requests 5 --print-attrs commands malware http_requests
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Load only attacks with IDs XXXX and YYYY from the attacks directory then print the unique sessions and unique source IPs for each attack

```bash
honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --print-attrs uniq_sessions uniq_source_ips
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Analyze attack with ID XXXX using OpenAI and OSINT analyzers then write markdown and export to reports directory

```bash
honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write-markdown --export-report
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Enter chat mode to ask custom questions about attack with ID XXXX before analyzing, writing markdown, and exporting

```bash
honeypot-ai/run.sh -lfa --only-attack XXXX -AWE --chat
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Enter interactive Python shell to manually modify attacks before analyzing, writing markdown, and exporting

```bash
honeypot-ai/run.sh -lfa -AWE --interact
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Update config file with values from command line arguments

```bash
honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY
```

<details>
<summary>
Output
</summary>


```

```

</details>



</details>

---


<details>
<summary>
<h2>Advanced Usage</h2>
</summary>


### All Command Line Arguments

```bash
usage: main.py [-h] [--list-attacks] [--print-attrs ATTACK_ATTRS [ATTACK_ATTRS ...]] [--organize-attacks] [--analyze-attacks] [--chat] [--write-reports] [--export-reports] [--interactive] [--config FILE]
               [--update-config] [--load-from-logs] [--load-from-attacks-dir] [--only-attacks ATTACK_IDS [ATTACK_IDS ...]] [--skip-attacks ATTACK_IDS [ATTACK_IDS ...]] [--max-ips-per-attack MAX_IPS_PER_ATTACK]
               [--max-attacks MAX_ATTACKS] [--sort-attrs SORT_ATTRS [SORT_ATTRS ...]] [--sort-order SORT_ORDER] [--load-attacks-max-workers LOAD_ATTACKS_MAX_WORKERS] [--log-types LOG_TYPES [LOG_TYPES ...]]
               [--zeek-log-types ZEEK_LOG_TYPES [ZEEK_LOG_TYPES ...]] [--zeek-log-ext ZEEK_LOG_EXT] [--zeek-keep-empty-fields | --no-zeek-keep-empty-fields]
               [--zeek-keep-unset-fields | --no-zeek-keep-unset-fields] [--attack-min-commands ATTACK_MIN_COMMANDS] [--attack-min-malware ATTACK_MIN_MALWARE]
               [--attack-min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS] [--attack-min-http-requests ATTACK_MIN_HTTP_REQUESTS]
               [--attack-http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...]] [--attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]]
               [--standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]] [--standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]]
               [--standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]] [--merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]]
               [--merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]] [--merge-regex-malware MERGE_REGEX_MALWARE [MERGE_REGEX_MALWARE ...]]
               [--merge-regex-http-requests MERGE_REGEX_HTTP_REQUESTS [MERGE_REGEX_HTTP_REQUESTS ...]] [--organizer-overwrite | --no-organizer-overwrite | --overwrite | --no-overwrite]
               [--organizer-iterby ORGANIZER_ITERBY] [--organizer-concurrency-type ORGANIZER_CONCURRENCY_TYPE] [--organizer-max-workers ORGANIZER_MAX_WORKERS] [--organizer-chunksize ORGANIZER_CHUNKSIZE]
               [--organizer-yield-order ORGANIZER_YIELD_ORDER] [--organizer-ip-subdirs | --no-organizer-ip-subdirs | --ip-subdirs | --no-ip-subdirs] [--use-openai | --no-use-openai | --openai | --no-openai]
               [--use-openai-code-interpreter | --no-use-openai-code-interpreter | --openai-code-interpreter | --no-openai-code-interpreter] [--openai-api-key OPENAI_API_KEY] [--openai-model OPENAI_MODEL]
               [--openai-training-data-path OPENAI_TRAINING_DATA_PATH] [--use-ipanalyzer | --no-use-ipanalyzer | --ipanalyzer | --no-ipanalyzer]
               [--ipanalyzer-sources IPANALYZER_SOURCES [IPANALYZER_SOURCES ...]] [--ipanalyzer-max-errors IPANALYZER_MAX_ERRORS] [--webdriver-path WEBDRIVER_PATH] [--webdriver-type WEBDRIVER_TYPE]
               [--use-malwareanalyzer | --no-use-malwareanalyzer | --malwareanalyzer | --no-malwareanalyzer] [--malwareanalyzer-sources MALWAREANALYZER_SOURCES [MALWAREANALYZER_SOURCES ...]]
               [--malwareanalyzer-max-errors MALWAREANALYZER_MAX_ERRORS] [--malwareanalyzer-allow-downloads | --no-malwareanalyzer-allow-downloads] [--user-ips USER_IPS [USER_IPS ...]]
               [--honeypot-external-ips HONEYPOT_EXTERNAL_IPS [HONEYPOT_EXTERNAL_IPS ...]] [--honeypot-internal-ips HONEYPOT_INTERNAL_IPS [HONEYPOT_INTERNAL_IPS ...]]
               [--honeypot-ports HONEYPOT_PORTS [HONEYPOT_PORTS ...]] [--honeypot-software HONEYPOT_SOFTWARE [HONEYPOT_SOFTWARE ...]] [--logs-path LOGS_PATH] [--cowrie-logs-path COWRIE_LOGS_PATH]
               [--firewall-logs-path FIREWALL_LOGS_PATH] [--web-logs-path WEB_LOGS_PATH] [--zeek-logs-path ZEEK_LOGS_PATH] [--malware-downloads-path MALWARE_DOWNLOADS_PATH]
               [--auth-random-path AUTH_RANDOM_PATH] [--resources-path RESOURCES_PATH] [--attacks-path ATTACKS_PATH] [--db-path DB_PATH] [--ipdb-path IPDB_PATH] [--mwdb-path MWDB_PATH] [--aidb-path AIDB_PATH]
               [--reports-path REPORTS_PATH]

honeypot-ai: Honeypot Log Analyzer Built on OpenAI

options:
  -h, --help            show this help message and exit

Actions:
  Actions to perform on loaded attacks

  --list-attacks, --list, -L
                        List loaded attacks
  --print-attrs ATTACK_ATTRS [ATTACK_ATTRS ...], --print ATTACK_ATTRS [ATTACK_ATTRS ...], -P ATTACK_ATTRS [ATTACK_ATTRS ...]
                        Print specified attributes of loaded attacks
  --organize-attacks, --organize, -O
                        Organize attacks into attack directories
  --analyze-attacks, --analyze, -A
                        Analyze loaded attacks with OpenAI and OSINT Analyzers
  --chat, -C            Chat with the OpenAI Assistant about the loaded attacks
  --write-reports, --write, -W
                        Write markdown reports for analyzed attacks
  --export-reports, --export, -E
                        Export attack report and files to REPORTS_PATH
  --interactive, --interact, -I
                        Enter interactive mode after loading attacks (python shell with loaded attacks in the "ATTACKS" variable)

Config File:
  Config file to load settings from

  --config FILE, -c FILE
                        Path to config file
  --update-config, -u   Update config file with new values

Loading Attacks:
  Methods for loading attacks from logs or the attacks directory

  --load-from-logs, -lfl, -ll
                        Load attacks from logs
  --load-from-attacks-dir, -lfa, -la
                        Load attacks from attacks directory
  --only-attacks ATTACK_IDS [ATTACK_IDS ...]
                        Only load attacks with these keys
  --skip-attacks ATTACK_IDS [ATTACK_IDS ...]
                        Skip loading attacks with these keys
  --max-ips-per-attack MAX_IPS_PER_ATTACK
                        Maximum number of IPs in each loaded attack
  --max-attacks MAX_ATTACKS
                        Maximum number of attacks to load
  --sort-attrs SORT_ATTRS [SORT_ATTRS ...]
                        Order of attrs to sort attacks by (default: ['num_source_ips', 'num_sessions', 'num_commands', 'num_malware', 'num_http_requests'])
  --sort-order SORT_ORDER
                        Order to sort attacks by (asc or desc) (default: desc)
  --load-attacks-max-workers LOAD_ATTACKS_MAX_WORKERS
                        Maximum number of worker processes to use when loading attacks from the attacks directory (default: 2)

Log Types:
  Log types to process

  --log-types LOG_TYPES [LOG_TYPES ...]
                        Log types to process (default: ['cowrie', 'zeek'])
  --zeek-log-types ZEEK_LOG_TYPES [ZEEK_LOG_TYPES ...]
                        Zeek log types to process (default: ['http'])
  --zeek-log-ext ZEEK_LOG_EXT
                        Zeek log file extension (default: .log)
  --zeek-keep-empty-fields, --no-zeek-keep-empty-fields
                        Whether or not to keep empty fields in Zeek logs (default: True)
  --zeek-keep-unset-fields, --no-zeek-keep-unset-fields
                        Whether or not to keep unset fields in Zeek logs (default: False)
  --zeek-logs-path ZEEK_LOGS_PATH
                        Path to the zeek logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/zeek)

Attack Conditions:
  Conditions for determining which SourceIPs should be included in an Attack

  --attack-min-commands ATTACK_MIN_COMMANDS, --min-commands ATTACK_MIN_COMMANDS
                        Minimum number of commands used for SourceIP included in an Attack (default: 1)
  --attack-min-malware ATTACK_MIN_MALWARE, --min-malware ATTACK_MIN_MALWARE
                        Minimum number of malware files for SourceIP included in an Attack (default: 1)
  --attack-min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS, --min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS
                        Minimum number of successful logins for SourceIP included in an Attack (default: 1)
  --attack-min-http-requests ATTACK_MIN_HTTP_REQUESTS, --min-http-requests ATTACK_MIN_HTTP_REQUESTS
                        Minimum number of HTTP requests for SourceIP included in an Attack (default: 1)
  --attack-http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...], --http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...]
                        Regexes to match anywhere in the HTTP request URI that should be considered attacks (default:
                        ['(\\||\\$|\\`|;|\\-\\-|\\{|\\}|\\[|\\]|\\(|\\)|<|>|\\\\|\\^|\\~|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])
  --attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...], --http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]
                        Regexes to match anywhere in the HTTP request that should be considered attacks (default: ['(\\||\\$|\\`|\\{|\\}|<|>|\\\\[^n]|\\^|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])

Standardization Regexes:
  Regexes to match in commands, malware, and HTTP requests that should be standardized before hashing and comparing values. All captured groups will be replaced with X.

  --standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]
                        Regexes to match in commands that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['/bin/busybox (\\w+)',
                        '/tmp/([\\w\\d]+)', '/tmp/[\\w\\d]+ ([\\w/\\+]+)', '(\\d+\\.\\d+\\.\\d+\\.\\d+[:/]\\d+)'])
  --standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]
                        Regexes to match in malware that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['C0755 4745 (\\S+)'])
  --standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]
                        Regexes to match in HTTP requests that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: [])

Merge Conditions:
  Conditions for merging attacks

  --merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]
                        Attributes to automatically merge attacks on when any are shared (default: ['src_ips', 'malware', 'cmdlog_ips', 'cmdlog_urls', 'malware_ips', 'malware_urls'])
  --merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]
                        Regexes to match in commands of attacks that should be merged (default: [">\\??A@/ ?X'8ELFX", 'cat /proc/mounts; /bin/busybox [\\w\\d]+', 'cd /tmp && chmod \\+x [\\w\\d]+ && bash -c
                        ./[\\w\\d]+', 'cd ~; chattr -ia .ssh; lockr -ia .ssh'])
  --merge-regex-malware MERGE_REGEX_MALWARE [MERGE_REGEX_MALWARE ...]
                        Regexes to match in malware of attacks that should be merged (default: [])
  --merge-regex-http-requests MERGE_REGEX_HTTP_REQUESTS [MERGE_REGEX_HTTP_REQUESTS ...]
                        Regexes to match in HTTP requests of attacks that should be merged (default: ['GET /shell\\?cd\\+/tmp'])

Organizer Settings:
  Settings for organizing attacks into attack directories

  --organizer-overwrite, --no-organizer-overwrite, --overwrite, --no-overwrite
                        Whether or not to overwrite existing attack directories when organizing (default: True)
  --organizer-iterby ORGANIZER_ITERBY, --iterby ORGANIZER_ITERBY
                        How to iterate when organizing (logs or attacks) (default: logs)
  --organizer-concurrency-type ORGANIZER_CONCURRENCY_TYPE, --concurrency-type ORGANIZER_CONCURRENCY_TYPE
                        How to run organizing concurrently (processes or threads) (default: multiprocessing)
  --organizer-max-workers ORGANIZER_MAX_WORKERS, --max-workers ORGANIZER_MAX_WORKERS
                        Maximum number of workers (processes or threads) to use when organizing (default: None)
  --organizer-chunksize ORGANIZER_CHUNKSIZE, --chunksize ORGANIZER_CHUNKSIZE
                        Chunksize to use when organizing (default: 1)
  --organizer-yield-order ORGANIZER_YIELD_ORDER, --yield-order ORGANIZER_YIELD_ORDER
                        Order to yield results when organizing (as_completed or as_submitted) (default: as_completed)
  --organizer-ip-subdirs, --no-organizer-ip-subdirs, --ip-subdirs, --no-ip-subdirs
                        Whether or not to organize attacks into subdirectories by IP (default: False)

OpenAI Analyzer Settings:
  Settings for OpenAIAnalyzer

  --use-openai, --no-use-openai, --openai, --no-openai
                        Whether or not to run the OpenAIAnalyzer (default: True)
  --use-openai-code-interpreter, --no-use-openai-code-interpreter, --openai-code-interpreter, --no-openai-code-interpreter
                        Whether or not to use the OpenAI Code Interpreter (default: True)
  --openai-api-key OPENAI_API_KEY
                        OpenAI API Key (Get from https://platform.openai.com/api-keys) (default: <PASTE YOUR API KEY HERE>)
  --openai-model OPENAI_MODEL
                        OpenAI Model to use (Get from https://platform.openai.com/docs/models) (default: gpt-4-1106-preview)
  --openai-training-data-path OPENAI_TRAINING_DATA_PATH
                        Path to the openai-training-data directory (default: ./resources/openai-training-data)

IP Analyzer and Webdriver Settings:
  Settings for analyzing OSINT on IPs with IPAnalyzer and Selenium webdrivers

  --use-ipanalyzer, --no-use-ipanalyzer, --ipanalyzer, --no-ipanalyzer
                        Whether or not to run the IPAnalyzer (default: True)
  --ipanalyzer-sources IPANALYZER_SOURCES [IPANALYZER_SOURCES ...]
                        Sources to use for the IPAnalyzer (default: ['isc', 'whois', 'cybergordon', 'threatfox', 'shodan'])
  --ipanalyzer-max-errors IPANALYZER_MAX_ERRORS
                        Maximum number of errors allowed before a source is skipped (default: 5)
  --webdriver-path WEBDRIVER_PATH
                        Path to the webdriver executable for use with Selenium via SouperScraper (default: ./resources/chromedriver)
  --webdriver-type WEBDRIVER_TYPE
                        Type of webdriver executable for use with Selenium via SouperScraper (chrome, firefox, edge, safari, etc.) (default: chrome)

Malware Analyzer Settings:
  Settings for analyzing OSINT on malware samples with MalwareAnalyzer

  --use-malwareanalyzer, --no-use-malwareanalyzer, --malwareanalyzer, --no-malwareanalyzer
                        Whether or not to run the MalwareAnalyzer (default: True)
  --malwareanalyzer-sources MALWAREANALYZER_SOURCES [MALWAREANALYZER_SOURCES ...]
                        Sources to use for the MalwareAnalyzer (default: ['exploitdb', 'malpedia', 'malwarebazaar', 'threatfox', 'urlhaus'])
  --malwareanalyzer-max-errors MALWAREANALYZER_MAX_ERRORS
                        Maximum number of errors allowed before a source is skipped (default: 5)
  --malwareanalyzer-allow-downloads, --no-malwareanalyzer-allow-downloads
                        Weather or not to malware analyzer to attempt to download failed malware samples from Urlhaus (default: False)

User and Honeypot Environment Settings:
  Settings specific to the user and honeypot environment

  --user-ips USER_IPS [USER_IPS ...]
                        IPs that belong to the user to be excluded from analysis (default: [])
  --honeypot-external-ips HONEYPOT_EXTERNAL_IPS [HONEYPOT_EXTERNAL_IPS ...]
                        External IPs of the honeypot system(s) to inform AI for more accurate analysis (default: [])
  --honeypot-internal-ips HONEYPOT_INTERNAL_IPS [HONEYPOT_INTERNAL_IPS ...]
                        Interal IPs of the honeypot system(s) to inform AI for more accurate analysis (default: [])
  --honeypot-ports HONEYPOT_PORTS [HONEYPOT_PORTS ...]
                        Open ports of on honeypot system(s) to inform AI for more accurate analysis (default: [22, 23, 80, 2222, 2223, 2323, 5555, 7547, 8000, 8080, 9000])
  --honeypot-software HONEYPOT_SOFTWARE [HONEYPOT_SOFTWARE ...]
                        Version strings of the software running on each open port of the honeypot system(s) to inform AI for more accurate analysis. (default: ['Cowrie SSH server running OpenSSH 6.0p1 Debian
                        4+deb7u2 (protocol 2.0)', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)',
                        'Cowrie Telnet server', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server
                        running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7'])

Input Paths:
  Paths to input logs and files

  --logs-path LOGS_PATH
                        Path to the logs directory (default: ./logs)
  --cowrie-logs-path COWRIE_LOGS_PATH
                        Path to the cowrie logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/cowrie)
  --firewall-logs-path FIREWALL_LOGS_PATH
                        Path to the firewall logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/firewall)
  --web-logs-path WEB_LOGS_PATH
                        Path to the web logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/web)
  --malware-downloads-path MALWARE_DOWNLOADS_PATH
                        Path to the malware downloads directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/malware/downloads)
  --auth-random-path AUTH_RANDOM_PATH
                        Path to the auth_random.json file (Should be a subdirectory of LOGS_PATH) (default: ./logs/auth_random.json)
  --resources-path RESOURCES_PATH
                        Path to the resources directory (default: ./resources)

Output Paths:
  Paths to output files and directories

  --attacks-path ATTACKS_PATH
                        Path to the attacks directory where Attack data will be stored and loaded from (default: ./attacks)
  --db-path DB_PATH     Path to the db directory where IP, Malware, and OpenAI data will be stored and loaded from (default: ./db)
  --ipdb-path IPDB_PATH
                        Path to the ipdb directory where IP data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/ipdb)
  --mwdb-path MWDB_PATH
                        Path to the mwdb directory where Malware data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/mwdb)
  --aidb-path AIDB_PATH
                        Path to the aidb directory where OpenAI data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/aidb)
  --reports-path REPORTS_PATH
                        Path to the reports directory where attack markdown reports and files will be exported too (default: ./reports)

```
> For more advanced usage see comments in the source code and/or edit DEFAULT_CONFIG in [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/main.py).

</details>

---


<details>
<summary>
<h2>Default Config</h2>
</summary>


```python
{'SORT_ATTRS': ['num_source_ips',
                'num_sessions',
                'num_commands',
                'num_malware',
                'num_http_requests'],
 'SORT_ORDER': 'desc',
 'LOAD_ATTACKS_MAX_WORKERS': 2,
 'LOG_TYPES': ['cowrie', 'zeek'],
 'ZEEK_LOG_TYPES': ['http'],
 'ZEEK_LOG_EXT': '.log',
 'ZEEK_KEEP_EMPTY_FIELDS': True,
 'ZEEK_KEEP_UNSET_FIELDS': False,
 'ATTACK_MIN_COMMANDS': 1,
 'ATTACK_MIN_MALWARE': 1,
 'ATTACK_MIN_SUCCESSFUL_LOGINS': 1,
 'ATTACK_MIN_HTTP_REQUESTS': 1,
 'ATTACK_HTTP_URI_REGEXES': ['(\\||\\$|\\`|;|\\-\\-|\\{|\\}|\\[|\\]|\\(|\\)|<|>|\\\\|\\^|\\~|\\!|\\$?\\{?IFS\\}?|\\.\\/)'],
 'ATTACK_HTTP_ANYWHERE_REGEXES': ['(\\||\\$|\\`|\\{|\\}|<|>|\\\\[^n]|\\^|\\!|\\$?\\{?IFS\\}?|\\.\\/)'],
 'STANDARDIZE_REGEX_COMMANDS': ['/bin/busybox (\\w+)',
                                '/tmp/([\\w\\d]+)',
                                '/tmp/[\\w\\d]+ ([\\w/\\+]+)',
                                '(\\d+\\.\\d+\\.\\d+\\.\\d+[:/]\\d+)'],
 'STANDARDIZE_REGEX_MALWARE': ['C0755 4745 (\\S+)'],
 'STANDARDIZE_REGEX_HTTP_REQUESTS': [],
 'MERGE_SHARED_ATTRS': ['src_ips',
                        'malware',
                        'cmdlog_ips',
                        'cmdlog_urls',
                        'malware_ips',
                        'malware_urls'],
 'MERGE_REGEX_COMMANDS': [">\\??A@/ ?X'8ELFX",
                          'cat /proc/mounts; /bin/busybox [\\w\\d]+',
                          'cd /tmp && chmod \\+x [\\w\\d]+ && bash -c '
                          './[\\w\\d]+',
                          'cd ~; chattr -ia .ssh; lockr -ia .ssh'],
 'MERGE_REGEX_MALWARE': [],
 'MERGE_REGEX_HTTP_REQUESTS': ['GET /shell\\?cd\\+/tmp'],
 'ORGANIZER_OVERWRITE': True,
 'ORGANIZER_ITERBY': 'logs',
 'ORGANIZER_CONCURRENCY_TYPE': 'multiprocessing',
 'ORGANIZER_MAX_WORKERS': None,
 'ORGANIZER_CHUNKSIZE': 1,
 'ORGANIZER_YIELD_ORDER': 'as_completed',
 'ORGANIZER_IP_SUBDIRS': False,
 'USE_OPENAI': True,
 'USE_OPENAI_CODE_INTERPRETER': True,
 'OPENAI_API_KEY': '<PASTE YOUR API KEY HERE>',
 'OPENAI_MODEL': 'gpt-4-1106-preview',
 'OPENAI_TRAINING_DATA_PATH': './resources/openai-training-data',
 'USE_IPANALYZER': True,
 'IPANALYZER_SOURCES': ['isc', 'whois', 'cybergordon', 'threatfox', 'shodan'],
 'IPANALYZER_MAX_ERRORS': 5,
 'WEBDRIVER_PATH': './resources/chromedriver',
 'WEBDRIVER_TYPE': 'chrome',
 'USE_MALWAREANALYZER': True,
 'MALWAREANALYZER_SOURCES': ['exploitdb',
                             'malpedia',
                             'malwarebazaar',
                             'threatfox',
                             'urlhaus'],
 'MALWAREANALYZER_MAX_ERRORS': 5,
 'MALWAREANALYZER_ALLOW_DOWNLOADS': False,
 'USER_IPS': [],
 'HONEYPOT_EXTERNAL_IPS': [],
 'HONEYPOT_INTERNAL_IPS': [],
 'HONEYPOT_PORTS': [22, 23, 80, 2222, 2223, 2323, 5555, 7547, 8000, 8080, 9000],
 'HONEYPOT_SOFTWARE': ['Cowrie SSH server running OpenSSH 6.0p1 Debian '
                       '4+deb7u2 (protocol 2.0)',
                       'Cowrie Telnet server',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Cowrie SSH server running OpenSSH 6.0p1 Debian '
                       '4+deb7u2 (protocol 2.0)',
                       'Cowrie Telnet server',
                       'Cowrie Telnet server',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7'],
 'LOGS_PATH': './logs',
 'COWRIE_LOGS_PATH': './logs/cowrie',
 'FIREWALL_LOGS_PATH': './logs/firewall',
 'WEB_LOGS_PATH': './logs/web',
 'ZEEK_LOGS_PATH': './logs/zeek',
 'MALWARE_DOWNLOADS_PATH': './logs/malware/downloads',
 'AUTH_RANDOM_PATH': './logs/auth_random.json',
 'RESOURCES_PATH': './resources',
 'ATTACKS_PATH': './attacks',
 'DB_PATH': './db',
 'IPDB_PATH': './db/ipdb',
 'MWDB_PATH': './db/mwdb',
 'AIDB_PATH': './db/aidb',
 'REPORTS_PATH': './reports'}

```

</details>

---


<details>
<summary>
<h2>Module Descriptions</h2>
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

