from analyzerbase import *
from loganalyzers import CowrieParser, WebLogParser, DshieldParser, ZeekParser, LogProcessor, AttackDirOrganizer, AttackDirReader
from osintanalyzers import IPAnalyzer, MalwareAnalyzer
from openaianalyzers import OpenAIAnalyzer
from markdownwriters import ReportMarkdownWriter, RunStepsMarkdownWriter, DocsMarkdownWriter
from attackanalyzer import AttackAnalyzer, DEFAULT_QUESTIONS

from shutil import copytree, rmtree
import argparse
import code


DEFAULT_CONFIG = {
    # Sort settings
    "SORT_ATTRS": ["num_source_ips", "num_sessions", "num_commands", "num_malware", "num_http_requests"], # Order of attrs to sort attacks by
    "SORT_ORDER": "desc", # Order to sort attacks by (asc or desc)
    "LOAD_ATTACKS_MAX_WORKERS": 2, # Maximum number of workers to use when loading attacks from the attacks directory

    # Log Types and Zeek Settings
    "LOG_TYPES": ["cowrie", "zeek"], # Log types to process
    "ZEEK_LOG_TYPES": ["http"], # Zeek log types to process
    "ZEEK_LOG_EXT": ".log", # Zeek log file extension
    "ZEEK_KEEP_EMPTY_FIELDS": True, # Whether or not to keep empty fields in Zeek logs
    "ZEEK_KEEP_UNSET_FIELDS": False, # Whether or not to keep unset fields in Zeek logs

    # LogProcessor Attack Conditions (Used to determine which SourceIPs should be included in an Attack)
    "ATTACK_MIN_COMMANDS": 1, # Minimum number of commands used for SourceIP included in an Attack
    "ATTACK_MIN_MALWARE": 1, # Minimum number of malware files for SourceIP included in an Attack
    "ATTACK_MIN_SUCCESSFUL_LOGINS": 1, # Minimum number of successful logins for SourceIP included in an Attack
    "ATTACK_MIN_HTTP_REQUESTS": 1, # Minimum number of HTTP requests for SourceIP included in an Attack
    "ATTACK_HTTP_URI_REGEXES": [ # Regexes to match anywhere in the URI that should be considered attacks
        r'(\||\$|\`|;|\-\-|\{|\}|\[|\]|\(|\)|<|>|\\|\^|\~|\!|\$?\{?IFS\}?|\.\/)',
    ],
    "ATTACK_HTTP_ANYWHERE_REGEXES": [ # Regexes to match anywhere in the HTTP request that should be considered attacks
        r'(\||\$|\`|\{|\}|<|>|\\[^n]|\^|\!|\$?\{?IFS\}?|\.\/)',
    ],

    # Command Malware and HTTP Request Standardization Regexes
    "STANDARDIZE_REGEX_COMMANDS": [ # Regexes to match in commands that should be standardized before hashing. All captured groups will be replaced with X before hashing.
        r"/bin/busybox (\w+)",
        r"/tmp/([\w\d]+)",
        r"/tmp/[\w\d]+ ([\w/\+]+)",
        r"(\d+\.\d+\.\d+\.\d+[:/]\d+)",
    ],
    "STANDARDIZE_REGEX_MALWARE": [ # Regexes to match in malware that should be standardized before hashing. All captured groups will be replaced with X before hashing.
        r"C0755 4745 (\S+)",
    ],
    "STANDARDIZE_REGEX_HTTP_REQUESTS": [], # Regexes to match in HTTP requests that should be standardized before hashing. All captured groups will be replaced with X before hashing.
    

    # LogProcessor Attack Merge Conditions
    "MERGE_SHARED_ATTRS": [ # Attributes to automatically merge attacks on when any are shared 
        "src_ips", "malware", "cmdlog_ips", "cmdlog_urls", "malware_ips", "malware_urls",
    ],  
    "MERGE_REGEX_COMMANDS": [ # Regexes to match in commands of attacks that should be merged
        r">\??A@/ ?X'8ELFX",
        r"cat /proc/mounts; /bin/busybox [\w\d]+",
        r"cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+",
        r"cd ~; chattr -ia .ssh; lockr -ia .ssh",
    ],
    'MERGE_REGEX_MALWARE': [], # Regexes to match in malware of attacks that should be merged
    "MERGE_REGEX_HTTP_REQUESTS": [
        r'GET /shell\?cd\+/tmp',

    ], # Regexes to match in HTTP requests of attacks that should be merged

    # Oranizer Settings
    "ORGANIZER_OVERWRITE": True, # Whether or not to overwrite existing attack directories when organizing
    "ORGANIZER_ITERBY": "logs", # How to iterate when organizing (logs or attacks)
    "ORGANIZER_CONCURRENCY_TYPE": "multiprocessing", # How to run organizing concurrently (processes or threads)
    "ORGANIZER_MAX_WORKERS": None, # Maximum number of workers (processes or threads) to use when organizing
    "ORGANIZER_CHUNKSIZE": 1, # Chunksize to use when organizing
    "ORGANIZER_YIELD_ORDER": "as_completed", # Order to yield results when organizing (as_completed or as_submitted)
    "ORGANIZER_IP_SUBDIRS": False, # Whether or not to organize attacks into subdirectories by IP

    # OpenAI Settings
    "USE_OPENAI": True, # Whether or not to run the OpenAIAnalyzer
    "USE_OPENAI_CODE_INTERPRETER": True, # Whether or not to use the OpenAI Code Interpreter
    "OPENAI_API_KEY": "<PASTE YOUR API KEY HERE>", # OpenAI API Key (Get from https://platform.openai.com/api-keys)
    "OPENAI_MODEL": "gpt-4-1106-preview", # OpenAI Model to use (Get from https://platform.openai.com/docs/models)
    "OPENAI_TRAINING_DATA_PATH": "./honeypot-ai/resources/openai-training-data", # Path to the openai-training-data directory

    # IPAnalyzer and Webdriver Settings
    "USE_IPANALYZER": True, # Whether or not to run the IPAnalyzer
    "IPANALYZER_SOURCES": [ "isc", "whois", "cybergordon", "threatfox", "shodan" ], # Sources to use for the IPAnalyzer
    "IPANALYZER_MAX_ERRORS": 5, # Maximum number of errors allowed before a source is skipped
    "WEBDRIVER_PATH": "./resources/chromedriver", # Path to the webdriver executable for use with Selenium via SouperScraper 
    "WEBDRIVER_TYPE": "chrome", # Type of webdriver executable for use with Selenium via SouperScraper (chrome, firefox, edge, safari, etc.)    

    # MalwareAnalyzer Settings
    "USE_MALWAREANALYZER": True, # Whether or not to run the MalwareAnalyzer
    "MALWAREANALYZER_SOURCES": [ "exploitdb", "malpedia", "malwarebazaar", "threatfox", "urlhaus" ], # Sources to use for the MalwareAnalyzer
    "MALWAREANALYZER_MAX_ERRORS": 5, # Maximum number of errors allowed before a source is skipped
    "MALWAREANALYZER_ALLOW_DOWNLOADS": False, # Weather or not to malware analyzer to attempt to download failed malware samples from Urlhaus

    # User and Honeypot Environment Settings
    "USER_IPS": [], #IPs that belong to the user to be excluded from analysis
    "HONEYPOT_EXTERNAL_IPS": [], # External IPs of the honeypot system(s) to inform AI for more accurate analysis
    "HONEYPOT_INTERNAL_IPS": [], # Interal IPs of the honeypot system(s) to inform AI for more accurate analysis
    "HONEYPOT_PORTS": [22, 23, 80, 2222, 2223, 2323, 5555, 7547, 8000, 8080, 9000], # Open ports of on honeypot system(s) to inform AI for more accurate analysis
    "HONEYPOT_SOFTWARE": [  # Version strings of the software running on each open port of the honeypot system(s) to inform AI for more accurate analysis.
        "Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)",
        "Cowrie Telnet server",
        "Web server running Apache httpd 3.2.3 and WordPress 5.6.7",
        "Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)",
    ] + ["Cowrie Telnet server"] * 2 + ["Web server running Apache httpd 3.2.3 and WordPress 5.6.7"] * 5,

    # Input Paths    
    "LOGS_PATH": "./logs", # Path to the logs directory
    "COWRIE_LOGS_PATH": "./logs/cowrie", # Path to the cowrie logs directory (Should be a subdirectory of LOGS_PATH)
    "FIREWALL_LOGS_PATH": "./logs/firewall", # Path to the firewall logs directory (Should be a subdirectory of LOGS_PATH)
    "WEB_LOGS_PATH": "./logs/web", # Path to the web logs directory (Should be a subdirectory of LOGS_PATH)
    "ZEEK_LOGS_PATH": "./logs/zeek", # Path to the zeek logs directory (Should be a subdirectory of LOGS_PATH)
    "MALWARE_DOWNLOADS_PATH": "./logs/malware/downloads", # Path to the malware downloads directory (Should be a subdirectory of LOGS_PATH)
    "AUTH_RANDOM_PATH": "./logs/auth_random.json", # Path to the auth_random.json file (Should be a subdirectory of LOGS_PATH)
    #Resource Paths
    "RESOURCES_PATH": "./resources", # Path to the resources directory


    # Output Paths
    "ATTACKS_PATH": "./attacks", # Path to the attacks directory where Attack data will be stored and loaded from 
    "DB_PATH": "./db", # Path to the db directory where IP, Malware, and OpenAI data will be stored and loaded from
    "IPDB_PATH": "./db/ipdb", # Path to the ipdb directory where IP data will be stored and loaded from (Should be a subdirectory of DB_PATH)
    "MWDB_PATH": "./db/mwdb", # Path to the mwdb directory where Malware data will be stored and loaded from (Should be a subdirectory of DB_PATH)
    "AIDB_PATH": "./db/aidb", # Path to the aidb directory where OpenAI data will be stored and loaded from (Should be a subdirectory of DB_PATH)
    "REPORTS_PATH": "./reports", # Path to the reports directory where attack markdown reports and files will be exported too

}

ARG_DESCRIPTIONS = {
    # Sort settings
    "SORT_ATTRS": "Order of attrs to sort attacks by",
    "SORT_ORDER": "Order to sort attacks by (asc or desc)",
    "LOAD_ATTACKS_MAX_WORKERS": "Maximum number of worker processes to use when loading attacks from the attacks directory",

    # Log Types and Zeek Settings
    "LOG_TYPES": "Log types to process",
    "ZEEK_LOG_TYPES": "Zeek log types to process",
    "ZEEK_LOG_EXT": "Zeek log file extension",
    "ZEEK_KEEP_UNSET_FIELDS": "Whether or not to keep unset fields in Zeek logs",
    "ZEEK_KEEP_EMPTY_FIELDS": "Whether or not to keep empty fields in Zeek logs",

    # LogProcessor Attack Conditions (Used to determine which SourceIPs should be included in an Attack)
    "ATTACK_MIN_COMMANDS": "Minimum number of commands used for SourceIP included in an Attack",
    "ATTACK_MIN_MALWARE": "Minimum number of malware files for SourceIP included in an Attack",
    "ATTACK_MIN_SUCCESSFUL_LOGINS": "Minimum number of successful logins for SourceIP included in an Attack",
    "ATTACK_MIN_HTTP_REQUESTS": "Minimum number of HTTP requests for SourceIP included in an Attack",
    "ATTACK_HTTP_URI_REGEXES": "Regexes to match anywhere in the HTTP request URI that should be considered attacks",
    "ATTACK_HTTP_ANYWHERE_REGEXES": "Regexes to match anywhere in the HTTP request that should be considered attacks",

    # Command Malware and HTTP Request Standardization Regexes
    "STANDARDIZE_REGEX_COMMANDS": "Regexes to match in commands that should be standardized before hashing. All captured groups will be replaced with X before hashing.",
    "STANDARDIZE_REGEX_MALWARE": "Regexes to match in malware that should be standardized before hashing. All captured groups will be replaced with X before hashing.",
    "STANDARDIZE_REGEX_HTTP_REQUESTS": "Regexes to match in HTTP requests that should be standardized before hashing. All captured groups will be replaced with X before hashing.",

    # LogProcessor Merge Conditions
    "MERGE_SHARED_ATTRS": "Attributes to automatically merge attacks on when any are shared", 
    "MERGE_REGEX_COMMANDS": "Regexes to match in commands of attacks that should be merged",
    "MERGE_REGEX_MALWARE": "Regexes to match in malware of attacks that should be merged",
    "MERGE_REGEX_HTTP_REQUESTS": "Regexes to match in HTTP requests of attacks that should be merged",

    # Oranizer Settings
    "ORGANIZER_OVERWRITE": "Whether or not to overwrite existing attack directories when organizing",
    "ORGANIZER_ITERBY": "How to iterate when organizing (logs or attacks)",
    "ORGANIZER_CONCURRENCY_TYPE": "How to run organizing concurrently (processes or threads)",
    "ORGANIZER_MAX_WORKERS": "Maximum number of workers (processes or threads) to use when organizing",
    "ORGANIZER_CHUNKSIZE": "Chunksize to use when organizing",
    "ORGANIZER_YIELD_ORDER": "Order to yield results when organizing (as_completed or as_submitted)",
    "ORGANIZER_IP_SUBDIRS": "Whether or not to organize attacks into subdirectories by IP",
    
    # OpenAI Settings
    "USE_OPENAI": "Whether or not to run the OpenAIAnalyzer",
    "USE_OPENAI_CODE_INTERPRETER": "Whether or not to use the OpenAI Code Interpreter",
    "OPENAI_API_KEY": "OpenAI API Key (Get from https://platform.openai.com/api-keys)",
    "OPENAI_MODEL": "OpenAI Model to use (Get from https://platform.openai.com/docs/models)",
    "OPENAI_TRAINING_DATA_PATH": "Path to the openai-training-data directory",

    # IPAnalyzer and Webdriver Settings
    "USE_IPANALYZER": "Whether or not to run the IPAnalyzer",
    "IPANALYZER_SOURCES": "Sources to use for the IPAnalyzer",
    "IPANALYZER_MAX_ERRORS": "Maximum number of errors allowed before a source is skipped",
    "WEBDRIVER_PATH": "Path to the webdriver executable for use with Selenium via SouperScraper",
    "WEBDRIVER_TYPE": "Type of webdriver executable for use with Selenium via SouperScraper (chrome, firefox, edge, safari, etc.)",

    # MalwareAnalyzer Settings
    "USE_MALWAREANALYZER": "Whether or not to run the MalwareAnalyzer",
    "MALWAREANALYZER_SOURCES": "Sources to use for the MalwareAnalyzer",
    "MALWAREANALYZER_MAX_ERRORS": "Maximum number of errors allowed before a source is skipped",
    "MALWAREANALYZER_ALLOW_DOWNLOADS": "Weather or not to malware analyzer to attempt to download failed malware samples from Urlhaus",

    # User and Honeypot Environment Settings    
    "USER_IPS": "IPs that belong to the user to be excluded from analysis",
    "HONEYPOT_EXTERNAL_IPS": "External IPs of the honeypot system(s) to inform AI for more accurate analysis",
    "HONEYPOT_INTERNAL_IPS": "Interal IPs of the honeypot system(s) to inform AI for more accurate analysis",
    "HONEYPOT_PORTS": "Open ports of on honeypot system(s) to inform AI for more accurate analysis",
    "HONEYPOT_SOFTWARE": "Version strings of the software running on each open port of the honeypot system(s) to inform AI for more accurate analysis.",

    # Input Paths    
    "LOGS_PATH": "Path to the logs directory",
    "COWRIE_LOGS_PATH": "Path to the cowrie logs directory (Should be a subdirectory of LOGS_PATH)",
    "FIREWALL_LOGS_PATH": "Path to the firewall logs directory (Should be a subdirectory of LOGS_PATH)",
    "WEB_LOGS_PATH": "Path to the web logs directory (Should be a subdirectory of LOGS_PATH)",
    "ZEEK_LOGS_PATH": "Path to the zeek logs directory (Should be a subdirectory of LOGS_PATH)",
    "MALWARE_DOWNLOADS_PATH": "Path to the malware downloads directory (Should be a subdirectory of LOGS_PATH)",
    "AUTH_RANDOM_PATH": "Path to the auth_random.json file (Should be a subdirectory of LOGS_PATH)",
    
    # Output Paths
    "ATTACKS_PATH": "Path to the attacks directory where Attack data will be stored and loaded from",
    "DB_PATH": "Path to the db directory where IP, Malware, and OpenAI data will be stored and loaded from",
    "IPDB_PATH": "Path to the ipdb directory where IP data will be stored and loaded from (Should be a subdirectory of DB_PATH)",
    "MWDB_PATH": "Path to the mwdb directory where Malware data will be stored and loaded from (Should be a subdirectory of DB_PATH)",
    "AIDB_PATH": "Path to the aidb directory where OpenAI data will be stored and loaded from (Should be a subdirectory of DB_PATH)",
    "REPORTS_PATH": "Path to the reports directory where attack markdown reports and files will be exported too",

    # Resource Paths
    "RESOURCES_PATH": "Path to the resources directory",
}


ARG_GROUP_DESCRIPTIONS = {
    "Actions": "Actions to perform on loaded attacks",
    "Config File": "Config file to load settings from",
    "Loading Attacks": "Methods for loading attacks from logs or the attacks directory",    
    "Log Types": "Log types to process",
    "Attack Conditions": "Conditions for determining which SourceIPs should be included in an Attack",
    "Standardization Regexes": "Regexes to match in commands, malware, and HTTP requests that should be standardized before hashing and comparing values. All captured groups will be replaced with X.",
    "Merge Conditions": "Conditions for merging attacks",
    "Organizer Settings": "Settings for organizing attacks into attack directories",
    "OpenAI Analyzer Settings": "Settings for OpenAIAnalyzer",
    "IP Analyzer and Webdriver Settings": "Settings for analyzing OSINT on IPs with IPAnalyzer and Selenium webdrivers",
    "Malware Analyzer Settings": "Settings for analyzing OSINT on malware samples with MalwareAnalyzer",
    "User and Honeypot Environment Settings": "Settings specific to the user and honeypot environment",
    "Input Paths": "Paths to input logs and files",
    "Output Paths": "Paths to output files and directories",
    # "Resource Paths": "Paths to resources",
}

def config_arg_parser():
    parser = argparse.ArgumentParser(description='honeypot-ai: Honeypot Log Analyzer Built on OpenAI')
    
    # Create argument groups for each section of arguments
    groups = {
       title: parser.add_argument_group(title, description) for title, description in ARG_GROUP_DESCRIPTIONS.items()
    }

    # Add arguments to each group
    
    groups['Actions'].add_argument('--list-attacks', '--list', '-L', action='store_true', help='List loaded attacks')
    groups['Actions'].add_argument('--print-attrs', '--print', '-P', metavar='ATTACK_ATTRS', type=str, nargs='+', action='extend', help='Print specified attributes of loaded attacks')
    groups['Actions'].add_argument('--organize-attacks', '--organize', '-O', action='store_true', help='Organize attacks into attack directories')
    groups['Actions'].add_argument('--analyze-attacks', '--analyze', '-A', action='store_true', help='Analyze loaded attacks with OpenAI and OSINT Analyzers')
    groups["Actions"].add_argument("--chat", "-C", action="store_true", help="Chat with the OpenAI Assistant about the loaded attacks")
    groups['Actions'].add_argument('--write-reports', '--write', '-W', action='store_true', help='Write markdown reports for analyzed attacks')
    groups["Actions"].add_argument('--export-reports', '--export', '-E', action='store_true', help='Export attack report and files to REPORTS_PATH')
    groups["Actions"].add_argument('--interactive', '--interact', '-I', action='store_true', help='Enter interactive mode after loading attacks (python shell with loaded attacks in the "ATTACKS" variable)')

    groups['Config File'].add_argument('--config', '-c', metavar="FILE", type=str, default='config.json', help='Path to config file')
    groups['Config File'].add_argument('--update-config', '-u', action='store_true', help='Update config file with new values')
    
    groups["Loading Attacks"].add_argument('--load-from-logs', '-lfl', '-ll', action='store_true', help='Load attacks from logs')
    groups["Loading Attacks"].add_argument('--load-from-attacks-dir', '-lfa', '-la', action='store_true', help='Load attacks from attacks directory')
    groups["Loading Attacks"].add_argument('--only-attacks', metavar='ATTACK_IDS', type=str, nargs='+', default=None, help='Only load attacks with these keys')
    groups["Loading Attacks"].add_argument('--skip-attacks', metavar='ATTACK_IDS', type=str, nargs='+', default=None, help='Skip loading attacks with these keys')
    groups["Loading Attacks"].add_argument('--max-ips-per-attack', type=int, default=None, help='Maximum number of IPs in each loaded attack')
    groups["Loading Attacks"].add_argument('--max-attacks', type=int, default=None, help='Maximum number of attacks to load')
    

    # Add arguments for each config option to parser in the appropriate group
    for key, value in DEFAULT_CONFIG.items():
        group_name = ""
        if key.startswith("LOAD_") or key.startswith("SORT_"):
            group_name = "Loading Attacks"
        elif key == "LOG_TYPES" or key.startswith("ZEEK_"):
            group_name = "Log Types"
        elif key.startswith("ATTACK_"):
            group_name = "Attack Conditions"    
        elif key.startswith("STANDARDIZE_"):
            group_name = "Standardization Regexes"
        elif key.startswith("MERGE_"):
            group_name = "Merge Conditions"            
        elif key.startswith("ORGANIZER_"):
            group_name = "Organizer Settings"            
        elif "OPENAI" in key:
            group_name = "OpenAI Analyzer Settings"            
        elif "IPANALYZER" in key or key.startswith("WEBDRIVER_"):
            group_name = "IP Analyzer and Webdriver Settings"            
        elif "MALWAREANALYZER" in key:
            group_name = "Malware Analyzer Settings"         
        elif key.startswith("USER_") or key.startswith("HONEYPOT_"):
            group_name = "User and Honeypot Environment Settings"               
        elif "DB_PATH" in key or key == "ATTACKS_PATH" or key == "REPORTS_PATH":
            group_name = "Output Paths"
        elif "S_PATH" in key or key == "AUTH_RANDOM_PATH":
            group_name = "Input Paths"


        # arg_name is lowercase with dashes instead of underscores
        arg_names = [f'--{key.lower().replace("_", "-")}']
        if any(key.startswith(key_preix) for key_preix in ("USE_", "ATTACK_", "ORGANIZER_")):
            arg_names.append(f"--{'-'.join(key.lower().split('_')[1:])}")

        # Dict of kwargs for argparse .add_argument method
        add_argument_kwargs = {
            "type": type(value),
            "help": f"{ARG_DESCRIPTIONS[key]} (default: {value})",
            "required": False,
        }

        if isinstance(value, (list, dict)):
            add_argument_kwargs["type"] = type(value[0]) if len(value) > 0 else str
            add_argument_kwargs["nargs"] = "+"
            add_argument_kwargs["action"] = "extend"
            add_argument_kwargs["default"] = None

        if isinstance(value, bool):
            add_argument_kwargs["action"] = argparse.BooleanOptionalAction
            add_argument_kwargs["default"] = value

        # Add argument to parser via groups[group_name] or to parser if not in a group
        groups.get(group_name, parser).add_argument(*arg_names, **add_argument_kwargs)

    return parser


def main(test_args=None):
    print("Starting honeypot-ai...\n")
    
    # Parse args
    parser = config_arg_parser()
    args = parser.parse_args(args=test_args.split() if test_args else None)
    
    # Set initial config to copy of default config
    config = DEFAULT_CONFIG.copy()

    # Update config with values from config file if --config flag is set
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config.update({k:v for k,v in json.load(f).items() if k in config})
        except Exception as e:
            if isinstance(e, FileNotFoundError):
                print(f"Creating new config file at {args.config}")
                # Set update_config flag to True so that it will be created after applying args to DEFAULT_CONFIG
                args.update_config = True
            else:
                print(f"Error loading config file at {args.config}\n{e}")
                exit(1)

    # Update config with values from args (args take precedence over config file)
    # checks arg is set, the key a valid key and that value is not the current config value (needs to be updated)
    config.update({k.upper(): v for k,v in vars(args).items() 
                   if v != None # Not an unset arg (Note: config values cannot be set to None on the command line but can be by editing the config file.)
                   and v != config.get(k.upper(), v) # Not the same as the value in the config file
                   and k.upper() in DEFAULT_CONFIG # A valid key
                   })
    

    # Update config file with values from args if --update-config flag is set
    if args.update_config:
        with open(args.config, 'w+') as f:
            json.dump(config, f, indent=4)
        print(f"Updated config file at {args.config}")


    # Setup Path Objects
    for key, value in config.items():
        if key.endswith("_PATH"):
            config[key] = Path(value).expanduser().resolve()

    # Set class Path and regex attributes to config values
    Attack.ATTACKS_PATH = config["ATTACKS_PATH"]
    Malware.MALWARE_DOWNLOADS_PATH = config["MALWARE_DOWNLOADS_PATH"]
    
    # Compile and set class standardization regexes to config values
    Session.STANDARDIZE_REGEX_COMMANDS = list(map(re.compile, config["STANDARDIZE_REGEX_COMMANDS"]))
    Session.STANDARDIZE_REGEX_HTTP_REQUESTS = list(map(re.compile, config["STANDARDIZE_REGEX_HTTP_REQUESTS"]))
    Malware.STANDARDIZE_REGEX_MALWARE = [re.compile(regex.encode()) for regex in config["STANDARDIZE_REGEX_MALWARE"]]
    


    # Setup LogParsers
    LOG_PARSERS = []
    if config["LOG_TYPES"] == ["all"]:
        config["LOG_TYPES"] = ["cowrie", "firewall", "web", "zeek"]
    if config["LOG_TYPES"]:
        for log_type in set(config["LOG_TYPES"]):
            if config.get(f"{log_type.upper()}_LOGS_PATH"): 
                logs_path = config[f"{log_type.upper()}_LOGS_PATH"].parent
            else:
                logs_path = config["LOGS_PATH"]

            if log_type == "cowrie":
                LOG_PARSERS.append(CowrieParser(logs_path))
            elif log_type == "firewall":
                LOG_PARSERS.append(DshieldParser(logs_path))
            elif log_type == "web":
                LOG_PARSERS.append(WebLogParser(logs_path))
            elif log_type == "zeek":
                LOG_PARSERS.append(
                    ZeekParser(
                        logs_path=logs_path,
                        zeek_log_ext=config["ZEEK_LOG_EXT"],
                        zeek_log_types=config["ZEEK_LOG_TYPES"],
                        keep_empty_fields=config["ZEEK_KEEP_EMPTY_FIELDS"],
                        keep_unset_fields=config["ZEEK_KEEP_UNSET_FIELDS"],    
                    )
                )
            else:
                print(f"Invalid log type: {log_type}")
                exit(1)
    else:
        print("No log types specified. Use --log-types or modify config.json to specify log types to process")
        exit(1)

    
    # Setup LogProcessor
    LOG_PROCESSOR = LogProcessor(
        parsers=LOG_PARSERS,
        remove_ips=config["USER_IPS"] + config["HONEYPOT_INTERNAL_IPS"] + config["HONEYPOT_EXTERNAL_IPS"],
        min_commands=config["ATTACK_MIN_COMMANDS"],
        min_malware=config["ATTACK_MIN_MALWARE"],
        min_successful_logins=config["ATTACK_MIN_SUCCESSFUL_LOGINS"],
        min_http_requests=config["ATTACK_MIN_HTTP_REQUESTS"],
        http_attack_regexes={
            "uri": config["ATTACK_HTTP_URI_REGEXES"],
            "httplog": config["ATTACK_HTTP_ANYWHERE_REGEXES"],
        },
        merge_shared_attrs=config["MERGE_SHARED_ATTRS"],
        merge_sig_regexes={
            "commands": config["MERGE_REGEX_COMMANDS"],
            "malware": config["MERGE_REGEX_MALWARE"],
            "http_requests": config["MERGE_REGEX_HTTP_REQUESTS"],
        },
        sort_attrs=config["SORT_ATTRS"],
        sort_order=config["SORT_ORDER"],
    )


    # Handle Missing Attack Loading Method
    if not args.load_from_logs and not args.load_from_attacks_dir:
        if args.organize_attacks:
            print("Argument --organize-attacks used without --load-from-logs or --load-from-attacks-dir. Defaulting to --load-from-logs")
            args.load_attacks_from_logs = True
        elif args.only_attacks:
            print("Argument --only-attacks used without --load-from-logs or --load-from-attacks-dir. Defaulting to --load-from-attacks-dir")
            args.load_from_attacks_dir = True
        else:
            print("No attack loading method specified. Use --load-from-logs OR --load-from-attacks-dir flags to specify how to load attacks.")
            exit(1)
    
    ATTACKS = OrderedDict()
    # Load Attacks with LogProcessor
    if args.load_from_logs:
        print(f"Loading attacks from logs directory at {config['LOGS_PATH']}")
        ATTACKS.update(LOG_PROCESSOR.load_attacks_from_logs())

    if args.load_from_attacks_dir:
        print(f"Loading attacks from attacks directory at {config['ATTACKS_PATH']}")
        ATTACKS.update(LOG_PROCESSOR.load_attacks_from_attacks_dir(
            attacks_dir=config["ATTACKS_PATH"],
            only_attacks=args.only_attacks,
            skip_attacks=args.skip_attacks,
            max_ips_per_attack=args.max_ips_per_attack,
            max_workers=config["LOAD_ATTACKS_MAX_WORKERS"],
        ))


    # Check if Attacks were loaded and exit if not unless writing README
    if not ATTACKS and "README" not in args.only_attacks:
        print("No attacks loaded. Exiting.")
        exit(1)


    # Filter Attacks
    for attack in list(ATTACKS.values()):
        # Remove attacks with more than max_ips_per_attack IPs
        if args.max_ips_per_attack and attack.num_source_ips > args.max_ips_per_attack:
            del ATTACKS[attack.attack_id]
            print(f"Skipping attack {attack.attack_id} with {attack.num_source_ips} IPs (max_ips_per_attack={args.max_ips_per_attack})")
        # Remove attacks not in only_attacks if --only-attacks flag is set
        elif args.only_attacks and attack.attack_id not in args.only_attacks:
            del ATTACKS[attack.attack_id]
            print(f"Skipping attack {attack.attack_id} (not in only_attacks={args.only_attacks})")
        # Remove attacks in skip_attacks if --skip-attacks flag is set
        elif args.skip_attacks and attack.attack_id in args.skip_attacks:
            del ATTACKS[attack.attack_id]
            print(f"Skipping attack {attack.attack_id} (in skip_attacks={args.skip_attacks})")
    
    # Remove attacks after max_attacks if --max-attacks flag is set
    if args.max_attacks and args.max_attacks < len(ATTACKS):
        print(f"Skipping {len(ATTACKS) - args.max_attacks} attacks (max_attacks={args.max_attacks})")
        for attack in list(ATTACKS.values())[args.max_attacks:]:
            del ATTACKS[attack.attack_id]
        

    # Preform Actions on Attacks
            
    # Print list of attacks if --list-attacks flag is set
    if args.list_attacks:
        LOG_PROCESSOR.print_stats_and_attacks()

    # Organize Attacks into attack directories if --organize-attacks flag is set
    if args.organize_attacks and ATTACKS:
        ATTACK_DIR_ORGANIZER = AttackDirOrganizer(
            attacks=ATTACKS,
            parser=CowrieParser(config["LOGS_PATH"]), # Use CowrieParser so auth_random.json is organized
            attacks_path=config["ATTACKS_PATH"],
            src_ip_subdirs=config["ORGANIZER_IP_SUBDIRS"],
            overwrite=config["ORGANIZER_OVERWRITE"],

        )

        results_generator = ATTACK_DIR_ORGANIZER.organize(
            iterby=config["ORGANIZER_ITERBY"],
            concurrency_type=config["ORGANIZER_CONCURRENCY_TYPE"],
            max_workers=config["ORGANIZER_MAX_WORKERS"],
            chunksize=config["ORGANIZER_CHUNKSIZE"],
            yield_order=config["ORGANIZER_YIELD_ORDER"],
        )

        print(f"Organizing attacks into attack directories at {config['ATTACKS_PATH']}")
        for result in results_generator:
            print(result)
        print(f"Finished organizing attacks into attack directories at {config['ATTACKS_PATH']}")


    # Setup Analyzers for analyzing/postprocessing organized Attacks
    IP_ANALYZER = None
    MALWARE_ANALYZER = None
    OPENAI_ANALYZER = None
    # Setup IPAnalyzer if --use-ipanalyzer flag is True
    if config["USE_IPANALYZER"]:
        IP_ANALYZER = IPAnalyzer(
            db_path=config["IPDB_PATH"],
            selenium_webdriver_type=config["WEBDRIVER_TYPE"],
            webdriver_path=config["WEBDRIVER_PATH"],
            sources=config["IPANALYZER_SOURCES"],
            max_errors=config["IPANALYZER_MAX_ERRORS"],
        )
    # Setup MalwareAnalyzer if --use-malwareanalyzer flag is True
    if config["USE_MALWAREANALYZER"]:
        MALWARE_ANALYZER = MalwareAnalyzer(
            db_path=config["MWDB_PATH"],
            selenium_webdriver_type=config["WEBDRIVER_TYPE"],
            webdriver_path=config["WEBDRIVER_PATH"],
            sources=config["MALWAREANALYZER_SOURCES"],
            max_errors=config["MALWAREANALYZER_MAX_ERRORS"],
        )
    # Setup OpenAIAnalyzer if --use-openai flag is True
    if config["USE_OPENAI"]:
        OPENAI_ANALYZER = OpenAIAnalyzer(
            db_path=config["AIDB_PATH"],
            training_data_path=config["OPENAI_TRAINING_DATA_PATH"],
            api_key=config["OPENAI_API_KEY"],
            model=config["OPENAI_MODEL"],
            ip_analyzer=IP_ANALYZER,
            malwareanalyzer=MALWARE_ANALYZER,
            honeypot_details={
                "internal_ips": config["HONEYPOT_INTERNAL_IPS"],
                "external_ips": config["HONEYPOT_EXTERNAL_IPS"],
                "ports": dict(zip(config["HONEYPOT_PORTS"], config["HONEYPOT_SOFTWARE"])),
            },
            use_code_interpreter=config["USE_OPENAI_CODE_INTERPRETER"],
        )

    # Chat with OpenAI Assistant about attacks if --chat flag is True
    if args.chat:
        if not OPENAI_ANALYZER:
            print("--chat/-C action specified but OpenAIAnalyzer is not enabled. Use --use-openai flag or edit config.json to enable OpenAIAnalyzer")
            exit(1)

        for attack in ATTACKS.values():
            print(f"Chatting about attack {attack.attack_id} with OpenAI Assistant")
            question_run_logs = OPENAI_ANALYZER.interactive_chat_about_attack(attack)
            attack.question_run_logs.update(question_run_logs)
            print(f"Finished chatting about attack {attack.attack_id} with OpenAI Assistant")

            if not question_run_logs:
                print("No questions asked. Skipping writing chat run steps markdown")
                continue
            
            question_keys = list(attack.question_run_logs.keys())
            file_prefix = f"{question_keys[0]}-{question_keys[-1]}" if len(question_keys) > 1 else question_keys[0]
            chat_run_steps_filepath = attack.attack_dir / "ai-chat" / f"{file_prefix}run-steps.md"
            
            print(f"Writing chat markdown run steps for attack {attack.attack_id} to {chat_run_steps_filepath}")
            RUN_STEPS_MARKDOWN_WRITER = RunStepsMarkdownWriter(
                filepath=chat_run_steps_filepath,
                mode="w+",
                data_object=attack,
            )
            RUN_STEPS_MARKDOWN_WRITER.update_md()
            print(f"Finished writing chat markdown run steps for attack {attack.attack_id} to {chat_run_steps_filepath}")


    # Setup AttackAnalyzer if --analyze-attacks or --write-reports flags are True
    if args.analyze_attacks or args.write_reports:
        ATTACK_DIR_READER = AttackDirReader(
            attacks=ATTACKS, 
            log_types=config["LOG_TYPES"]
        )
        
        ATTACK_ANALYZER = AttackAnalyzer(
            attacks=ATTACKS,
            attack_dir_reader=ATTACK_DIR_READER,
            ip_analyzer=IP_ANALYZER, 
            malware_analyzer=MALWARE_ANALYZER,
            openai_analyzer=OPENAI_ANALYZER,
            allow_fetch_failed_malware=config["MALWAREANALYZER_ALLOW_DOWNLOADS"],
        )    

        # Analyze Attacks if --analyze-attacks flag is set using AttackAnalyzer
        if args.analyze_attacks:
            ATTACKS = ATTACK_ANALYZER.analyze_attacks()


    # Enter interactive mode if --interactive flag is set after loading attacks. Useful for editing attacks in the python shell before writing reports
    if args.interactive:
        ATTACKS_LIST = list(ATTACKS.values())
        code.interact(
            local=locals(),
            banner="Entering interactive mode (python shell)...\n\n"
                    + f"{len(ATTACKS)} attacks are loaded into the 'ATTACKS' dict and 'ATTACKS_LIST' variables)"
                    + "\nAttack attributes can be accessed via 'ATTACKS[ATTACK_ID].ATTR_NAME' or 'ATTACKS_LIST[ATTACK_INDEX].ATTR_NAME'"
                    + "Use dir(ATTACKS_LIST[0]) to see available Attack attr names and functions."
                    + "\nUse 'exit()' or type CTRL-D to exit interactive mode",
            exitmsg="Exiting interactive mode and continuing honeypot-ai...",
            )


    # Write markdown reports for analyzed attacks if --write-markdown flag is set
    if args.write_reports or args.export_reports:
        for attack in ATTACKS.values():
            report_filepath = attack.attack_dir / "README.md"
            print(f"Writing markdown report for attack {attack.attack_id} to {report_filepath}")
            REPORT_MARKDOWN_WRITER = ReportMarkdownWriter(
                filepath=report_filepath,
                mode="w+",
                data_object=attack,
            )
            REPORT_MARKDOWN_WRITER.update_md()
            print(f"Finished writing markdown report and for attack {attack.attack_id} to {report_filepath}")

            run_steps_filepath = attack.attack_dir / "run-steps.md"
            print(f"Writing markdown run steps for attack {attack.attack_id} to {run_steps_filepath}")
            RUN_STEPS_MARKDOWN_WRITER = RunStepsMarkdownWriter(
                filepath=run_steps_filepath,
                mode="w+",
                data_object=attack,
            )
            RUN_STEPS_MARKDOWN_WRITER.update_md()
            print(f"Finished writing markdown run steps for attack {attack.attack_id} to {run_steps_filepath}")
            

            # Export attack report and files to REPORTS_PATH if --export-reports flag is set
            if args.export_reports:
                print(f"Exporting attack report and files for attack {attack.attack_id} to {config['REPORTS_PATH']}")
                export_dir = config["REPORTS_PATH"] / attack.answers['title']
                copytree(attack.attack_dir, export_dir,  dirs_exist_ok=True)
                print(f"Finished exporting attack report and files for attack {attack.attack_id} to {config['REPORTS_PATH']}")



    # Print specified attributes of attacks if --print-attrs flag is set. 
    # Called after analyze_attacks so that the attributes are updated before printing
    if args.print_attrs:
        for attack in ATTACKS.values():
            attack.print_attrs(*args.print_attrs)

    
    # Hidden option to update README.md with config_parser and default_config
    if args.only_attacks and "README" in args.only_attacks:
        DocsMarkdownWriter(
            filepath="README.md", 
            mode="w+", 
            data_object = {
                "config_parser": config_arg_parser(),
                "default_config": pprint_str(DEFAULT_CONFIG, sort_dicts=False),
            }
        ).update_md()


    print(f'Honeypot AI Finished Successfully!')
    exit(0)


if __name__ == "__main__":
    main()

    
    