from .markdownwriterbase import *
from urllib.parse import quote

class DocsMarkdownWriter(MarkdownWriterBase):
    """Writes markdown for the honeypot-ai project documentation and README"""
    
    GITHUB_BASE_URL = "https://github.com/LucasFaudman/honeypot-ai/blob/main/"

    def prepare(self):
        self.md_editors.append(self.add_description)
        self.md_editors.append(self.add_example_reports)
        self.md_editors.append(self.add_setup)
        self.md_editors.append(self.add_basic_usage)
        self.md_editors.append(self.add_advanced_usage)
        self.md_editors.append(self.add_default_config)
        self.custom_scripts_title = "Module Descriptions"
        self.md_editors.append(self.add_custom_scripts)

    
    def script_link(self, script):
        return link(script.split("/")[-1], f"{self.GITHUB_BASE_URL}{quote(script)}")


    def add_custom_scripts(self, md, *arg):
        scripts = {
            "main.py": {
                "description":"Main script for initializing and running all analyzer objects according to command line arguments and config file",
            },
            "attackanalyzer.py": {
                "description":"High level class for running OSINTAnalyzers and OpenAIAnalyzer on Attack objects after being created by the LogProcessor",
            },
            "analyzerbase":{
                "description" : "Base classes, utility functions, libraries, and constants for all analyzer modules",
                "common.py" : "Imports and constants used by all analyzer modules",
                "baseobjects.py": "Custom base classes for all objects. CachePropertyObject allows temporary caching of properties for faster processing while remaining dynamic. SmartAttrObject allows properties to be called with modifiers like uniq_ and num_",
                "attack.py" : "Attack object for storing all data related to a single attack. Constructed by LogProcessor and modified by OSINTAnalyzers and OpenAIAnalyzers",
                "malware.py": "Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object",                
                "session.py": "Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object",
                "sourceip.py": "SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object",
                "util.py": "Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text",
            },
            "loganalyzers":{
                "description" : "Scripts for analyzing logs to create Attack objects, organizing and reading Attack directories",
                "logparser.py": "Classes for reading all logs into Python objects with standardized keys",
                "logprocessor.py": "Processes logs into Attack objects by creating SourceIP, Session, and Malware objects and adding them to an Attack object when specified conditions are met.",
                "attackdirorganizer.py": "Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading",
                "attackdirreader.py": "Reads and counts log events in Attack directories organized by attackdirorganizer",
            },
            "openaianalyzers":{
                "description" : "Scripts for analyzing Attack objects using OpenAI's Completions and Assistant APIs",
                "aibase.py": "Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost",
                "completions.py": "OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code",
                "assistant.py": "OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about an Attack object and its subobjects",
                "tools.py": "Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects",
            },
            "osintanalyzers":{
                "description" : "Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object",
                "osintbase.py": "Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer",
                "ipanalyzer.py": "IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois",
                "malwareanalyzer.py": "MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, Malpedia, and Explot-DB",
                "soupscraper.py": "SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects",
                
            },
            "markdownwriters":{
                "description" : "Scripts for writing markdown files from Attack objects",
                "markdownwriterbase.py": "Base class for all markdown writers and markdown shortcut functions",
                "attackmarkdownwriter.py": "Markdown writer for Attack objects following ISC format",
                "ipmarkdownwriter.py": "Markdown writer for ipdata added to Attack objects by IPAnalyzer",
                "runstepsmarkdownwriter.py": "Markdown writer for AI RunSteps for questions asked by the OpenAIAssistantAnalyzer when processed by the AttackAnalyzer and when in interactive mode",
                "docsmarkdownwriter.py": "Markdown writer for the honeypot-ai project documentation and README",
                "visualizer.py": "Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts']. (Not currently used due to crowding)",
            },
            "setup.sh": {
                "description":"Setup script for installing the honeypot-ai project",
            },
            "setup":{
                "description" : "Scripts for setting up the honeypot-ai project",
                "requirements.txt": "List of all required packages for the honeypot-ai project",
                "getchromedrier.py": "Utility script to download correct chromedriver for Selenium",
                "sync-logs.sh": "Utility script to sync logs from honeypot to honeypot-ai project logs directory",
                "install-zeek-on-honeypot.sh": "Utility script to install Zeek on a remote honeypot",
            },
        }

        script_md = ""

        for module, module_dict in scripts.items():
            module_md = h4(self.script_link(module))
            module_md += blockquote(module_dict.pop("description"))
            
            if module_dict:
                module_md += table(
                    ["Script", "Description"], 
                    [[self.script_link(module + "/" + script), description] for script, description in module_dict.items()]
                    )
            
            script_md += module_md
        
        
        md += collapseable_section(script_md, self.custom_scripts_title, 2)
        
        return md
    

    def add_setup(self, md, data_object):
        setup = ""
        setup += h4("Step 1: Clone the Repository")
        setup += codeblock("git clone https://github.com/LucasFaudman/honeypot-ai", lang="bash")
        
        setup += h4(f"Step 2: Run the Setup Script {self.script_link('setup.sh')}")
        setup += codeblock("chmod +x honeypot-ai/setup.sh && honeypot-ai/setup.sh", lang="bash")
        setup += blockquote("This will install all required packages in a virtual environment and walk you through setting up your config.json file. ")
        setup += "\n" + blockquote(
            f"You will need your honeypot IP and login credentials to create {self.script_link('setup/sync-logs.sh')} and {self.script_link('setup/install-zeek-on-honeypot.sh')}.")
        
        setup += h4(f"Optional: Install Zeek on your Honeypot using {self.script_link('setup/install-zeek-on-honeypot.sh')}")
        setup += codeblock("honeypot-ai/install-zeek-on-honeypot.sh", lang="bash")
        
        setup += h4(f"Step 3: Sync Logs from Honeypot to local logs directory using {self.script_link('setup/sync-logs.sh')}")
        setup += codeblock("honeypot-ai/sync-logs.sh", lang="bash")
        
        setup += h4("Step 4: Run Honeypot-AI with --help to see all command line arguments and options.")
        setup += codeblock("honeypot-ai/run.sh --help", lang="bash")
        setup += "\nOR\n" 
        setup += codeblock("python3 honeypot-ai/main.py --help", lang="bash")
        
        md += collapseable_section(setup, "Setup", 2)
        return md


    def add_description(self, md, data_object):
        description = ""
        description += h1("honeypot-ai")
        description += h4(
            "A modular honeypot log analyzer and OSINT collector with OpenAI integration to easily create ISC style reports and interactively chat with AI about attacks. "
            "Currently supports Cowrie, DShield and Zeek logs. "
            )
        
        description +=  blockquote("Built by Lucas Faudman for SANS ISC/DShield")
        md += description
        return md
    

    def make_usage_example(self, description, command, output):
        usage_md = blockquote(description)
        usage_md += codeblock(command, lang="bash")
        usage_md += collapseable_section(codeblock(output.strip()), "Output", 0, end_line=False)
        return usage_md


    def add_basic_usage(self, md, data_object):
        basic_usage = ""
        for example in BASIC_USAGE.values():
            basic_usage += self.make_usage_example(**example)
        
        md += collapseable_section(basic_usage, "Basic Usage", 2)
        return md


    def add_advanced_usage(self, md, data_object):
        advanced_usage = ""
        advanced_usage += h3("All Command Line Arguments")
        help_text = data_object.get("config_parser").format_help()
        advanced_usage += codeblock(help_text, lang="bash")
        advanced_usage += blockquote(f"For more advanced usage see comments in the source code and/or edit DEFAULT_CONFIG in {self.script_link('main.py')}.")
        md += collapseable_section(advanced_usage, "Advanced Usage", 2)
        return md
    

    def add_default_config(self, md, data_object):
        md += collapseable_section(codeblock(data_object.get("default_config"), lang='python'), "Default Config", 2)
        return md


    def add_example_reports(self, md, data_object):
        example_reports_md = h2("Attack Examples")
        titles = [f"example-reports/{dir.name}" for dir in sorted(Path("./reports").glob("*"), key=lambda x: x.stat().st_mtime, reverse=True) if dir.is_dir()]
        reports_table = table(
            ["Attack", "AI Run Steps"],
            [[self.script_link(title), self.script_link(title+"/run-steps.md")] for title in titles]
        )
        example_reports_md += reports_table
        md += example_reports_md
        return md



BASIC_USAGE = {
    "load_from_logs_list": {
        "description": "Load attacks from logs then list all attacks",
        "command": "honeypot-ai/run.sh --load-from-logs --list-attacks",
        "output": """
         """
        },


    "load_from_logs_sort": {
        "description": "Load attacks from logs then list first 5 attacks sorted in descending order by number of commands, then start time. Then print the commands for each attack",
        "command": "honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands",
        "output": """
         """
        },


    "organize_attacks": {
        "description": "Organize attacks with at most 10 source IPs into attack directories for faster loading and to prepare for storing analysis results",
        "command": "honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10",
        "output": """
         """
        },


    "load_from_attacks_dir": {
        "description": "Load attacks from the attacks directory with at least 5 commands, or at least 3 HTTP requests then print the first session, last 2 sessions, 3 most common HTTP requests and the most common src ip for each attack",
        "command": "honeypot-ai/run.sh --load-from-attacks-dir --min-commands 5 --min-http-requests 3 --print-attrs first_session last2_sessions most_common3_http_requests most_common_src_ip",
        "output": """
         """
        },


    "only_attacks": {
        "description": "Load only attacks with IDs XXXX and YYYY from the attacks directory then print the source IPs, unique dst ports, sessions,and commands and for each attack",
        "command": "honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --print-attrs source_ips uniq_dst_ports sessions commands ",
        "output": """
         """
        },


    "analyze_write_export": {
        "description": "Analyze attack with ID XXXX using OpenAI and OSINT analyzers then write markdown and export to reports directory",
        "command": "honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write --export",
        "output": """
         """
        },


    "chat_mode": {
        "description": "Enter chat mode to ask custom questions about attack with ID XXXX before analyzing, writing markdown, and exporting",
        "command": "honeypot-ai/run.sh -lfa --only-attack XXXX -AWE --chat",
        "output": """
         """
        },


    "interactive": {
        "description": "Enter interactive Python shell to manually modify attacks before analyzing, writing markdown, and exporting",
        "command": "honeypot-ai/run.sh -lfa -AWE --interact",
        "output": """
        """
    },


    "config_update": {
        "description": "Update config file with values from command line arguments",
        "command": "honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY",
        "output": """
        """
    },
        
}