from .markdownwriterbase import *


class DocsMarkdownWriter(MarkdownWriterBase):
    def prepare(self):
        self.md_editors.append(self.add_description)
        self.md_editors.append(self.add_setup)
        self.md_editors.append(self.add_basic_usage)
        self.md_editors.append(self.add_advanced_usage)
        self.md_editors.append(self.add_help_from_parser)
        self.md_editors.append(self.add_default_config)
        self.custom_scripts_title = "Module Descriptions"
        self.md_editors.append(self.add_custom_scripts)

    
    def script_link(self, script):
        return link(script.split("/")[-1], f"https://github.com/LucasFaudman/honeypot-ai/blob/main/{script}")


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
                module_md += table(["Script", "Description"], [[self.script_link(
                    module + "/" + script), description] for script, description in module_dict.items()])
            
            script_md += module_md
        
        
        md += collapseable_section(script_md, self.custom_scripts_title, 2)
        
        return md
    

    def add_help_from_parser(self, md, data_object):
        help_text = data_object.get("config_parser").format_help()
        md += collapseable_section(codeblock(help_text), "All Command Line Arguments", 2)
        return md
    
    
    def add_default_config(self, md, data_object):
        md += collapseable_section(codeblock(data_object.get("default_config"), lang='python'), "Default Config", 2)
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
        
        description +=  blockquote("Built by Lucas Faudman for SANS ISC")
        md += description
        return md

    def add_basic_usage(self, md, data_object):
        basic_usage = ""
        basic_usage += blockquote("Load all attacks from logs and list loaded attacks")
        basic_usage += codeblock( "honeypot-ai/run.sh --load-from-logs --list-attacks")

        basic_usage += blockquote("Load all attacks from logs and list attacks in order of start time, then number of commands, in ascending order")
        basic_usage += codeblock( "honeypot-ai/run.sh -lfl --list --sort-attrs start_time num_commands --sort-order asc")
        
        basic_usage += blockquote("Organize attacks with at most 50 source IPs into attack directories for faster loading and storing analysis results")
        basic_usage += codeblock( "honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 50")

        basic_usage += blockquote("Load attacks from the attacks directory and print the commands, malware, and HTTP requests for attacks with at least 2 commands, or at least 5 HTTP requests")
        basic_usage += codeblock("honeypot-ai/run.sh --load-from-attacks-dir --min-commands 2 --min-http-requests 5 --print-attrs commands malware http_requests")

        basic_usage += blockquote("Load only attacks with IDs XXXX and YYYY from the attacks directory then analyze each with OpenAI and IP analyzers, but not the Malware analyzer")
        basic_usage += codeblock("honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --analyze --no-malwareanalyzer")

        basic_usage += blockquote("Write and export markdown report for attack id XXXX")
        basic_usage += codeblock("honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write-markdown --export-report")

        basic_usage += blockquote("Enter chat mode to interactively ask questions about attack id XXXX before writing and exporting markdown report")
        basic_usage += codeblock("honeypot-ai/run.sh -lfa --only-attack XXXX --chat --analyze --write --export")

        md += collapseable_section(basic_usage, "Basic Usage", 2)
        return md


    def add_advanced_usage(self, md, data_object):
        advanced_usage = ""
        advanced_usage += blockquote("Update config file with values from command line arguments")
        advanced_usage += codeblock( "honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY")


        advanced_usage += blockquote("Enter interactive Python shell to manually modify attacks before analyzing and writing reports")
        advanced_usage += codeblock( "honeypot-ai/run.sh -lfa --interactive --analyze --write --export")

        advanced_usage += bullet("Modify the config file to change the default behavior of the honeypot-ai.")
        advanced_usage += bullet("See all command line arguments with --help to see all options and arguments.")

        md += collapseable_section(advanced_usage, "Advanced Usage", 2)
        return md