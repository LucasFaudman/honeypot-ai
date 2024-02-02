from .markdownwriterbase import *


class DocsMarkdownWriter(MarkdownWriterBase):
    def prepare(self):
        self.custom_scripts_title = "Modules"
        self.md_editors.append(self.add_help_from_parser)
        self.md_editors.append(self.add_default_config)
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
                #"__init__.py": "Exports all classes, utility functions and imports from the analyzerbase folder",
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
                "setup.py": "Setup script for installing the honeypot-ai project",
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
        
        
        md += collapseable_section(script_md, self.custom_scripts_title, 1)
        
        return md
    

    def add_help_from_parser(self, md, data_object):
        help_text = data_object.get("config_parser").format_help()
        md += collapseable_section(codeblock(help_text), "All Command Line Arguments", 1)
        return md
    
    
    def add_default_config(self, md, data_object):
        md += collapseable_section(codeblock(data_object.get("default_config"), lang='python'), "Default Config", 1)
        return md
    


