from .markdownwriterbase import *


class DocsMarkdownWriter(MarkdownWriterBase):
    def prepare(self):
        self.custom_scripts_title = "Modules"
        self.md_editors.append(self.add_help_from_parser)
        self.md_editors.append(self.add_default_config)
        self.md_editors.append(self.add_custom_scripts)

    
    def script_link(self, script):
        return link(script.split("/")[-1], f"https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzer-scripts/{script}")


    def add_custom_scripts(self, md, *arg):
        scripts = {
            "main.py": {
                "description":"Main script for running all analyzers through AttackAnalyzer inteface. (IN PROGRESS)",
            },
            # "runtests.py": {
            #     "description": "Script for running tests from the tests directory",
            # },
            "analyzerbase":{
                "description" : "Base classes, utility functions, libraries, and constants for all analyzer modules",
                "attack.py" : "Attack object for storing all data related to a single attack. Constructed by the loganalyzer scripts then processed by openaianlyzers and ipanalyzers before being passed to markdownwriters",
                "common.py" : "Imports and constants used by all analyzer modules",
                "malware.py": "Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object",                
                "session.py": "Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object",
                "sourceip.py": "SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object",
                "util.py": "Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text",
            },
            "loganalyzers":{
                "description" : "Scripts for analyzing logs to create Attack objects, organizing and read Attack files",
                "logparser.py": "Classes for reading all logs as json objects with standardized keys",
                "cowrieloganalyzer.py": "Reads Cowrie logs to create and merge Attack objects",
                "webloganalyzer.py": "Reads Web logs to create and merge Attack objects (IN PROGRESS)",
                "attackdirorganizer.py": "Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading",
                "attackdirreader.py": "Reads Attack files from directories organized by attackdirorganizer",
            },
            "openaianalyzers":{
                "description" : "Scripts for analyzing Attack objects using OpenAI's Completion and Assistant APIs",
                "aibase.py": "Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost",
                "completions.py": "OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code",
                "assistant.py": "OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about the attack",
                "tools.py": "Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects",
            },
            "osintanalyzers":{
                "description" : "Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object",
                "osintbase.py": "Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer",
                "ipanalyzer.py": "IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois",
                "mwanalyzer.py": "MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, and Malpedia, ",
                "soupscraper.py": "SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects",
                "getchromedrier.py": "Utility script to download correct chromedriver for Selenium",
            },
            "markdownwriters":{
                "description" : "Scripts for writing markdown files from Attack objects",
                "markdownwriterbase.py": "Base class for all markdown writers and markdown shortcut functions",
                "cowrieattackmarkdownwriter.py": "Markdown writer for Cowrie Attack objects (TODO abstract this to be AttackMarkdownWriter so it can be used for all future Attack objects types, Cowrie, Web, etc.)",
                "ipmarkdownwriter.py": "Markdown writer for ipdata added to Attack objects by IPAnalyzer",
                "visualizer.py": "Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts']",
            },
            # "tests":{
            #     "description" : "Tests for all analyzer modules",
            #     "test_analyzerbase.py": "Tests for analyzerbase",
            #     "test_loganalyzers.py": "Tests for loganalyzers",
            #     "test_openaianalyzers.py": "Tests for openaianalyzers",
            #     "test_osintanalyzers.py": "Tests for osintanalyzers",
            #     "test_markdownwriter.py": "Tests for markdownwriter",
            # },
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
    


