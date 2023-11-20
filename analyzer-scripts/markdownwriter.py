
from ipanalyzer import IPAnalyzer
from cowrieloganalyzer import CowrieLogAnalyzer, Attack
from openaianalyzer import OpenAIAnalyzer

from analyzerbase import *

LOG_DESCRIPTIONS = {}


h1 = lambda text: f'# {text}\n'
h2 = lambda text: f'## {text}\n'
h3 = lambda text: f'### {text}\n'
h4 = lambda text: f'#### {text}\n'
italic = lambda text: f'*{text}*'
bold = lambda text: f'**{text}**'
link = lambda text, url: f'[{text}](' + url + ')'
image = lambda text, url: f'![{text}](' + url + ')'
code = lambda text: f'`{text}`'
codeblock = lambda text, lang="": f'\n```{lang}\n{text}\n```\n'
blockquote = lambda text: f'> {text}\n'
bullet = lambda text: f'* {text}\n'
blockbullet = lambda text: f'> * {text}\n'
unordered_list = lambda items: ''.join([f'\n* {item}' for item in items]) + '\n'
ordered_list = lambda items: ''.join([f'\n{n}. {item}\n' for n,item in enumerate(items)]) + '\n'
hline = lambda: '---\n'

def table(headers, rows, style_fn=str):
    table = ''
    table += '| ' + ' | '.join(headers) + ' |\n'
    table += '| ' + ' | '.join(['---' for _ in headers]) + ' |\n'
    for row in rows:
        row = [style_fn(item) for item in row]
        table += '| ' + ' | '.join(row) + ' |\n'
    return table



class MarkdownWriter:
    def __init__(self, filepath="test.md", mode="a+", md="", data_object: Union[dict, Attack]={}):
        
        self.filepath = pathlib.Path(filepath)
        self.mode = mode
        self.md = md
        self.data_object = data_object
        
        self.md_editors = []
        

    def edit_md(self, md, data_object={}):
        for editor in self.md_editors:
            md = editor(md, data_object)
        return md

    def update_md(self):
        self.prepare()
        self.md = self.edit_md(self.md, self.data_object)
        self.write_md(self.md)

    def write_md(self, md):
        with self.filepath.open(self.mode) as f:
            f.write(md)
    
    def prepare(self):
        #Implement in subclasses
        return NotImplementedError    
     

class IPAnalyzerMarkdownWriter(MarkdownWriter):


    def prepare(self):
    
        self.md += h1("What do you know about the attacker?")
        self.md_editors.append(self.add_ip_locations)
        self.md_editors.append(self.add_shodan)
        self.md_editors.append(self.add_isc)
        self.md_editors.append(self.add_cybergordon)
        self.md_editors.append(self.add_whois)



    def add_ip_locations(self, md, data):
        md += h2("IP Locations")
        location_data = [(ip, 
                        data[ip]["isc"]["ip"]["ascountry"],
                        data[ip]["isc"]["ip"]["as"],
                        data[ip]["isc"]["ip"]["asname"],
                        data[ip]["isc"]["ip"]["network"]
                        ) for ip in data if data[ip]["isc"].get("ip")]

        md += table(['IP Address', 'Country', "AS", "AS Name", "Network"], location_data)
        return md

    def add_isc(self, md, data):
        

        if len(data) == 1:
            sharing_url = list(data.values())[0]["isc"]["sharing_link"]
            sharing_link = link(sharing_url, sharing_url)
        else:
            sharing_link = link("https://isc.sans.edu/ipinfo/", "https://isc.sans.edu/ipinfo/")

        md += h2("Internet Storm Center (ISC) " + sharing_link)
        
        ics_data = [(ip, 
                        data[ip]["isc"]["ip"]["count"],
                        data[ip]["isc"]["ip"]["attacks"],
                        data[ip]["isc"]["ip"]["mindate"],
                        data[ip]["isc"]["ip"]["maxdate"],
                        data[ip]["isc"]["ip"]["updated"],
                        ) for ip in data if data[ip]["isc"].get("ip")]
        
        headers = ['IP Address', 'Total Reports', "Targets", "First Report", "Last Report", "Update Time"]
        md += table(headers, ics_data)
        return md    

    def add_whois(self, md, data):
        md += h2("Whois")

        #md += table(['IP Address', 'Whois Data'], whois_data)
        for ip in data:
            md += h3(f"Whois data for: {ip}")
            if isinstance(data[ip]["whois"], str):
                md += codeblock(data[ip]["whois"])
            else:    
                md += codeblock(data[ip]["whois"]["whois_raw"])

        return md

    def add_cybergordon(self, md, data):
        md += h2("CyberGordon")
        for ip in data:
            sharing_link = link(data[ip]["cybergordon"]["sharing_link"], data[ip]["cybergordon"]["sharing_link"])
            
            md += h3(f"Cybergordon results for: {ip} " + sharing_link)
            cybergordon_data = []
            for priority in ["high", "medium", "low"]:
                for entry in data[ip]["cybergordon"]["results"].get(priority, []):
                    cybergordon_data.append((entry["engine"], entry["result"], entry["url"]))

            #cybergordon_data = [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["high"]]
            #cybergordon_data += [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["medium"]]
            #cybergordon_data += [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["low"]]
            headers = ['Engine', 'Results', "Url"]
            md += table(headers, cybergordon_data)
        
        return md
    
    def add_shodan(self, md, data):
        md += h2("Shodan")
        for ip in data:
            
            if data[ip]["shodan"] == 'ERROR: 404: Not Found':
                continue


            sharing_link = link(data[ip]["shodan"]["sharing_link"], data[ip]["shodan"]["sharing_link"])
            md += h3(f"Shodan results for: {ip} " + sharing_link)
            headers = list(data[ip]["shodan"]["results"]["general"].keys())
            shodan_general_values = list(data[ip]["shodan"]["results"]["general"].values())
            md += table(headers, [shodan_general_values])
            
            md += h4("Open Ports")
            shodan_ports_data = [(port, entry["protocol"], entry["service_name"], entry["timestamp"]) for port, entry in data[ip]["shodan"]["results"]["ports"].items()]
            shodan_ports_keys = ["Port", "Protocol", "Service", "Update Time"]
            md += table(shodan_ports_keys, shodan_ports_data)
        return md




class CowrieAttackMarkdownWriter(MarkdownWriter):

    def prepare(self):
        attack = self.data_object
        self.md += h1(f"Attack: {attack.attack_id}")
        
        self.md_editors.append(self.add_time_and_date)
        self.md_editors.append(self.add_relevant_logs)
        self.md_editors.append(self.add_custom_scripts)
        self.md_editors.append(self.add_malware_analysis)
        self.md_editors.append(self.add_vuln_analysis)
        self.md_editors.append(self.add_goal_of_attack)
        self.md_editors.append(self.add_success_of_attack)
        self.md_editors.append(self.add_mitigation)

        


    def session_table(self,sessions):
        session_headers = ["Session ID", "IP", "Src Port", "Dst Port", "Start Time", "End Time", "Duration"]
        session_data = [(session.session_id, session.src_ip, session.src_port, session.dst_port, session.start_time, session.end_time, session.duration) for session in sessions]
        return table(session_headers, session_data, style_fn=code)

    def add_time_and_date(self, md, attack: Attack):
        first_session = attack.first_session
        last_session = attack.last_session
        md += h1("Time and Date of Activity")
        md += blockquote(f"First activity logged: {code(str(attack.start_time))}")
        md += blockbullet(f"First session: {code(first_session.session_id)}")
        md += blockbullet(f"First IP/Port: {code(first_session.src_ip)}:{code(first_session.src_port)} -> {code(first_session.dst_ip)}:{code(first_session.dst_port)}" )
        md += "\n"

        md += blockquote(f"Last activity logged: {code(str(attack.end_time))}")
        md += blockbullet(f"Last session: {code(last_session.session_id)}")
        md += blockbullet(f"Last IP/Port: {code(last_session.src_ip)}:{code(last_session.src_port)} -> {code(last_session.dst_ip)}:{code(last_session.dst_port)}" )
        md += "\n"
        
        md += self.session_table([first_session, last_session])
        
        return md

    def add_attack_summary(self, md, attack: Attack):
        counts = attack.counts
        log_counts = attack.log_counts
        
        if len(attack.source_ips) <= 15:
            src_ip_summary = ', '.join([src_ip.ip for src_ip in attack.source_ips])
        else:
            src_ip_summary = ', '.join([src_ip.ip for src_ip in attack.source_ips][:15]) + f" (and {len(attack.source_ips)-15} more)"
        
        if len(counts['all_src_ports']) <= 15:
            src_port_summary = ', '.join([str(port) for port in counts['all_src_ports']])
        else:
            src_port_summary = f" Min: {min(counts['all_src_ports'])}, Max: {max(counts['all_src_ports'])}"

        

        summary = [
            f"This attack was carried out by a {code(len(attack.source_ips))} unique source IP address(es): {code(src_ip_summary)}",
            f"A total of {code(len(attack.sessions))} sessions were logged. {code(len(attack.login_sessions))} sessions were successful logins.",
            f"{code(sum(counts['all_login_pairs'].values()))} login attempts were made. {code(sum(counts['successful_login_pairs'].values()))} were successful.",
            f"{code(len(counts['all_login_pairs']))} unique username/password pairs were attempted. {code(len(counts['successful_login_pairs']))} were successful.",
            f"{code(len(counts['all_dst_ports']))} unique destination ports were targeted: {code(', '.join([str(port) for port in counts['all_dst_ports']]))}",
            f"{code(len(counts['all_src_ports']))} unique source ports were used: {code(src_port_summary)}",
            f"This attack used {code(len(attack.commands))} commands in total. {code(len(counts['all_cmdlog_ips']))} IP(s) and {code(len(counts['all_cmdlog_urls']))} URL(s) were found in the commands",
            f"{code(len(attack.malware))} unique malware samples were downloaded. {code(len(counts['all_malware_ips']))} IP(s) and {code(len(counts['all_malware_urls']))} URL(s) were found in the malware samples",
            
        ]

        md += "Summary of attack" 
        md += unordered_list(summary)
        return md

    def add_relevant_logs(self, md, attack: Attack):
        md += h1("Relevant Logs, File or Email")
        md = self.add_attack_summary(md, attack)
        
        log_counts = attack.log_counts
        log_types = attack.log_types
        
        md += h2("Log Stats")
        md += bullet(f"This attack was generated a total of {code(log_counts['all']['lines'])} log lines in {code(log_counts['all']['files'])} log files: {code(', '.join(log_types))}\n")


        log_table_headers = ["Log Name", "Lines"]
        ip = 'all'
        log_table_data = [(log_type, log_counts[ip][log_type]["lines"]) for log_type in log_types]
        md += table(log_table_headers, log_table_data)


        md = self.add_ip_and_port_tables(md, attack)
        
        if "dshield.log" in log_types:
            md = self.add_dshield_logs(md, attack, ip="all", n_lines=-1)

        md = self.add_ssh_analysis(md, attack)

        if "cowrie.log" in log_types:
            md = self.add_cowrie_logs(md, attack, ip="all", n_lines=-1)

        if "web.json" in log_types:
            md = self.add_web_logs(md, attack, ip="all", n_lines=-1)
        
        #TODO ADD ZEEK + OTHER LOGS

        

        return md
    

    def add_dshield_logs(self, md, attack: Attack, ip="all", n_lines=-1):
        md += h2("DShield Logs")
        #TODO ADD Log Descriptions
        md += f"Total DShield logs: {code(attack.log_counts[ip]['dshield.log']['lines'])}\n"
        md += h4(f"The {code(len(attack.sessions))} sessions in this attack were logged as connection in the following DShield firewall logs:")
        md += f"Here is a sample of the first {code(n_lines)} lines:\n"
        md += codeblock(attack.get_log_lines(ip, "dshield.log", n_lines), "log")
        md += blockquote("COMMENTARY ON LOGS")

        return md

    def add_web_logs(self, md, attack: Attack, ip="all", n_lines=-1):
        md += h2("Web Logs")
        #TODO ADD Log Descriptions
        md += f"Total Web logs: {code(attack.log_counts[ip]['web.json']['lines'])}\n"
        md += h4(f"The {code(len(attack.sessions))} sessions in this attack were logged as connection in the following Web logs:")
        md += f"Here is a sample of the first {code(n_lines)} lines:\n"
        md += codeblock(attack.get_log_lines(ip, "web.json", n_lines),'json')
        md += blockquote("COMMENTARY ON LOGS")

        return md
    
    def add_cowrie_logs(self, md, attack: Attack, ip="all", n_lines=-1):
        first_command_session = attack.first_command_session

        for ext in ('.log', '.json'):
            md += h2(f"Cowrie {ext} Logs")
            #TODO ADD Log Descriptions
            md += f"Total Cowrie logs: {code(attack.log_counts[ip][f'cowrie{ext}']['lines'])}\n"
            md += h4(f"First Session With Commands {first_command_session.session_id} Cowrie {ext} Logs")
            md += f"This sample shows the Cowrie {code(ext)} Logs for session_id {code(first_command_session.session_id)} the first session in this attack where the attacker exectuted commands in on the honeypot system."
            if n_lines > 0:
                md += f"Here is a sample of the first {code(n_lines)} lines:\n" 
            if ext == '.log':
                session_filter = f"0,{first_command_session.src_ip}" 
                codeblock_lang = 'verilog'
            else:
                session_filter = first_command_session.session_id
                codeblock_lang = 'json'
            md += codeblock(attack.get_log_lines(ip, f"cowrie{ext}", n_lines, session_filter), codeblock_lang)
            md += blockquote("COMMENTARY ON LOGS")
        return md
    

    def most_common_table(self, label, counter, n=10, style_fn=code):
        md = h3(f"Top {n} {label}s")
        md += f"Total: {label}s {code(sum(counter.values()))}\n"
        md += f"Unique: {code(len(counter))}\n"
        
        headers = [label, "Times Seen"]
        if isinstance(label, (tuple, list)):
            headers = label[:2]

        md += table(headers, [(item, count) for item, count in counter.most_common(n)], style_fn)
        return md

    def add_ssh_analysis(self, md, attack: Attack):
        md += h2("SSH Analysis")
        n = 10
        md += self.most_common_table("Username", attack.counts["all_usernames"], n)
        md += self.most_common_table("Password", attack.counts["all_passwords"], n)
        md += self.most_common_table("Username/Password Pair", attack.counts["all_login_pairs"], n)
        md += self.most_common_table("Successful Username", attack.counts["successful_usernames"], n)
        md += self.most_common_table("Successful Password", attack.counts["successful_passwords"], n)
        md += self.most_common_table("Successful Username/Password Pair", attack.counts["successful_login_pairs"], n)
        return md
    
    def add_ip_and_port_tables(self, md, attack: Attack):
        md += h2("IP and Ports")
        n = 10

        md += self.most_common_table("Source IP", attack.counts["all_src_ips"], n)
        md += self.most_common_table("Destination IP", attack.counts["all_dst_ips"], n)
        md += self.most_common_table("Source Port", attack.counts["all_src_ports"], n)
        md += self.most_common_table("Destination Port", attack.counts["all_dst_ports"], n)
        return md



    def script_link(self, script):
        return link(script, f"https://github.com/LucasFaudman/BACS-4498/blob/main/analyzer-scripts/{script}")

    def add_custom_scripts(self, md, attack: Attack):
        scripts = {
            "logparser.py": "Base class for reading all logs as json objects with standardized keys",
            "cowrieloganalyzer.py": "Python script for Analyzing Cowrie logs",
            "webloganalyzer.py": "Python script for Analyzing Web logs",
            "soupscraper.py": "Base class for scraping web pages with BeautifulSoup and Selenium",
            "ipanalyzer.py": "Python script for Analyzing IP addresses and domains",
            "markdownwriter.py": "Python for writing markdown files",
            "getlogsbyip.sh": "Bash script for getting all logs for a given IP address",
        }

        md += h1("Custom Scripts")
        md += table(["Script", "Description"], [[self.script_link(script), description] for script, description in scripts.items()])

        return md
    


    def command_analysis(self, attack: Attack):
        commands = attack.commands
        split_commands = attack.split_commands
        command_explainations = attack.command_explainations
        

        md = h2("Commands Used")
        md += f"This attack used a total of {code(len(commands))} inputs to execute the following {code(len(split_commands))} commands:\n"
        for command, explaination in command_explainations.items():
            md += codeblock(command, "bash")
            md += blockquote(explaination)


        return md
    
    def malware_analysis(self, attack: Attack):
        malware = attack.malware

        md = h2("Malware Downloaded")
        md += f"This attack downloaded the following {len(malware)} malware samples:\n"
        for n, sample in enumerate(malware.items()):
            shasum, mwobj = sample
            md += h3(f"\nMalware Sample {n} Sha256 HASH: {code(shasum)}")
            md += codeblock(mwobj.text)
            
        return md


    def add_malware_analysis(self, md, attack: Attack):
        counts = attack.counts
        malware = attack.malware

        md += h1("Malware Analysis")
        md += bullet(f"This attack used {code(len(attack.commands))} commands in total. {code(len(counts['all_cmdlog_ips']))} IP(s) and {code(len(counts['all_cmdlog_urls']))} URL(s) were found in the commands")
        md += bullet(f"{code(len(malware))} unique malware samples were downloaded. {code(len(attack.counts['all_malware_ips']))} IP(s) and {code(len(attack.counts['all_malware_urls']))} URL(s) were found in the malware samples")
        md += self.command_analysis(attack)
        if malware:
            md += self.malware_analysis(attack)
        
        return md

    def add_vuln_analysis(self, md, attack: Attack):
        md += h1("Which vulnerability does the attack attempt to exploit?")
        md += h4(f'Exploit: {link("Exploit Name", "https://www.exploit-db.com/exploits/12345")}')
        md += h4(f'CVE: {link("CVE-1234-1234", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1234-1234")}')
        md += h4(f"Mitre ATT&CK: {link('T1234', 'https://attack.mitre.org/techniques/T1234')}")
        md += h4(f'Proof of Concept from {link("PoC Name", "https://www.exploit-db.com/exploits/12345")}')
        md += codeblock("PoC Code", "python")

        return md

    def add_goal_of_attack(self, md, attack: Attack):
        md += h1("What is the goal of the attack?")
        #md += h4("Goal of the attack")

        return md    

    def add_success_of_attack(self, md, attack: Attack):
        md += h1("If the system is vulnerable, do you think the attack will be successful?")
        #md += h4("Success of the attack")

        return md


    def add_mitigation(self, md, attack: Attack):
        md += h1("How can a system be protected from this attack?")
        #md += h4("Mitigation steps")

        return md    


    def add_ioc(self, md, attack: Attack):
        md += h1("What are the indicators of compromise (IOCs)?")
        #md += h4("IOCs")

        return md





def test_md():
    mdw = MarkdownWriter('test.md')
    mdw.write_md(h1('h1'))
    mdw.write_md(h2('h2'))
    mdw.write_md(h3('h3'))
    mdw.write_md(h4('h4'))
    mdw.write_md("\n"+italic('italic')+"\n")
    mdw.write_md("\n"+bold('bold')+"\n")
    mdw.write_md("\n"+link('Google.com', 'https://www.google.com')+"\n")
    mdw.write_md("\n"+image('image', 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png')+"\n")
    mdw.write_md("\n"+code('code')+"\n")
    mdw.write_md("\n"+codeblock('code block'))
    mdw.write_md("\n"+blockquote('blockquote'))
    mdw.write_md(unordered_list(['item1', 'item2', 'item3']))
    mdw.write_md(ordered_list(['item1', 'item2', 'item3']))
    mdw.write_md(hline())
    mdw.write_md(table(['header1', 'header2', 'header3'], [['row1col1', 'row1col2', 'row1col3'], ['row2col1', 'row2col2', 'row2col3']]))
   

def test_ipanalyzer_md():    
    ips = ["2.237.57.70",'80.94.92.20']
    analyzer = IPAnalyzer()

    ipdata = analyzer.get_data(ips)
    ips_str = '_'.join(ips)

    mdw = IPAnalyzerMarkdownWriter(f'test{ips_str}.md', mode="w+", data_object=ipdata)
    mdw.update_md()
    

def test_cowrieattack_md():
    la = CowrieLogAnalyzer()
    la.process()
    la.analyze()
    la.get_log_paths()

    keys = [
            'c4b10bb73706910252919070fbd459b71060e72c6a2ed888ec5223629b2d0cd0',
            '38628b4bc67736d9c84770b16d65c687f260b7e6055f573c0adc3ac0340a8a53',
            #'http://80.94.92.20/ssh.sh'
            "ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b",
            "c4b10bb73706910252919070fbd459b71060e72c6a2ed888ec5223629b2d0cd0"
            'ea40ecec0b30982fbb1662e67f97f0e9d6f43d2d587f2f588525fae683abea73',
        #'e63969f07eb117998329f37cb3543d83c76c1260d6122120ec7b7d256676b022',
        #'5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75',
        #'01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
        #'8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358',
        #'6f09f57fbae18a7e11096ca715d0a91fb05f497c4c7ff7e65dc439a3ee8be953',
        #'bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747',
        #"1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687"
    ]

    openai_analyzer = OpenAIAnalyzer()

    for key in keys:
        attack = la.attacks[key]
        
        attack.command_explainations = openai_analyzer.explain_commands(attack.split_commands)
        #attack.command_explainations  = openai_analyzer.explain_commands(attack.commands)


        key = key.replace('/', '_')
        mdw = CowrieAttackMarkdownWriter(f'tests/attacks/' + key + '.md', mode="w+", data_object=attack)
        mdw.update_md()


        ipa = IPAnalyzer()
        ipdata = ipa.get_data(set(attack.all_ips_and_urls))
        
        ipmdw = IPAnalyzerMarkdownWriter(f'tests/attacks/' + key +'.md', mode="a+", data_object=ipdata)
        ipmdw.update_md()
        





def convert_md_to_mdtxt_for_canvas(filepath, github_url):
    txt_header = f"""NOTE: This is a .md file with GitHub formatting. 
If you are viewing this in Canvas, please click the following link to view the formatted file on GitHub: 
{github_url}
Alternatively, you can download the file and view it locally in your IDE.
All relevant logs and scripts can also be found in this repository.
""" 
    with open(filepath, 'r') as f:
        md = f.read()
    with open(filepath.replace('.md', '.md.txt'), 'w+') as f:
        f.write(txt_header)
        f.write('\n\n')
        f.write(md)


def test_convert_md_to_mdtxt_for_canvas():
    filepath = '/Users/lucasfaudman/Documents/SANS/internship/BACS-4498/attack-observations/attack-1/observation1.md'
    github_url = 'https://github.com/LucasFaudman/BACS-4498/blob/main/attack-observations/attack-1/observation1.md'
    convert_md_to_mdtxt_for_canvas(filepath, github_url)

if __name__ == "__main__":
    #test_ipanalyzer_md()
    #test_convert_md_to_mdtxt_for_canvas()
    test_cowrieattack_md()