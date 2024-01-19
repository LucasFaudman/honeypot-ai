from .markdownwriterbase import *
from .attackmarkdownwriter import AttackMarkdownWriter
from .ipmarkdownwriter import IPMarkdownWriter

class MarkdownWriter(AttackMarkdownWriter, IPMarkdownWriter):

    def prepare(self):
        attack = self.data_object
        #self.md += h1(f"Attack: {attack.attack_id}")
        self.md += h1(attack.answers.get("title", f"Attack: {attack.attack_id}"))

        self.md_editors.append(self.add_attack_summary)

        self.md_editors.append(self.add_custom_scripts)
        self.md_editors.append(self.add_time_and_date)
        self.md_editors.append(self.add_relevant_logs)

        self.md_editors.append(self.add_ip_and_port_tables)
        self.md_editors.append(self.add_ssh_analysis)
        self.md_editors.append(self.add_command_and_malware_analysis)
        self.md_editors.append(self.add_vuln_analysis)
        self.md_editors.append(self.add_questions)

        self.md_editors.append(self.add_osint_header)
        self.md_editors.append(self.add_ip_locations)
        self.md_editors.append(self.add_cybergordon)
        self.md_editors.append(self.add_shodan)
        self.md_editors.append(self.add_threatfox)
        self.md_editors.append(self.add_isc)
        self.md_editors.append(self.add_whois)