from .markdownwriterbase import *
from .attackmarkdownwriter import AttackMarkdownWriter
from .ipmarkdownwriter import IPMarkdownWriter
from .docsmarkdownwriter import DocsMarkdownWriter
from .runstepsmarkdownwriter import RunStepsMarkdownWriter


class ReportMarkdownWriter(AttackMarkdownWriter, IPMarkdownWriter, DocsMarkdownWriter):

    def prepare(self):
        attack = self.data_object
        self.md += h1(attack.answers.get("title", f"Attack: {attack.attack_id}"))

        self.md_editors.append(self.add_attack_summary)
        self.custom_scripts_title = "Custom Scripts Used To Generate This Report"
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


    def convert_report_md_to_txt_for_canvas(self, attack, report_filepath):
        report_filename = report_filepath.name
        txt_header = f"""
NOTE: This is a .md file with GitHub formatting. 
If you are viewing this in Canvas, please click the following link to view the formatted file on GitHub: 
{self.GITHUB_BASE_URL}example-reports/{quote(attack.answers.get("title", f"Attack: {attack.attack_id}"))}/{report_filename}
Alternatively, you can download the file and view it locally in your IDE.
All relevant logs and scripts can also be found in this repository.
""" 
        report_filepath.with_suffix('.md.txt').write_text(txt_header + '\n\n' + self.md)

        