from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser, ZeekParser
from loganalyzers.logprocessor import LogProcessor
from loganalyzers.attackdirorganizer import AttackDirOrganizer, ProcessPoolExecutor
from loganalyzers.attackdirreader import AttackDirReader

from osintanalyzers.ipanalyzer import IPAnalyzer
from osintanalyzers.malwareanalyzer import MalwareAnalyzer
from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY



DEFAULT_QUESTIONS = {
                # Initializer Questions (Asked to begin populating the AI context window before asking to retreive OSINT data)
                "ips_and_ports": "What are the IP addresses and ports involved in the attack?",
                "sessions_summary": "Summarize the Sessions involved in the attack.",

                # Session Analysis Questions (Asked to begin populating the AI context window before asking to retreive OSINT data)
                "ssh_analysis": "Analyze the SSH/Telnet sessions in the context of the attack. Include the usernames, passwords, ssh hasshes, and any other relevant.",
                "http_sessions": "Analyze the HTTP sessions in the context of the attack. Include the URIs, HTTP headers, and any other relevant info.",

                # IP OSINT Questions (Asked after AI context window has been updated with session analysis)
                "ip_locations_summary": "Summarize what is known about the location of the IP addresses involved in the attack.",
                "shodan_summary": "Summarize what is known about the IP addresses involved in the attack using Shodan data.",
                "isc_summary": "Summarize what is known about the IP addresses involved in the attack using ISC data.",
                "threatfox_summary": "Summarize what is known about the IP addresses involved in the attack using ThreatFox.",
                "cybergordon_summary": "Summarize what is known about the IP addresses involved in the attack using CyberGordon.",

                # Malware OSINT Questions (Asked after AI context window has been updated with IP OSINT)
                "malware_osint_summary": "Explain what is known about the malware and/or exploits used in the attack using data from MalwareBazaar, ThreatFox, URLhaus, and Malpedia. "
                "Be sure to analyze the src_ips, malware hashes, and any urls or hosts found in the malware samples, commands and/or HTTP requests.",
                
                # OSINT Full Summary (Asked once all OSINT data is in the AI context window)
                "osint_summary": "Summarize the critical findings across all OSINT sources.",
                
                # Attack Methods Analysis Questions (Asked after AI context window has been updated with sessions and OSINT data)
                "http_analysis": "Explain the HTTP requests and their functions in the context of the attack.",
                "commands_analysis": "Explain the commands used and their functions in the context of the attack.",
                "malware_analysis": "Explain the how the malware functions in the context of the attack.",
                "vuln_analysis": "Explain which vulnerabilities are being exploited. Include the exploit name(s), CVE number(s) and example code from ExploitDB, if possible.",
        
                # Attack Classification Questions (Asked after AI context window has been updated with OSINT data and attack methods analysis)
                "mitre_attack": "How can this attack be classified using the MITRE ATT&CK framework?",
                "goal_of_attack": "What is the goal of the attack?",
                "would_attack_be_successful": "If the system is vulnerable, would the attack will be successful?",
                "how_to_protect": "How can a system be protected from this attack?",
                "what_iocs": "What are the indicators of compromise (IOCs) for this attack?",
                "summary": "Summarize attack details, methods and goals to begin the report.",
                "title": "Create an informative title for this attack based on the analysis. Do not use any markdown.",
}


class MissingAnalyzerError(Exception):
    pass


class AttackAnalyzer:
    def __init__(self,
                 attacks: dict,
                 attack_dir_reader: AttackDirReader, 
                 ip_analyzer: Union[IPAnalyzer, None]=None,
                 malware_analyzer: Union[MalwareAnalyzer, None]=None, 
                 openai_analyzer: Union[OpenAIAnalyzer, None]=None
                 ):
        
        self.attacks = attacks
        self.attack_dir_reader = attack_dir_reader
        self.ip_analyzer = ip_analyzer
        self.malware_analyzer = malware_analyzer
        self.openai_analyzer = openai_analyzer


    def analyze_attacks(self):
        print(f"Analyzing {len(self.attacks)} attacks.")
        
        if self.attack_dir_reader:
            print("Getting log paths and counts.")
            log_paths, log_counts = self.get_all_log_paths_and_counts()
            print(f"Done getting log paths and counts. \nLog paths: {log_paths} \nLog counts: {log_counts}")

        if self.ip_analyzer:
            print("Getting ipdata.")
            ipdata = self.get_all_ipdata()
            print(f"Done getting ipdata. \nIP data: {ipdata}")

        if self.malware_analyzer:
            print("Getting mwdata.")
            mwdata = self.get_all_mwdata()
            print(f"Done getting mwdata. \nMW data: {mwdata}")

        if self.openai_analyzer:        
            print("Getting command explanations.")
            command_explanations = self.get_all_command_explanations()
            print(f"Done getting command explanations. \nCommand explanations: {command_explanations}")
            
            print("Getting malware explanations.")
            malware_explanations = self.get_all_malware_explanations()
            print(f"Done getting malware explanations. \nMalware explanations: {malware_explanations}")

            print("Getting assistant answers.")
            assistant_answers = self.get_all_assistant_answers()
            print(f"Done getting assistant answers. \nAssistant answers: {assistant_answers}")

        
        print(f"Done analyzing/postprocessing {len(self.attacks)} attacks.")
        return self.attacks



    def get_all_log_paths_and_counts(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.attack_dir_reader:
            raise MissingAnalyzerError("AttackDirReader not initialized can't get log paths and counts.")
        
        log_paths = {}
        log_counts = {}
        for attack in attacks.values():
            attack.add_postprocessor(self.attack_dir_reader)
            attack_log_paths, attack_log_counts = self.attack_dir_reader.update_attack_log_paths_and_counts(attack)

            log_paths.update(attack_log_paths)
            log_counts.update(attack_log_counts)
        
        return log_paths, log_counts
            

    def get_all_ipdata(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.ip_analyzer:
            raise MissingAnalyzerError("IPAnalyzer not initialized can't get ip data.")
        
        
        ipdata = {}
        for attack in attacks.values():
            attack.add_postprocessor(self.ip_analyzer)
            attack_ipdata = self.ip_analyzer.get_data(attack.uniq_ips)
            
            attack.update_ipdata(attack_ipdata)
            ipdata.update(attack_ipdata)

            
        
        return ipdata
    

    def get_all_mwdata(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.malware_analyzer:
            raise MissingAnalyzerError("MalwareAnalyzer not initialized can't get mwdata.")
        
        
        mwdata = {}
        for attack in attacks.values():
            attack_mwdata ={}

            attack_mwdata.update(
                self.malware_analyzer.get_data(
                    args=attack.uniq_malware_shasums,
                    arg_type="hash",               
                    sources=['malwarebazaar', "threatfox"]
                    )
            )
            
            attack_mwdata.update(
                self.malware_analyzer.get_data(
                    args=attack.uniq_urls,
                    arg_type="url",               
                    sources=['urlhaus', "threatfox"]
                    )
            )                           
            
            attack_mwdata.update(
                self.malware_analyzer.get_data(
                    args=attack.uniq_hosts,
                    arg_type="host",               
                    sources=['urlhaus', "threatfox"]
                    )
            )


            attack.update_mwdata(attack_mwdata)
            mwdata.update(attack_mwdata)

        return mwdata
    

    

    def get_all_command_explanations(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.openai_analyzer:
            raise MissingAnalyzerError("OpenAIAnalyzer not initialized can't get command explanations.")
        
        
        command_explanations = {}
        for attack in attacks.values():
            if not attack.commands:
                continue
            
            attack_command_explanations = self.openai_analyzer.explain_commands(attack.split_commands)
            attack.update_command_explanations(attack_command_explanations)
            command_explanations.update(attack_command_explanations)
        

        return command_explanations


    def get_all_malware_explanations(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.openai_analyzer:
            raise MissingAnalyzerError("OpenAIAnalyzer not initialized can't get malware explanations.")

        malware_explanations = {}
        for attack in attacks.values():
            if not attack.malware:
                continue

            attack_malware_explanations = {}
            for std_mw_hash, std_mw_obj_list in attack.standardized_malware.items():
                std_mw_obj0 = std_mw_obj_list[0]
                
                attack_malware_explanations.update({
                    std_mw_hash: 
                        self.openai_analyzer.explain_and_comment_malware(
                            malware_source_code=std_mw_obj0.standardized_text, 
                            commands=attack.split_commands
                            )
                })

            attack.update_malware_explanations(attack_malware_explanations)
            malware_explanations.update(attack_malware_explanations)
        
        return malware_explanations

    

    def get_all_assistant_answers(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.openai_analyzer:
            raise MissingAnalyzerError("OpenAIAnalyzer not initialized can't get assistant answers.")
        
        
        for attack in attacks.values():
            questions = DEFAULT_QUESTIONS.copy()

            if not attack.http_requests:
                del questions["http_sessions"]
                del questions["http_analysis"]

            if not attack.ssh_sessions and not attack.telnet_sessions:
                del questions["ssh_analysis"]

            if not attack.malware:
                del questions["malware_analysis"]
                
            if not attack.commands:
                del questions["commands_analysis"]
            


            answers = self.openai_analyzer.ass_answer_questions(questions.values(), attack)
            answers_by_question_key = {}
            for key, question in questions.items():
               answers_by_question_key[key] = answers[question]

            attack.questions = questions
            attack.answers = answers_by_question_key
            attack.question_answers = answers


    





















