from analyzerbase import *
from loganalyzers.attackdirreader import AttackDirReader
from osintanalyzers import IPAnalyzer, MalwareAnalyzer
from openaianalyzers import OpenAIAnalyzer


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
                 openai_analyzer: Union[OpenAIAnalyzer, None]=None,
                 allow_fetch_failed_malware: bool=True
                 ):
        
        self.attacks = attacks
        self.attack_dir_reader = attack_dir_reader
        self.ip_analyzer = ip_analyzer
        self.malware_analyzer = malware_analyzer
        self.openai_analyzer = openai_analyzer
        self.allow_fetch_failed_malware = allow_fetch_failed_malware


    def analyze_attacks(self):
        print(f"Analyzing {len(self.attacks)} attacks.")
        
        if self.attack_dir_reader:
            print("Getting log paths and counts.")
            log_paths, log_counts = self.get_all_log_paths_and_counts()
            print(f"Done getting log paths and counts. \nLog paths: {pprint_str(log_paths)} \nLog counts: {pprint_str(log_counts)}")

        if self.ip_analyzer:
            print("Getting ipdata.")
            ipdata = self.get_all_ipdata()
            print(f"Done getting ipdata. \nIP data: {pprint_str(ipdata)}")

        if self.malware_analyzer:
            print("Getting mwdata.")
            mwdata = self.get_all_mwdata()
            print(f"Done getting mwdata. \nMW data: {pprint_str(mwdata)}")
            if self.allow_fetch_failed_malware:
                print("Fetching failed malware.")
                failed_malware = self.fetch_all_failed_malware()
                print(f"Done fetching failed malware. \nFailed malware: {pprint_str(failed_malware)}")


        if self.openai_analyzer:        
            print("Getting command explanations.")
            command_explanations = self.get_all_command_explanations()
            print(f"Done getting command explanations. \nCommand explanations: {pprint_str(command_explanations)}")
            
            print("Getting malware explanations.")
            malware_explanations = self.get_all_malware_explanations()
            print(f"Done getting malware explanations. \nMalware explanations: {pprint_str(malware_explanations)}")

            print("Getting assistant answers.")
            assistant_answers = self.get_all_assistant_answers()
            print(f"Done getting assistant answers. \nAssistant answers: {pprint_str(assistant_answers)}")

        
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
            # attack.add_postprocessor(self.ip_analyzer)
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
        
        assistant_answers = defaultdict(dict)
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
            

            question_run_logs = self.openai_analyzer.answer_attack_questions(questions, attack)
            attack.questions = questions
            for question_key, question_run_log in question_run_logs.items():
                attack.question_run_logs[question_key] = question_run_log
                attack.answers[question_key] = question_run_log["answer"]
                assistant_answers[attack.attack_id][question_key] = question_run_log["answer"]

            attack.answers["title"] = attack.answers["title"].strip('"').strip("'")
            
        return assistant_answers
    

        
    def fetch_all_failed_malware(self, attacks=None):
        attacks = attacks or self.attacks

        if not self.malware_analyzer:
            raise MissingAnalyzerError("MalwareAnalyzer not initialized can't get malware.")
        
        
        failed_malware = {}
        for attack in attacks.values():
            if attack._malware:
                for malware_id, malware_obj in list(attack._malware.items()):
                    if malware_obj.failed and malware_obj.source_address:
                        mw_bytes = self.malware_analyzer.get_urlhaus_download(malware_obj.source_address)
                        if not mw_bytes:
                            continue
                        
                        mw_hash = sha256hex(mw_bytes)
                        mw_file = attack.attack_dir / f"malware/downloads/{mw_hash}"
                        with mw_file.open('wb+') as f:
                            f.write(mw_bytes)
                        
                        malware_obj.filepath = mw_file
                        malware_obj.id = mw_hash
                        malware_obj.shasum = mw_hash
                        malware_obj.failed = False
                        attack._malware[mw_hash] = attack._malware.pop(malware_id)
                        
                        failed_malware[mw_hash] = malware_obj
                        print(f"Successfully fetched failed malware {mw_hash} for attack {attack.attack_id} from {malware_obj.source_address}")
                        
        
        return failed_malware

    





















