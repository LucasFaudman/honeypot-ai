from time import time


from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer
from loganalyzers.webloganalyzer import WebLogAnalyzer
from loganalyzers.attacklogorganizer import AttackLogOrganizer, AttackLogReader

from netanalyzers.ipanalyzer import IPAnalyzer
from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY

#test_logs_path = Path("tests/tl2")
test_attacks_path = Path("tests/a1")
test_ipdb_path = Path("tests/ipdb")
test_aidb_path = Path("tests/aidb")
test_ai_training_data_path=Path("openai-training-data")

class AttackAnalyzer:

    def __init__(self, 
                 log_path=test_logs_path, 
                 attacks_path=test_attacks_path, 
                 ipdb_path=test_ipdb_path,
                 aidb_path=test_aidb_path,
                 test_ai_training_data_path=test_ai_training_data_path,
                 remove_ips=MYIPS, 
                 overwrite=True, 
                 openai_key=OPENAI_API_KEY,
                 openai_model="gpt-4-1106-preview",
                 webdriver_type="chrome",
                 webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver"):
        
        self.log_path = log_path
        self.attacks_path = attacks_path
        self.ipdb_path = ipdb_path
        self.aidb_path = aidb_path
        self.ai_training_data_path = test_ai_training_data_path

        
        
        self.remove_ips = remove_ips
        self.overwrite = overwrite
        
        self.attacks = {}
        self.source_ips = {}

        self.cowrie_parser = CowrieParser(self.log_path)
        self.dshield_parser = DshieldParser(self.log_path)
        self.weblog_parser = WebLogParser(self.log_path)


        self.cowrie_analyzer = CowrieLogAnalyzer(self.cowrie_parser, self.remove_ips)
        self.weblog_analyzer = WebLogAnalyzer(self.weblog_parser, self.remove_ips, self.attacks_path)
        
        self.attack_organizer = AttackLogOrganizer(self.cowrie_parser, self.attacks_path, self.attacks, self.overwrite)
        self.attack_reader = AttackLogReader(self.cowrie_parser, self.attacks_path, self.attacks, self.overwrite)

        self.webdriver_type = webdriver_type
        self.webdriver_path = webdriver_path
        self.ipanalyzer = IPAnalyzer(self.ipdb_path, self.webdriver_type, self.webdriver_path)

        self.openai_key = openai_key
        self.openai_model = openai_model
        self.openai_analyzer = OpenAIAnalyzer(self.ai_training_data_path, self.aidb_path, self.openai_key, self.openai_model)



    def load_attacks_from_cowrie_logs(self):
        """Loads attacks from log files and returns them as an OrderedDict of attacks"""

        self.source_ips = self.cowrie_analyzer.process()
        self.attacks = self.cowrie_analyzer.analyze()

        return self.attacks 
    



    def organize_attacks_from_cowrie_logs(self, max_src_ips=50):
        """Loads attacks from log files and saves them to json files"""

        attacks = self.load_attacks_from_cowrie_logs()
        for attack_id, attack in list(attacks.items()):
            if attack.num_src_ips > max_src_ips:
                del attacks[attack_id]
        

        self.attack_organizer.set_attacks(attacks)
            
        results = list(self.attack_organizer.organize())
        return results




    def load_attacks_from_attack_dir(self, only_attacks=[], skip_attacks=[]):
        """Loads attacks from organized attack dirs"""

        self.cowrie_analyzer = CowrieLogAnalyzer(self.cowrie_parser, self.remove_ips)

        for attack_dir in self.attacks_path.glob("*"):
            if only_attacks and attack_dir.name not in only_attacks:
                continue
            
            if skip_attacks and attack_dir.name in skip_attacks:
                continue

            parser = CowrieParser(attack_dir)
            self.cowrie_analyzer.set_parser(parser)
            self.cowrie_analyzer.process()

        self.attacks = self.cowrie_analyzer.analyze()
        
        return self.attacks
    



    def postprocess_attacks(self):
        self.attack_reader.set_attacks(self.attacks)
        self.attack_reader.update_all_log_paths_and_counts()

        for attack in self.attacks.values():

            attack.add_postprocessor(self.attack_reader)
            #self.attack_reader.update_attack_log_counts(attack)

            # attack.add_postprocessor(self.ipanalyzer)
            # TODO get IPdata for all ips in attack
            
            split_commands = attack.split_commands
            command_explanations = self.openai_analyzer.explain_commands(split_commands)
            attack.update_command_explanations(command_explanations)
            
            if attack.malware:
                std_mw_hash0, std_mw_obj_list0 = list(attack.standardized_malware.items())[0]
                std_mw_obj0 = std_mw_obj_list0[0]
                malware_source_code = std_mw_obj0.standardized_text

                malware_explainatons = {
                    std_mw_hash0 : 
                        self.openai_analyzer.explain_and_comment_malware(malware_source_code=malware_source_code, commands=split_commands)
                } 
                attack.update_malware_explanations(malware_explainatons)

            else:
                malware_source_code = ""

            questions = ["What is the goal of the attack?",
                        "If the system is vulnerable, do you think the attack will be successful?",
                        "How can a system be protected from this attack?",
                        "What are the indicators of compromise (IOCs)?"]
            
            attack.question_answers = self.openai_analyzer.answer_attack_questions(questions, split_commands, malware_source_code)
            print("Done with attack: " + attack.attack_id)
            

    def get_attack_ipdata(self, attacks=None):
        if not attacks:
            attacks = self.attacks.values()
        
        ipdata = {}
        for attack in attacks:
            ipdata.update(self.ipanalyzer.get_data(attack.uniq_ips_and_urls))
        
        return ipdata



if __name__ == "__main__":

    # Example usage of the AttackAnalyzer class
    analyzer = AttackAnalyzer()

    only_attacks = [
        "fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "440e8a6e0ddc0081c39663b5fcc342a6aa45185eb53c826d5cf6cddd9b87ea64",
        "0229d56a715f09337b329f1f6ced86e68b6d0125747faafdbdb3af2f211f56ac",
        "04a9aabb18e701dbe12c2606538202dc02156f480f3d58d926d20bd9bc613451",
        "275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f",
        "c41b0875c506cc9421ae26ee43bd9821ccd505e9e24a732c8a9c0180eb34a5a8",
        
        ]

    start_time = time()
    attacks = analyzer.load_attacks_from_attack_dir(only_attacks=only_attacks)
    print(f"load_attacks_from_attack_dir\tTime elapsed: {time() - start_time}")
    
    start_time = time()

    ipdata = analyzer.get_attack_ipdata(attacks.values())
    print(ipdata)

    # start_time = time()
    # attacks = analyzer.organize_attacks_from_cowrie_logs(300)
    # print(f"organize_attacks_from_cowrie_logs\tTime elapsed: {time() - start_time}")

    # start_time = time()
    # attacks = analyzer.load_attacks_from_cowrie_logs()
    # print(f"load_attacks_from_cowrie_logs\tTime elapsed: {time() - start_time}")

    
    print(attacks)



















