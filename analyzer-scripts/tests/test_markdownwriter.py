from analyzerbase import *
from markdownwriter.markdownwriterbase import *

from markdownwriter.ipmarkdownwriter import IPAnalyzerMarkdownWriter
from markdownwriter.cowrieattackmarkdownwriter import CowrieAttackMarkdownWriter


from markdownwriter.visualizer import CounterGrapher
from netanalyzers.ipanalyzer import IPAnalyzer
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer 
from loganalyzers.attacklogorganizer import AttackLogOrganizer, AttackLogReader

from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY
from .test_loganalyzers import AnalyzerTestCase


        

        # self.attacks = self.cla.attacks


class TestMarkdownWriterBasics(TestCase):

    def test_basic_md(self):
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



    def test_convert_md_to_mdtxt_for_canvas(self):
        filepath = '/Users/lucasfaudman/Documents/SANS/internship/BACS-4498/attack-observations/attack-1/observation1.md'
        github_url = 'https://github.com/LucasFaudman/BACS-4498/blob/main/attack-observations/attack-1/observation1.md'
        convert_md_to_mdtxt_for_canvas(filepath, github_url)




    def test_counter_grapher(self):
        counter = Counter(['A', 'B', 'A', 'C', 'B', 'A', 'D', 'C', 'A', 'B', 'E'])
        grapher = CounterGrapher("/Users/lucasfaudman/Documents/SANS/internship/tests/observations", counter)
        grapher.plot()




class TestMarkdownWriter(AnalyzerTestCase):


    @classmethod
    def setUpClass(cls):
        # Only run this once
        if hasattr(cls, 'cla'):
            return None

        cls.cla = CowrieLogAnalyzer(test_logs_path, test_attacks_path, overwrite=True)
        cls.alo = AttackLogOrganizer(test_logs_path, test_attacks_path, overwrite=True)
        cls.alr = AttackLogReader(test_logs_path, test_attacks_path, overwrite=True)
        cls.ia = IPAnalyzer(
            db_path=str(test_logs_path).replace("logs", "ipdb"), 
            output_path=test_attacks_path,
        )
        cls.oa = OpenAIAnalyzer(
            db_path=str(test_logs_path).replace("logs", "aidb"),
        )
        

        cls.cla.process()
        cls.cla.analyze()

        cls.attacks = cls.cla.attacks
        cls.alr.set_attacks(cls.attacks)
        cls.alo.set_attacks(cls.attacks)

        for message in cls.alo.organize():
            print(message)
        
        cls.alr.update_all_log_paths_and_counts()


    def test_ipanalyzer_md(self):    
        ips = ['80.94.92.20']
        ipanalyzer = IPAnalyzer()

        ipdata = ipanalyzer.get_data(ips)
        ips_str = '_'.join(ips)

        mdw = IPAnalyzerMarkdownWriter(f'tests/attacks/{ips_str}.md', mode="w+", data_object=ipdata)
        mdw.update_md()
    



    def test_cowrieattack_md(self):

    

        keys = [
                "ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b",
                'ea40ecec0b30982fbb1662e67f97f0e9d6f43d2d587f2f588525fae683abea73',
            'a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9',
            '8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358',
            '4b055ef0e08e1d87512b8fe62e5f5f1c26c8f427dc357cbbaa9b201afa9bbddc',
        ]

        openai_analyzer = OpenAIAnalyzer()

        for key in keys:
            attack = self.cla.attacks[key]
            
            split_commands = attack.split_commands
            command_explanations = openai_analyzer.explain_commands(split_commands)
            attack.update_command_explanations(command_explanations)
            
            if attack.malware:
                std_mw_hash0, std_mw_obj_list0 = list(attack.standardized_malware.items())[0]
                std_mw_obj0 = std_mw_obj_list0[0]
                malware_explainatons = {std_mw_hash0: openai_analyzer.explain_and_comment_malware(malware_source_code=std_mw_obj0.standardized_text, commands=split_commands)} 
                attack.update_malware_explanations(malware_explainatons)

                malware_source_code = std_mw_obj0.standardized_text
            else:
                malware_source_code = ""

            questions = ["What is the goal of the attack?",
                        "If the system is vulnerable, do you think the attack will be successful?",
                        "How can a system be protected from this attack?",
                        "What are the indicators of compromise (IOCs)?"]
            
            attack.question_answers = openai_analyzer.answer_attack_questions(questions, split_commands, malware_source_code)



            attack.add_postprocessor(self.alr)
            self.alr.update_attack_log_counts(attack)

            key = key.replace('/', '_')
            mdw = CowrieAttackMarkdownWriter(f'/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/' + key + '.md', mode="w+", data_object=attack)
            mdw.update_md()


            ipa = IPAnalyzer()
            ips = attack.uniq_ips
            ips.difference_update(("127.0.0.1", "8.8.8.8"))

            ipdata = ipa.get_data(ips)
            
            ipmdw = IPAnalyzerMarkdownWriter(f'/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/' + key +'.md', mode="a+", data_object=ipdata)
            ipmdw.update_md()