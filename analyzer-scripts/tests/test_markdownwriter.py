from analyzerbase import *
from markdownwriter.markdownwriterbase import *

from markdownwriter.ipmarkdownwriter import IPAnalyzerMarkdownWriter
from markdownwriter.cowrieattackmarkdownwriter import CowrieAttackMarkdownWriter


from markdownwriter.visualizer import CounterGrapher
from netanalyzers.ipanalyzer import IPAnalyzer
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer 
from loganalyzers.attacklogorganizer import AttackLogOrganizer, AttackLogReader

from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY




from main import AttackAnalyzer


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
        grapher = CounterGrapher("/Users/lucasfaudman/Documents/SANS/internship/tests/observations", counter, n=10)
        grapher.plot()
        print(grapher.labels)



class TestMarkdownWriter(TestCase):


    @classmethod
    def setUpClass(cls):
        # Only run this once
        if hasattr(cls, 'cla'):
            return None


        cls.test_keys = [
            "6f09f57fbae18a7e11096ca715d0a91fb05f497c4c7ff7e65dc439a3ee8be953",
            'ea40ecec0b30982fbb1662e67f97f0e9d6f43d2d587f2f588525fae683abea73',
            '8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358',
            #'8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358',
            #'4b055ef0e08e1d87512b8fe62e5f5f1c26c8f427dc357cbbaa9b201afa9bbddc',
        ]

        cls.analyzer = AttackAnalyzer()
        cls.analyzer.load_attacks_from_attack_dir(only_attacks=cls.test_keys)
        cls.analyzer.postprocess_attacks()

    
    def test_cowrie_md(self):

        for key in self.test_keys:
            attack = self.analyzer.attacks[key]
            key = key.replace('/', '_')
            mdw = CowrieAttackMarkdownWriter(f'/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/' + key + '.md', mode="w+", data_object=attack)
            mdw.update_md()


    
    def test_ipanalyzer_md(self):
        for key in self.test_keys:
            attack = self.analyzer.attacks[key]
                
            ips = attack.uniq_ips
            ips.difference_update(("127.0.0.1", "8.8.8.8"))

            ipdata = self.analyzer.ipanalyzer.get_data(ips)
            
            key = key.replace('/', '_')
            ipmdw = IPAnalyzerMarkdownWriter(f'/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/' + key +'.md', mode="a+", data_object=ipdata)
            ipmdw.update_md()        






    