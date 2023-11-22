from analyzerbase import *

from netanalyzers.ipanalyzer import IPAnalyzer
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer, Attack
from openaianalyzers.openaianalyzer import OpenAIAnalyzer


class TestOpenAIAnalyzer(TestCase):
    def setUp(self):
        self.ai = OpenAIAnalyzer(test_logs_path, test_attacks_path)
        self.ips = ['80.94.92.20']