from analyzerbase import *


import unittest
#from tests.test_analyzerbase import *
#from tests.test_loganalyzers import TestZeekParser, TestAttackLogReader
#from tests.test_ipanalyzer import TestIPAnalyzer
#from tests.test_openaianalyzers import *
#from tests.test_loganalyzers import TestAttackDirOrganizer
from tests.test_markdownwriter import TestMarkdownWriter#, TestMarkdownWriterBasics
#from tests.test_openaianalyzers import TestOpenAIAnalyzer

import sys
import threading

test_logs_path = Path("tests/logs")
test_attacks_path = Path("tests/a2")
test_ipdb_path = Path("tests/ipdb")
test_aidb_path = Path("tests/aidb")

class SingleThreadedTextTestRunner(unittest.TextTestRunner):
    def run(self, test):
        
        # Set the maximum number of threads to 1 and run the test
        threading.stack_size(64 * 1024)
        threading.Thread(target=lambda: unittest.TextTestRunner.__getattribute__(self, "run")(test)).start()
        threading.Event().wait()


if __name__ == "__main__":
    
    unittest.main()

    # test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAttackLogOrganizer)
    # SingleThreadedTextTestRunner(stream=sys.stdout).run(test_suite)
    ## SingleThreadedTextTestRunner().run(unittest.TestLoader().discover("tests"))
    
    
    