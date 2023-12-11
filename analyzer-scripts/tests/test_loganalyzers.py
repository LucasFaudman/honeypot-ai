from time import time


from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer
from loganalyzers.webloganalyzer import WebLogAnalyzer
from loganalyzers.attackdirorganizer import AttackDirOrganizer, ThreadPoolExecutor, ProcessPoolExecutor
from loganalyzers.attackdirreader import AttackDirReader


test_logs_path = Path("tests/logs")
test_attacks_path = Path("tests/a2")





class SetupOnceTestCase(TestCase):
    _setup_done = False

    @classmethod
    def setUpClass(cls):
        """Subclass should implement this method with super() call as first line"""

        # Prevent this from running more than once when subclassed
        if cls._setup_done:
            return None
        else:
            cls._setup_done = True





class ParserTestCase(SetupOnceTestCase):
    _parser_cls = LogParser

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        
        cls.parser = cls._parser_cls(test_logs_path)
        cls.logs_per_test = 50

        

    def _print_log_loop(self, log_iter):
        logs = 0
        for log in log_iter:
            print(log)
            
            logs += 1
            if logs >= self.logs_per_test:
                break

    def test_read_nlogs(self):
        self._print_log_loop(self.parser.nlogs(self.logs_per_test))



class TestCowrieParser(ParserTestCase):
    _parser_cls = CowrieParser


class TestWebLogParser(ParserTestCase):
    _parser_cls = WebLogParser


class TestDshieldParser(ParserTestCase):
    _parser_cls = DshieldParser

    
        
class TestWebLogAnalyzer(SetupOnceTestCase):
        
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.parser = WebLogParser(test_logs_path)
        cls.analyzer = WebLogAnalyzer(cls.parser)

    def test_process(self):
        source_ips = self.analyzer.process()


    def test_analyze(self):
        attacks = self.analyzer.analyze()




class CowrieAnalyzerTestCase(SetupOnceTestCase):
    _setup_done = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        cls.parser = CowrieParser(test_logs_path)
        cls.analyzer = CowrieLogAnalyzer(cls.parser)

        cls.source_ips = cls.analyzer.process()
        cls.attacks = cls.analyzer.analyze()

        cls.attacks = cls.analyzer.attacks
        cls.attack0 = list(cls.attacks.values())[0]












class TestCowrieLogAnalyzer(CowrieAnalyzerTestCase):
    

    # @classmethod
    # def setUpClass(cls):
    #     super().setUpClass()

    def test_process(self):
        source_ips = self.source_ips #self.analyzer.process()
        self.assertGreater(len(source_ips), 0)
        self.assertIsInstance(source_ips, dict)
        self.assertIsInstance(list(source_ips.values())[0], SourceIP)
        self.assertIsInstance(list(source_ips.values())[0].sessions, dict)


    def test_analyze(self):
        attacks = self.attacks#self.analyzer.analyze()
        self.assertGreater(len(attacks), 0)
        self.assertIsInstance(attacks, dict)
        self.assertIsInstance(list(attacks.values())[0], Attack)
        self.assertIsInstance(list(attacks.values())[0].source_ips, list)
        self.assertIsInstance(list(attacks.values())[0].source_ips[0], SourceIP)
        self.assertIsInstance(list(attacks.values())[0].source_ips[0].sessions, dict)
        

    def test_no_shared_ips(self):
        shared_src_ips = set()
        for attack_id, attack in self.analyzer.attacks.items():
            for attack_id2, attack2 in self.analyzer.attacks.items():
                if attack_id == attack_id2:
                    continue
                #shared_src_ips = set(attack.source_ips).intersection(set(attack2.source_ips))
                shared_src_ips.update(set(attack.source_ips).intersection(set(attack2.source_ips)))
                if shared_src_ips:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_src_ips)} source IPs: \n{shared_src_ips}")
                    print()
                self.assertTrue(len(shared_src_ips) == 0)


    def test_no_shared_cmdlog_hashes(self):
        shared_cmdlog_hashes = set()
        for attack_id, attack in self.analyzer.attacks.items():
            for attack_id2, attack2 in self.analyzer.attacks.items():
                if attack_id == attack_id2:
                    continue

                #shared_cmdlog_hashes = set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes))
                shared_cmdlog_hashes.update( set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes)))

                if shared_cmdlog_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_cmdlog_hashes)} source IPs: \n{shared_cmdlog_hashes}")
                    print()
                    
                self.assertTrue(len(shared_cmdlog_hashes) == 0)


    def test_no_shared_malware_hashes(self):
        shared_malware_hashes = set()
        for attack_id, attack in self.analyzer.attacks.items():
            for attack_id2, attack2 in self.analyzer.attacks.items():
                if attack_id == attack_id2:
                    continue
                
                #shared_malware_hashes = set(attack.malware).intersection(set(attack2.malware))
                shared_malware_hashes.update(set(attack.malware).intersection(set(attack2.malware)))
                if shared_malware_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_malware_hashes)} source IPs: \n{shared_malware_hashes}")
                    print()

                self.assertTrue(len(shared_malware_hashes) == 0)


    def test_no_shared_sshhashs(self):
        shared_ssh_hashes = set()
        for attack_id, attack in self.analyzer.attacks.items():
            for attack_id2, attack2 in self.analyzer.attacks.items():
                if attack_id == attack_id2:
                    continue
                
                
                shared_ssh_hashes.update(set(attack.ssh_hashes).intersection(set(attack2.ssh_hashes)))
                if shared_ssh_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_ssh_hashes)} source IPs: \n{shared_ssh_hashes}")
                    print()

                self.assertTrue(len(shared_ssh_hashes) == 0)








class TestAttackDirReader(CowrieAnalyzerTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()


        cls.attack_log_reader = AttackDirReader(cls.parser, test_attacks_path, attacks=cls.attacks)
        

    
    def test_attack_log_reader_counts(self):
        print(self.attack0)
        self.attack0.add_postprocessor(self.attack_log_reader)
        self.attack_log_reader.update_all_log_paths()
        self.attack_log_reader.update_all_log_counts()

        print(self.attack0.get_log_paths())
        print(self.attack0.get_log_names())
        print(self.attack0.log_counts)


        self.assertGreaterEqual(len(self.attack0.get_log_paths()), 0)
        self.assertGreaterEqual(len(self.attack0.get_log_names()), 0)
        self.assertGreaterEqual(len(self.attack0.log_counts), 0)
        
        self.assertIn("cowrie.log", self.attack0.log_counts["all"])
        self.assertIn("cowrie.json", self.attack0.log_counts["all"])


    def test_get_attack_log_lines(self):
        self.attack_log_reader.update_all_log_paths()
        self.attack_log_reader.update_all_log_counts()

        total_lines = 0
        for log_filter in ["cowrie.log", "cowrie.json", "web.json", "dshield.log", "zeek.log"]:
            for session in [self.attack0.first_session, self.attack0.last_session]:
            
            
                ip = session.src_ip 
                line_filter = session.session_id if "cowrie" in log_filter else ""
                log_lines = self.attack_log_reader.get_attack_log_lines(self.attack0, ip, log_filter, line_filter, n_lines=None)
                total_lines += len(log_lines)

                print(log_lines)
                print()
                #self.assertGreater(len(log_lines), 0)
                self.assertGreater(total_lines, 0)
        












class TestAttackDirOrganizer(CowrieAnalyzerTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()


        cls.attack_log_reader = AttackDirReader(cls.parser, test_attacks_path, attacks=cls.attacks)
        cls.attack_log_organizer = AttackDirOrganizer(cls.parser, test_attacks_path, attacks=cls.attacks)

        cls.run_times = {}
        cls.max_workers = 10
        cls.chunksize = 1


    def test_organize(self):
        for iterby in ["logs", "attacks"]:
            for executor_cls in [None, ThreadPoolExecutor, ProcessPoolExecutor]:
                for yield_order in ["as_completed", "as_submitted"]:
                    start_time = time()
                    for output in self.attack_log_organizer.organize(
                            iterby=iterby, 
                            executor_cls=executor_cls, 
                            max_workers=self.max_workers, 
                            chunksize=self.chunksize, 
                            yield_order=yield_order
                            ):
                                print(output)
                    
                    elapsed_time = time() - start_time
                    test_name = f"test_organize_{iterby}_{executor_cls}_{yield_order}"
                    print(f"{test_name}\nElapsed Time:{elapsed_time}")
                    self.run_times[test_name] = elapsed_time
        

        sorted_run_times = sorted(self.run_times.items(), key=lambda item: item[1])
        for test_name, elapsed_time in sorted_run_times:
            print(f"{test_name}: {elapsed_time}")



        """
        test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 7630.16948723793
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 8236.926615953445
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 8770.862429857254
test_organize_attacks_None_as_completed: 8916.230272054672
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 8944.795355081558
test_organize_logs_None_as_submitted: 8954.41579413414
test_organize_attacks_None_as_submitted: 9314.279464244843
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 9451.206767082214
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 10328.38061618805
test_organize_logs_None_as_completed: 10841.376113891602
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 11813.116040229797
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 12423.709311962128
        """




























