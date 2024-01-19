from time import time


from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser, ZeekParser
from loganalyzers.logprocessor import LogProcessor
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
        cls.logs_per_test = 10

        

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

class TestZeekParser(ParserTestCase):
    _parser_cls = ZeekParser


            





class LogProcessorTestCase(SetupOnceTestCase):
    _setup_done = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        cls.parser = CowrieParser(test_logs_path)
        cls.logprocessor = LogProcessor(cls.parser)

        cls.source_ips = cls.logprocessor.process()
        cls.attacks = cls.logprocessor.analyze()

        cls.attacks = cls.logprocessor.attacks
        cls.attack0 = list(cls.attacks.values())[0]







class TestLogProcessor(LogProcessorTestCase):
    

    # @classmethod
    # def setUpClass(cls):
    #     super().setUpClass()

    def test_process(self):
        source_ips = self.source_ips #self.logprocessor.process()
        self.assertGreater(len(source_ips), 0)
        self.assertIsInstance(source_ips, dict)
        self.assertIsInstance(list(source_ips.values())[0], SourceIP)
        self.assertIsInstance(list(source_ips.values())[0].sessions, dict)


    def test_analyze(self):
        attacks = self.attacks#self.logprocessor.analyze()
        self.assertGreater(len(attacks), 0)
        self.assertIsInstance(attacks, dict)
        self.assertIsInstance(list(attacks.values())[0], Attack)
        self.assertIsInstance(list(attacks.values())[0].source_ips, list)
        self.assertIsInstance(list(attacks.values())[0].source_ips[0], SourceIP)
        self.assertIsInstance(list(attacks.values())[0].source_ips[0].sessions, dict)
        

    def test_no_shared_ips(self):
        shared_src_ips = set()
        for attack_id, attack in self.logprocessor.attacks.items():
            for attack_id2, attack2 in self.logprocessor.attacks.items():
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
        for attack_id, attack in self.logprocessor.attacks.items():
            for attack_id2, attack2 in self.logprocessor.attacks.items():
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
        for attack_id, attack in self.logprocessor.attacks.items():
            for attack_id2, attack2 in self.logprocessor.attacks.items():
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
        for attack_id, attack in self.logprocessor.attacks.items():
            for attack_id2, attack2 in self.logprocessor.attacks.items():
                if attack_id == attack_id2:
                    continue
                
                
                shared_ssh_hashes.update(set(attack.ssh_hashes).intersection(set(attack2.ssh_hashes)))
                if shared_ssh_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_ssh_hashes)} source IPs: \n{shared_ssh_hashes}")
                    print()

                self.assertTrue(len(shared_ssh_hashes) == 0)








class TestAttackDirReader(LogProcessorTestCase):

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
        












class TestAttackDirOrganizer(LogProcessorTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        max_src_ips = 300
        for attack_id, attack in list(cls.attacks.items()):
            if attack.num_src_ips > max_src_ips:
                del cls.attacks[attack_id]

        cls.attack_log_reader = AttackDirReader(cls.parser, test_attacks_path, attacks=cls.attacks)
        cls.attack_log_organizer = AttackDirOrganizer(cls.parser, test_attacks_path, attacks=cls.attacks)

        cls.run_times = {}
        cls.chunksize = 1
        cls.max_workers = 64#len(cls.parser.all_logs) // cls.chunksize
        


    def test_organize(self):
       
        for iterby in ["logs"]:
            for executor_cls in [ProcessPoolExecutor]:
                for yield_order in ["as_completed", "as_submitted"]:
                     for workers in [None, 4, 8, 16, 32, 64]:
                        test_name = f"test_organize_{iterby}_{executor_cls}_{yield_order}_workers{workers}"
                        
                        print(f"Starting {test_name}")
                        start_time = time()
                        for output in self.attack_log_organizer.organize(
                                iterby=iterby, 
                                executor_cls=executor_cls, 
                                max_workers=workers, 
                                chunksize=self.chunksize, 
                                yield_order=yield_order
                                ):
                                    print(output)
                        
                        elapsed_time = time() - start_time
                        
                        print(f"{test_name}\nElapsed Time:{elapsed_time}")
                        self.run_times[test_name] = elapsed_time
        

        # sorted_run_times = sorted(self.run_times.items(), key=lambda item: item[1])
        # for test_name, elapsed_time in sorted_run_times:
        #     print(f"{test_name}: {elapsed_time}")


    def __del__(self):

        sorted_run_times = sorted(self.run_times.items(), key=lambda item: item[1])
        print("Run Times")
        for test_name, elapsed_time in sorted_run_times:
            print(f"{test_name}: {elapsed_time}")


        """
        workers 10 chunk 1 max ips 300
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 324.03170919418335
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 369.38719272613525
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 523.2878358364105
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 553.8866717815399
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 844.5508642196655
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 981.7759490013123
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 1007.1715548038483
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 1037.2253878116608
        workers len(attacks) chunk 1 max ips 100
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 88.52793908119202
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 104.30426621437073
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 197.39882612228394
test_organize_logs_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 202.03842282295227
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 249.4189260005951
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 268.5438690185547
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_completed: 509.41456508636475
test_organize_attacks_<class 'concurrent.futures.thread.ThreadPoolExecutor'>_as_submitted: 566.7465331554413
         workers 16 chunk 1 max ips 100
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 83.2666449546814
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 93.89256930351257
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 179.68486309051514
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 182.97649693489075
        
         workers 32 chunk 1 max ips 100        
        test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 93.98449611663818
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 100.07887101173401
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed: 165.66290807724
test_organize_attacks_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted: 187.36473512649536
       100
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers8: 58.42835521697998
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers4: 60.94567823410034
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers16: 70.14051914215088
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workersNone: 71.40870118141174
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers4: 73.83851289749146
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers32: 77.10387802124023
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers32: 78.61152410507202
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers64: 93.86401915550232
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers64: 100.53227877616882
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers16: 102.84343123435974
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers8: 336.077513217926
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workersNone: 362.6425108909607
       
    100-2
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers8: 60.50324988365173
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workersNone: 61.942856788635254
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers8: 63.99519991874695
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers16: 68.33112096786499
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers16: 69.19294905662537
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workersNone: 70.48339796066284
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers32: 79.01031589508057
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers4: 81.41323208808899
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers4: 81.835688829422
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers32: 82.59684610366821
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers64: 99.24746012687683
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers64: 105.03146171569824
       300
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers16: 257.0312201976776
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workersNone: 257.82834100723267
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers16: 260.7398998737335
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers32: 265.5802381038666
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers32: 266.3524088859558
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workersNone: 266.5461208820343
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers8: 273.60535407066345
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers8: 276.8002231121063
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers64: 278.818696975708
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers64: 288.2485980987549
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_completed_workers4: 332.9143931865692
test_organize_logs_<class 'concurrent.futures.process.ProcessPoolExecutor'>_as_submitted_workers4: 339.46687483787537
       
       """




























