from time import time


from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer
from loganalyzers.webloganalyzer import WebLogAnalyzer
from loganalyzers.attacklogorganizer import AttackLogOrganizer, AttackLogReader



test_logs_path = Path("tests/tl2")
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










class TestAttackLogReader(CowrieAnalyzerTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()


        cls.attack_log_reader = AttackLogReader(cls.parser, test_attacks_path, attacks=cls.attacks)
        #cls.attack_log_reader.set_attacks(cls.attacks)
        #cls.attack_log_reader.update_all_log_paths_and_counts()

        #cls.attack0.add_postprocessor(cls.attack_log_reader)
        #cls.attack0.
        #

    
    def test_attack_log_reader_counts(self):
        print(self.attack0)

        log_paths_before = self.attack0.get_log_paths()
        log_names_before = self.attack0.get_log_names()
        log_counts_before = self.attack0.log_counts

        print(self.attack0.get_log_paths())
        print(self.attack0.get_log_names())
        print(self.attack0.log_counts)
        
        self.assertEqual(log_paths_before, [])
        self.assertEqual(log_names_before, [])
        self.assertDictEqual(log_counts_before, {'all': {}})

        
        self.attack_log_reader.update_all_log_paths()
        self.attack_log_reader.update_all_log_counts()

        print(self.attack0.get_log_paths())
        print(self.attack0.get_log_names())
        print(self.attack0.log_counts)

        self.assertNotEqual(log_paths_before,  self.attack0.get_log_paths())
        self.assertNotEqual(log_names_before, self.attack0.get_log_names())
        self.assertNotEqual(log_counts_before, self.attack0.log_counts)
        
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
        



class TestAttackLogOrganizer(CowrieAnalyzerTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()


        cls.attack_log_reader = AttackLogReader(cls.parser, test_attacks_path, attacks=cls.attacks)
        cls.attack_log_organizer = AttackLogOrganizer(cls.parser, test_attacks_path, attacks=cls.attacks)

        cls.run_times = {}
        cls.max_workers = 10
        cls.chunksize = 2




    def test_organize_by_iter_logs(self):
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_logs():
            print(output)
        fn_name = "test_organize_by_iter_logs"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()
        


    def test_organize_by_iter_attacks(self):
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_attacks():
            print(output)
        fn_name = "test_organize_by_iter_attacks"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        #self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_logs_multithreaded(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_logs_multithreaded(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_logs_multithreaded"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_attacks_multithreaded(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_attacks_multithreaded(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_attacks_multithreaded"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_logs_multiprocess(self):

        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_logs_multiprocess(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_logs_multiprocess"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_attacks_multiprocess(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.attack_log_organizer.organize_by_iter_attacks_multiprocess(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_attacks_multiprocess"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time: {elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()

    
    
    def test_print_run_times(self):
        sorted_run_times = sorted(self.run_times.items(), key=lambda item: item[1])
        for fn_name, elapsed_time in sorted_run_times:
            print(f"{fn_name}: {elapsed_time}")




























# class AnalyzerTestCase(TestCase):
#     _setup_done = False

    
#     @classmethod
#     def setUpClass(cls):

#         # Prevent this from running more than once when subclassed
#         if cls._setup_done:
#             return None
#         else:
#             cls._setup_done = True

#         cls.cp = CowrieParser(test_logs_path)
#         cls.wlp = WebLogParser(test_logs_path)
#         cls.dshp = DshieldParser(test_logs_path)

        
#         cls.wla = WebLogAnalyzer(cls.wlp, test_attacks_path)
#         cls.wla.process()
#         cls.wla.analyze()

#         cls.cla = CowrieLogAnalyzer(cls.cp)
#         cls.cla.process()
#         cls.cla.analyze()


#         cls.attacks = cls.cla.attacks
#         cls.attack0 = list(cls.attacks.values())[0]

#         cls.alr = AttackLogReader(cls.cp, attacks_path=test_attacks_path, attacks=cls.attacks)
#         cls.alr.set_attacks(cls.attacks)

#         cls.alo = AttackLogOrganizer(cls.cp, attacks_path=test_attacks_path, attacks=cls.attacks)
#         cls.alo.set_attacks(cls.attacks)


#         # for message in cls.alo.organize():
#         #     print(message)
#         cls.alr.update_all_log_paths_and_counts()


# class OFFTestAttackLogOrganizer(AnalyzerTestCase):
#     @classmethod
#     def setUpClass(cls):
#         super().setUpClass()


#         cls.run_times = {}

#         cls.max_workers = 10
#         cls.chunksize = 1

#         """
#         10,1
#         test_organize_by_iter_attacks_multiprocess  Elapsed Time:11.957556009292603
#         test_organize_by_iter_logs_multiprocess     Elapsed Time:12.045604705810547
#         test_organize_by_iter_attacks_multithreaded Elapsed Time:14.502341032028198
#         test_organize_by_iter_logs_multithreaded    Elapsed Time:15.098825931549072
#         test_organize_by_iter_attacks               Elapsed Time:16.647027015686035
#         test_organize_by_iter_logs                  Elapsed Time:18.170916080474854

#         10,2
#         .test_organize_by_iter_attacks_multiprocess: 15.708395004272461
#         test_organize_by_iter_attacks: 17.134219646453857
#         test_organize_by_iter_attacks_multithreaded: 19.463297128677368
#         test_organize_by_iter_logs_multithreaded: 22.91446805000305
#         test_organize_by_iter_logs_multiprocess: 28.85531210899353
#         test_organize_by_iter_logs: 29.179450035095215


#         cls.max_workers = 4
#         cls.chunksize = 1
#         test_organize_by_iter_attacks_multiprocess: 14.969735860824585
#         test_organize_by_iter_attacks_multithreaded: 15.034394979476929
#         test_organize_by_iter_attacks: 17.7277410030365
#         test_organize_by_iter_logs_multithreaded: 20.914682865142822
#         test_organize_by_iter_logs: 24.679287910461426
#         test_organize_by_iter_logs_multiprocess: 24.913766145706177

        
#         8,5
#         test_organize_by_iter_attacks_multiprocess: 17.404871940612793
#         test_organize_by_iter_attacks: 17.561967134475708
#         test_organize_by_iter_attacks_multithreaded: 20.039499044418335
#         test_organize_by_iter_logs_multiprocess: 28.44809579849243
#         test_organize_by_iter_logs: 29.09297776222229
#         test_organize_by_iter_logs_multithreaded: 29.267180919647217
#         """

#     def test_organize_by_iter_logs(self):
#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_logs():
#             print(output)
#         fn_name = "test_organize_by_iter_logs"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time:{elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         ##self.alr.update_all_log_paths_and_counts()
        


#     def test_organize_by_iter_attacks(self):
#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_attacks():
#             print(output)
#         fn_name = "test_organize_by_iter_attacks"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time:{elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         #self.alr.update_all_log_paths_and_counts()



#     def test_organize_by_iter_logs_multithreaded(self):
        
#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_logs_multithreaded(self.max_workers, self.chunksize):
#             print(output)
#         fn_name = "test_organize_by_iter_logs_multithreaded"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time:{elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         ##self.alr.update_all_log_paths_and_counts()



#     def test_organize_by_iter_attacks_multithreaded(self):
        
#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_attacks_multithreaded(self.max_workers, self.chunksize):
#             print(output)
#         fn_name = "test_organize_by_iter_attacks_multithreaded"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time:{elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         ##self.alr.update_all_log_paths_and_counts()



#     def test_organize_by_iter_logs_multiprocess(self):

#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_logs_multiprocess(self.max_workers, self.chunksize):
#             print(output)
#         fn_name = "test_organize_by_iter_logs_multiprocess"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time:{elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         ##self.alr.update_all_log_paths_and_counts()



#     def test_organize_by_iter_attacks_multiprocess(self):
        
#         #self.alr.update_all_log_paths_and_counts()

#         start_time = time()
#         for output in self.alo.organize_by_iter_attacks_multiprocess(self.max_workers, self.chunksize):
#             print(output)
#         fn_name = "test_organize_by_iter_attacks_multiprocess"
#         elapsed_time = time() - start_time
#         print(f"{fn_name}\nElapsed Time: {elapsed_time}")
#         self.run_times[fn_name] = elapsed_time
        
#         ##self.alr.update_all_log_paths_and_counts()

    
    
#     def test_print_run_times(self):
#         sorted_run_times = sorted(self.run_times.items(), key=lambda item: item[1])
#         for fn_name, elapsed_time in sorted_run_times:
#             print(f"{fn_name}: {elapsed_time}")
