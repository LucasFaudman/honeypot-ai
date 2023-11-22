from time import time


from analyzerbase import *
from loganalyzers.logparser import LogParser, CowrieParser, WebLogParser, DshieldParser
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer
from loganalyzers.webloganalyzer import WebLogAnalyzer
from loganalyzers.attacklogorganizer import AttackLogOrganizer, AttackLogReader



class AnalyzerTestCase(TestCase):
    _setup_done = False

    
    @classmethod
    def setUpClass(cls):

        # Prevent this from running more than once when subclassed
        if cls._setup_done:
            return None
        else:
            cls._setup_done = True

        cls.cp = CowrieParser()
        cls.wlp = WebLogParser()
        cls.dshp = DshieldParser()

        
        cls.wla = WebLogAnalyzer(test_logs_path, test_attacks_path)
        cls.wla.process()
        cls.wla.analyze()

        cls.cla = CowrieLogAnalyzer(test_logs_path, test_attacks_path, overwrite=True)
        cls.cla.process()
        cls.cla.analyze()


        cls.attacks = cls.cla.attacks
        cls.attack0 = list(cls.attacks.values())[0]

        cls.alr = AttackLogReader()
        cls.alr.set_attacks(cls.attacks)

        cls.alo = AttackLogOrganizer()
        cls.alo.set_attacks(cls.attacks)


        # for message in cls.alo.organize():
        #     print(message)
        cls.alr.update_all_log_paths_and_counts()
        



class TestCowrieLogParser_InitAndReadAll(AnalyzerTestCase):
    
    def setUp(self):
        super().setUp()
        #setup_analyzers(self)
        self.logs_per_test = 50

    def _print_log_loop(self, log_iter):
        logs = 0
        for log in log_iter:
            print(log)
            
            logs += 1
            if logs >= self.logs_per_test:
                break


    def test_init_cowrie(self):
        cp = CowrieParser()
        print(cp.logs)

        self._print_log_loop(cp.logs)
        self._print_log_loop(cp.nlogs(self.logs_per_test))


    def test_init_weblog(self):
        wp = WebLogParser()
        self._print_log_loop(wp.logs)
        self._print_log_loop(wp.nlogs(self.logs_per_test))


    def test_init_dshield(self):
        dp = DshieldParser()
        self._print_log_loop(dp.logs)
        self._print_log_loop(dp.nlogs(self.logs_per_test))


    def test_init_cowrie_analyzer(self):
        cla = CowrieLogAnalyzer()
        self._print_log_loop(cla.logs)
        self._print_log_loop(cla.nlogs(self.logs_per_test))

    
    def test_init_weblog_analyzer(self):
        wla = WebLogAnalyzer()
        self._print_log_loop(wla.logs)




        
class TestCowrieLogParser_NoSharedIPsOrHashes(AnalyzerTestCase):

    def setUp(self):
        #setup_analyzers(self)
        super().setUp()

    def test_print_shared_ips(self):
        shared_src_ips = set()
        for attack_id, attack in self.cla.attacks.items():
            for attack_id2, attack2 in self.cla.attacks.items():
                if attack_id == attack_id2:
                    continue
                #shared_src_ips = set(attack.source_ips).intersection(set(attack2.source_ips))
                shared_src_ips.update(set(attack.source_ips).intersection(set(attack2.source_ips)))
                if shared_src_ips:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_src_ips)} source IPs: \n{shared_src_ips}")
                    print()
                self.assertTrue(len(shared_src_ips) == 0)


    def test_shared_cmdlog_hashes(self):
        shared_cmdlog_hashes = set()
        for attack_id, attack in self.cla.attacks.items():
            for attack_id2, attack2 in self.cla.attacks.items():
                if attack_id == attack_id2:
                    continue

                #shared_cmdlog_hashes = set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes))
                shared_cmdlog_hashes.update( set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes)))

                if shared_cmdlog_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_cmdlog_hashes)} source IPs: \n{shared_cmdlog_hashes}")
                    print()
                    
                self.assertTrue(len(shared_cmdlog_hashes) == 0)

    def test_shared_malware_hashes(self):
        shared_malware_hashes = set()
        for attack_id, attack in self.cla.attacks.items():
            for attack_id2, attack2 in self.cla.attacks.items():
                if attack_id == attack_id2:
                    continue
                
                #shared_malware_hashes = set(attack.malware).intersection(set(attack2.malware))
                shared_malware_hashes.update(set(attack.malware).intersection(set(attack2.malware)))
                if shared_malware_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_malware_hashes)} source IPs: \n{shared_malware_hashes}")
                    print()

                self.assertTrue(len(shared_malware_hashes) == 0)


class TestAttackLogReader(AnalyzerTestCase):

    def setUp(self):
        super().setUp()

    
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
        self.assertDictEqual(log_counts_before, {})


        self.alr.update_all_log_paths()
        self.alr.update_all_log_counts()

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
        self.alr.update_all_log_paths()
        self.alr.update_all_log_counts()

        total_lines = 0
        for log_filter in ["cowrie.log", "cowrie.json", "web.json", "dshield.log", "zeek.log"]:
            for session in [self.attack0.first_session, self.attack0.last_session]:
            
            
                ip = session.src_ip 
                line_filter = session.session_id if "cowrie" in log_filter else ""
                log_lines = self.alr.get_attack_log_lines(self.attack0, ip, log_filter, line_filter, n_lines=None)
                total_lines += len(log_lines)

                print(log_lines)
                print()
                #self.assertGreater(len(log_lines), 0)
                self.assertGreater(total_lines, 0)
        



class OFFTestAttackLogOrganizer(AnalyzerTestCase):
    def setUp(self):
        super().setUp()

#        self.alr.update_all_log_paths_and_counts()


        self.run_times = {}

        self.max_workers = 10
        self.chunksize = 1

        """
        test_organize_by_iter_attacks_multiprocess  Elapsed Time:11.957556009292603
        test_organize_by_iter_logs_multiprocess     Elapsed Time:12.045604705810547
        test_organize_by_iter_attacks_multithreaded Elapsed Time:14.502341032028198
        test_organize_by_iter_logs_multithreaded    Elapsed Time:15.098825931549072
        test_organize_by_iter_attacks               Elapsed Time:16.647027015686035
        test_organize_by_iter_logs                  Elapsed Time:18.170916080474854
        """

    def test_organize_by_iter_logs(self):
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_logs():
            print(output)
        fn_name = "test_organize_by_iter_logs"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()
        


    def test_organize_by_iter_attacks(self):
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_attacks():
            print(output)
        fn_name = "test_organize_by_iter_attacks"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        #self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_logs_multithreaded(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_logs_multithreaded(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_logs_multithreaded"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_attacks_multithreaded(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_attacks_multithreaded(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_attacks_multithreaded"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_logs_multiprocess(self):

        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_logs_multiprocess(self.max_workers, self.chunksize):
            print(output)
        fn_name = "test_organize_by_iter_logs_multiprocess"
        elapsed_time = time() - start_time
        print(f"{fn_name}\nElapsed Time:{elapsed_time}")
        self.run_times[fn_name] = elapsed_time
        
        ##self.alr.update_all_log_paths_and_counts()



    def test_organize_by_iter_attacks_multiprocess(self):
        
        #self.alr.update_all_log_paths_and_counts()

        start_time = time()
        for output in self.alo.organize_by_iter_attacks_multiprocess(self.max_workers, self.chunksize):
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
