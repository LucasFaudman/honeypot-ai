from analyzerbase import *


from logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor


class CowrieLogAnalyzer(CowrieParser):

    def __init__(self, log_path=test_logs_path, attacks_path=test_attacks_path, remove_ips=MYIPS, overwrite=True):
        super().__init__(log_path, attacks_path, remove_ips, overwrite)

        # self.overwrite = overwrite
        # self.remove_ips = remove_ips
        # self.log_path = log_path
        # self.attacks_path = attacks_path
        
        self.source_ips = {}
        self.attacks = {}
        
        self.exceptions = []
        self.auth_random = json.loads((self.log_path / "malware" / "auth_random.json").read_bytes())
        

    def process(self):
        for event in self.logs:
            try:
                if event["src_ip"] not in self.source_ips:
                    self.source_ips[event["src_ip"]] = SourceIP(event["src_ip"])

                if event["eventid"] == "cowrie.session.connect":
                    self.source_ips[event["src_ip"]].add_session(event)

                elif event["eventid"].startswith("cowrie.client."):
                    self.source_ips[event["src_ip"]].sessions[event["session"]].add_client_info(event)

                elif event["eventid"].startswith("cowrie.login."):
                    self.source_ips[event["src_ip"]].sessions[event["session"]].add_login_attempt(event)

                elif event["eventid"] == "cowrie.command.input":
                    self.source_ips[event["src_ip"]].sessions[event["session"]].add_command(event)

                elif event["eventid"].startswith("cowrie.session.file_"):
                    self.source_ips[event["src_ip"]].sessions[event["session"]].add_malware(event)

                elif event["eventid"] == "cowrie.log.closed":
                    self.source_ips[event["src_ip"]].sessions[event["session"]].add_ttylog(event)
                
                elif event["eventid"] == "cowrie.session.closed":
                    self.source_ips[event["src_ip"]].sessions[event["session"]].close_session(event)
                    self.source_ips[event["src_ip"]].process_session(event["session"])
            except Exception as e:
                self.exceptions.append((event, e))


    def analyze(self):
        ips_with_successful_logins = []
        ips_with_commands = []
        ips_with_malware = []
        ips_with_commands_only = []
            

        for ip, source_ip in self.source_ips.items():
            if source_ip.successful_logins > 0:
                ips_with_successful_logins.append(ip)

                if source_ip.commands > 0:
                    ips_with_commands.append(ip)

                    if source_ip.downloaded_malware + source_ip.uploaded_malware == 0:
                        ips_with_commands_only.append(ip)
                        attack_ids = source_ip.all_cmdlog_hashes
                        attack_id_type = "cmdlog_hash"
                        

                    elif source_ip.downloaded_malware + source_ip.uploaded_malware > 0:
                        ips_with_malware.append(ip)
                        attack_ids = source_ip.all_malware_hashes
                        attack_id_type = "malware_hash"

                    else: #REMOVE?
                        continue

                    for attack_id in attack_ids:
                        if attack_id is None:
                            continue

                        if attack_id not in self.attacks:
                            self.attacks[attack_id] = Attack(attack_id, attack_id_type, source_ip)
                        else:
                            self.attacks[attack_id].add_source_ip(source_ip)

        
        
        for remove_ip in self.remove_ips:
            self.remove_attacks_with_ip(remove_ip)

        
        self.manual_merge()
        self.merge_attacks_shared_ips_or_hashes()

        print("Stats:")
        print(f"Number of IPs with successful logins: {len(ips_with_successful_logins)}")
        print(f"Number of IPs with commands: {len(ips_with_commands)}")
        print(f"Number of IPs with commands only: {len(ips_with_commands_only)}")
        print(f"Number of IPs with malware: {len(ips_with_malware)}")
        print(f"Number of attacks: {len(self.attacks)}")


        attacks_sorted_by_source_ips = sorted(self.attacks.keys(), key=lambda uuid: len(self.attacks[uuid].source_ips), reverse=True)
        sorted_attacks = OrderedDict()

        print("Attacks:")
        for attack_id in attacks_sorted_by_source_ips:
            sorted_attacks[attack_id] = self.attacks[attack_id]
            print(self.attacks[attack_id])
            #print("Commands:\n\t" + "\n\t".join(self.attacks[attack_id].commands)+ "\n")

        self.attacks = sorted_attacks

        print("Done")


    def manual_merge(self):
        attack_sigs ={
            #re.compile(r">A@/ X'8ELFXLL"): None,
            re.compile(r">\??A@/ ?X'8ELFX"): None,
            re.compile(r"cat /proc/mounts; /bin/busybox [\w\d]+"): None,
            re.compile(r"cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+"): None,
            re.compile(r"cd ~; chattr -ia .ssh; lockr -ia .ssh"): None,
        }


        for attack_id, attack in list(self.attacks.items()):
            for attack_sig in attack_sigs:
                if any(attack_sig.match(command) for command in attack.commands):
                    if not attack_sigs[attack_sig]:
                        attack_sigs[attack_sig] = attack
                    else:
                        print(f"Manual merge {attack.attack_id} into {attack_sigs[attack_sig].attack_id} on {str(attack_sig)}")
                        attack_sigs[attack_sig] += attack
                        self.attacks.pop(attack_id)
        
        #print(attack_sigs)

    def remove_attacks_with_ip(self, ip):
        for attack_id, attack in list(self.attacks.items()):
            if ip in [source_ip.ip for source_ip in attack.source_ips]:
                self.attacks.pop(attack_id)


    def print_shared_ips(self):
        for attack_id, attack in self.attacks.items():
            for attack_id2, attack2 in self.attacks.items():
                if attack_id == attack_id2:
                    continue
                shared_src_ips = set(attack.source_ips).intersection(set(attack2.source_ips))
                if shared_src_ips:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_src_ips)} source IPs: \n{shared_src_ips}")
                    print()


    def print_shared_cmdlog_hashes(self):
        for attack_id, attack in self.attacks.items():
            for attack_id2, attack2 in self.attacks.items():
                if attack_id == attack_id2:
                    continue
                shared_cmdlog_hashes = set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes))
                if shared_cmdlog_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_cmdlog_hashes)} source IPs: \n{shared_cmdlog_hashes}")
                    print()

    def print_shared_malware_hashes(self):
        for attack_id, attack in self.attacks.items():
            for attack_id2, attack2 in self.attacks.items():
                if attack_id == attack_id2:
                    continue
                shared_malware_hashes = set(attack.malware).intersection(set(attack2.malware))
                if shared_malware_hashes:
                    print(f"{attack} and \n{attack2} \nshare {len(shared_malware_hashes)} source IPs: \n{shared_malware_hashes}")
                    print()

    def merge_attacks_shared_ips_or_hashes(self):
        pop_attacks = []
        for attack_id, attack in list(self.attacks.items()):
            for attack_id2, attack2 in list(self.attacks.items()):
                if attack_id == attack_id2 or attack_id in pop_attacks or attack_id2 in pop_attacks:
                    continue

                shared_src_ips = set(attack.source_ips).intersection(set(attack2.source_ips))
                shared_cmdlog_hashes = set(attack.cmdlog_hashes).intersection(set(attack2.cmdlog_hashes))
                shared_malware_hashes = set(attack.malware).intersection(set(attack2.malware))
                if shared_src_ips or shared_cmdlog_hashes or shared_malware_hashes:
                    attack += attack2
                    
                    print(f"Merged {attack_id2} into {attack_id}")
                    pop_attacks.append(attack_id2)
                    continue

                shared_cmdlog_ips = set(attack.all_cmdlog_ips).intersection(set(attack2.all_cmdlog_ips))
                shared_cmdlog_urls = set(attack.all_cmdlog_urls).intersection(set(attack2.all_cmdlog_urls))
                shared_malware_ips = set(attack.all_malware_ips).intersection(set(attack2.all_malware_ips))
                shared_malware_urls = set(attack.all_malware_urls).intersection(set(attack2.all_malware_urls))

                if shared_cmdlog_hashes or shared_cmdlog_ips or shared_cmdlog_urls or shared_malware_hashes or shared_malware_ips or shared_malware_urls:
                    attack += attack2
                    print(f"Merged {attack_id2} into {attack_id} by ip or url")
                    pop_attacks.append(attack_id2)
    
        for attack_id in pop_attacks:
            self.attacks.pop(attack_id)

    def _organize_logs_by_attack(self, attack, attacks_path=test_attacks_path):
        print(f"Start organizing {attack}")
        attack_dir = attacks_path / attack.attack_id
        
        if attack_dir.exists() and not self.overwrite:
            return f"Attack {attack} already exists. Skipping"
        
        if not attack_dir.exists() or self.overwrite:

            attack_dir.mkdir(exist_ok=True, parents=True)
            all_src_ips = set(attack.all_src_ips)
            all_src_ips_regex = re.compile(rb"|".join(ip.encode().replace(b".", rb"\.") for ip in all_src_ips))
            src_ip_regexes = {ip: re.compile(ip.encode().replace(b".", rb"\.")) for ip in all_src_ips}

            for src_ip in all_src_ips:
                source_ip_dir = attack_dir / src_ip
                source_ip_dir.mkdir(exist_ok=True, parents=True)

            for file in self.all_logs:
                if file.name == "auth_random.json":
                    combined_auth_random = {}
                    for src_ip in all_src_ips:
                        src_ip_auth_random = self.auth_random[src_ip]
                        combined_auth_random.update(src_ip_auth_random)

                        out_file = attack_dir / src_ip / file.name
                        json.dump(src_ip_auth_random, out_file.open('w+'), indent=4)
                    
                    out_file = attack_dir / file.name    
                    json.dump(combined_auth_random, out_file.open('w+'), indent=4)    
                    continue

                file_bytes = file.read_bytes()
                if all_src_ips_regex.search(file_bytes):
                    out_file = attack_dir / file.name
                    self.write_matching_lines(file, out_file, all_src_ips_regex)

                    for src_ip, regex in src_ip_regexes.items():
                        
                        if regex.search(file_bytes):
                            out_file = attack_dir / src_ip / file.name
                            self.write_matching_lines(file, out_file, regex)
            
        return f"Done organizing {attack}"

    def organize_logs_by_attack_multi(self, attacks_path=test_attacks_path, max_workers=10):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for result in executor.map(self._organize_logs_by_attack, self.attacks.values()):
                print(result)
          

    def get_log_paths(self, attacks_path=test_attacks_path):
        log_paths = defaultdict(lambda: defaultdict(list))
        for attack_id, attack in self.attacks.items():
            attack_dir = attacks_path / attack_id
            for path in attack_dir.rglob("*"):
                if path.is_file():
                    if path.parent.name == attack_id:
                        log_paths[attack_id]["all"].append(path)
                    else:
                        ip = path.parent.name
                        log_paths[attack_id][ip].append(path)
            
            attack.update_log_paths(log_paths[attack_id])

        return log_paths



                
                
                

                    
    
                


            

if __name__ == "__main__":    
    la = CowrieLogAnalyzer(overwrite=True)
    la.process()
    la.analyze()
    #print(la.get_log_paths())
    #print(la.attacks["a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2"].get_log_counts())

    #la.organize_logs_by_attack() # 1076.96s user 78.03s system 99% cpu 19:20.38 total
    la.organize_logs_by_attack_multi()
    #print(la.get_log_paths())
    #la.print_shared_ips()
    #la.print_shared_cmdlog_hashes()
    #la.print_shared_malware_hashes()

    print()


