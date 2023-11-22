from analyzerbase import *

from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor


class CowrieLogAnalyzer(CowrieParser):

    def __init__(self, log_path=test_logs_path, attacks_path=test_attacks_path, remove_ips=MYIPS, overwrite=True):
        super().__init__(log_path, attacks_path, remove_ips, overwrite)

        self.source_ips = {}
        self.attacks = {}
        
        self.exceptions = []
        # self.auth_random = json.loads((self.log_path / "malware" / "auth_random.json").read_bytes())
        

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
        self.ips_with_successful_logins = []
        self.ips_with_commands = []
        self.ips_with_malware = []
        self.ips_with_commands_only = []
            

        for ip, source_ip in self.source_ips.items():
            if source_ip.successful_logins > 0:
                self.ips_with_successful_logins.append(ip)

                if source_ip.commands > 0:
                    self.ips_with_commands.append(ip)

                    if source_ip.downloaded_malware + source_ip.uploaded_malware == 0:
                        self.ips_with_commands_only.append(ip)
                        attack_ids = source_ip.all_cmdlog_hashes
                        attack_id_type = "cmdlog_hash"
                        

                    elif source_ip.downloaded_malware + source_ip.uploaded_malware > 0:
                        self.ips_with_malware.append(ip)
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

        

        self.remove_attacks_with_ips(self.remove_ips)
        self.manual_merge()
        self.merge_attacks_shared_ips_or_hashes()
        
        self.print_stats()
        self.print_attacks()

        print("Done")



    def remove_attacks_with_ips(self, ips_to_remove):
        for attack_id, attack in list(self.attacks.items()):

            for src_ip in attack.all_src_ips:
                if src_ip in ips_to_remove:
                    self.attacks.pop(attack_id)
                    print(f"Removed {attack_id} with src_ip {src_ip}")
                    break

    
    def sort_attacks(self, key=lambda attack: len(attack.source_ips), reverse=True):
        attacks_sorted_by_key_fn = sorted(self.attacks.values(), key=key, reverse=reverse)
        self.attacks = OrderedDict((attack.attack_id, attack) for attack in attacks_sorted_by_key_fn)
        
        return self.attacks

    

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
    

    def print_stats(self):
        print("Stats:")
        print(f"Number of IPs with successful logins: {len(self.ips_with_successful_logins)}")
        print(f"Number of IPs with commands: {len(self.ips_with_commands)}")
        print(f"Number of IPs with commands only: {len(self.ips_with_commands_only)}")
        print(f"Number of IPs with malware: {len(self.ips_with_malware)}")
        print(f"Number of attacks: {len(self.attacks)}")


    def print_attacks(self, include_commands=False):

        print("Attacks:")
        for attack_id in self.attacks:
            print(self.attacks[attack_id])
            if include_commands:
                print("Commands:\n\t" + "\n\t".join(self.attacks[attack_id].commands)+ "\n")






                

if __name__ == "__main__":    
    la = CowrieLogAnalyzer(overwrite=True)
    la.process()
    la.analyze()

    
    print()


