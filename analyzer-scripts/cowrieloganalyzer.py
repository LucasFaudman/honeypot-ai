import re
import hashlib 
from collections import defaultdict, OrderedDict, Counter
import os
import pathlib
import json
from datetime import datetime
from pprint import pprint
import tldextract

from logreader import Cowrie, test_logs_path, test_attacks_path
from concurrent.futures import ThreadPoolExecutor


MYIPS = os.environ.get("MYIPS", "").split(",")



def standardize_cmdlog(command):
    regexes = [
        re.compile(r"/bin/busybox (\w+)"),
        re.compile(r"/tmp/([\w\d]+)"),
        re.compile(r"/tmp/[\w\d]+ ([\w/\+]+)"),
        re.compile(r"(\d+\.\d+\.\d+\.\d+[:/]\d+)")
    ]

    for regex in regexes:
        
        for match in regex.finditer(command):
            random_str = match.group(1)
            replacement_str = "X" #* len(random_str)
            command = command.replace(random_str, replacement_str)
    
    return command

def extract_ips(string):
    regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    return set(regex.findall(string))

def extract_urls(string):
    regex = re.compile(r"(([\w\d\-]+\.)+([\w\d\-]+))")
    urls = {}
    for match in regex.finditer(string):
        url = match.group(1)
        extract = tldextract.extract(url)
        if extract.suffix and extract.suffix != "sh":
            urls [url] = extract 

    return urls


class Session:
    def __init__(self, session_id, connect_event):
        self.session_id = session_id
        self.src_ip = connect_event["src_ip"]
        self.dst_ip = connect_event["dst_ip"]
        self.src_port = connect_event["src_port"]
        self.dst_port = connect_event["dst_port"]
        self.start_time = connect_event["timestamp"]
        self.protocol = connect_event["protocol"]

        self.end_time = None
        self.duration = 0

        self.hassh = None
        self.ssh_version = None
        self.client_vars = {}

        #self.failed_logins = []
        #self.successful_login = []
        self.username = None
        self.password = None
        self.login_attempts = []
        #self.successful_login = (None, None)

        self.commands = []
        self.malware = []
        self.uploads = []
        self.downloads = []
    
        #self.is_attack = False
        self.contains_commands = False
        self.contains_malware = False
        self.login_success = False

    def add_client_info(self, event):
        if event["eventid"] == "cowrie.client.version":
            self.ssh_version = event["version"]
        elif event["eventid"] == "cowrie.client.kex":
            self.hassh = event["hassh"]
        elif event["eventid"] == "cowrie.client.var":
            self.client_vars[event["name"]] = event["value"]
        

    def add_login_attempt(self, event):
        login = event["username"], event["password"]
        self.login_attempts.append(login)

        if event["eventid"] == "cowrie.login.success":
            self.username, self.password = login
            self.login_success = True
        

    def add_command(self, event):
        #command = standardize_cmdlog(event["input"]) 

        self.commands.append(event["input"])
        self.contains_commands = True

    def add_malware(self, event):
        #TODO FIX URL CAUSED FILE ERRORS
        attack_id = event.get("shasum") or event.get("url")
        self.malware.append(attack_id)
        self.contains_malware = True

        if event["eventid"].startswith("cowrie.session.file_download"):
            self.downloads.append(attack_id)
        elif event["eventid"] == "cowrie.session.file_upload":
            self.uploads.append(attack_id)
    
    def close_session(self, event):
        self.end_time = event["timestamp"]
        self.duration = event["duration"]
        
    @property
    def cmdlog(self):
        cmdlog = "\n".join(self.commands)
        #return standardize_cmdlog(cmdlog)
        return cmdlog 
            
    @property
    def cmdlog_hash(self):
        if self.commands:
            standardized_cmdlog = standardize_cmdlog(self.cmdlog)
            return hashlib.sha256(standardized_cmdlog.encode()).hexdigest()

    @property
    def cmdlog_ips(self):
        return extract_ips(self.cmdlog)
    
    @property
    def cmdlog_urls(self):
        return extract_urls(self.cmdlog)

    def __repr__(self) -> str:
        return f"Session {self.session_id} with {len(self.commands)} commands, {len(self.malware)} malware, {len(self.uploads)} uploads, {len(self.downloads)} downloads, {len(self.login_attempts)} login attempts, {self.login_success} login success, {self.duration} seconds"



        
     


class SourceIP:
    def __init__(self, ip):
        self.ip = ip
        self.sessions = {}#defaultdict(Session)#defaultdict(lambda event: Session(event["session"], event))

        #self.login_attempts = []
        self.failed_logins = 0
        self.successful_logins = 0
        self.uploaded_malware = 0
        self.downloaded_malware = 0
        self.commands = 0

    def add_session(self, event):
        self.sessions[event["session"]] = Session(event["session"], event)
        #self.sessions[event["session"]] = Session(event["session"], event)

    def process_session(self, session_id):
        session = self.sessions[session_id]
        if session.login_success:
            self.successful_logins += 1
            self.failed_logins += len(session.login_attempts) - 1
        else:
            self.failed_logins += len(session.login_attempts)

        self.uploaded_malware += len(session.uploads)
        self.downloaded_malware += len(session.downloads)
        self.commands += len(session.commands)

    @property
    def is_attacker(self):
        return self.successful_logins > 0 and self.commands > 0

    @property
    def successful_login_pairs(self):
        return [(session.username, session.password) for session in self.sessions.values() if session.login_success]

    @property
    def all_login_pairs(self):
        all_login_pairs = []
        for session in self.sessions.values():
            for userpass in session.login_attempts:
                all_login_pairs.append(userpass)  #yield attempt
        return all_login_pairs
               
    @property
    def session_commands(self):
        return [session.commands for session in self.sessions.values() if session.commands]

    @property
    def all_commands(self):
        return [command for session in self.sessions.values() for command in session.commands]

    @property
    def all_cmdlog_hashes(self):
        return [session.cmdlog_hash for session in self.sessions.values()]

    @property
    def all_malware_hashes(self):
        return [malware for session in self.sessions.values() for malware in session.malware]
    
    @property
    def all_src_ports(self):
        return [session.src_port for session in self.sessions.values()]
    
    @property
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions.values()]

    def __repr__(self):
        return f"SourceIP {self.ip} with {len(self.sessions)} sessions, {len(set(self.all_dst_ports))} dst_ports {self.successful_logins} successful logins, {self.commands} commands, {self.uploaded_malware} uploads, {self.downloaded_malware} downloads"


class Attack:
    attacks_path = test_attacks_path
    def __init__(self, attack_id, attack_id_type, source_ip) -> None:
        self.attack_id = attack_id
        self.attack_id_type = attack_id_type
        self.source_ips = [source_ip,]

        self.commands = list(source_ip.all_commands)

        self.cmdlog_hashes = {session.cmdlog_hash: session.commands for session in source_ip.sessions.values() if session.commands}
        self.malware = {shasum: Malware(shasum) for  shasum in source_ip.all_malware_hashes} #set(source_ip.all_malware)


    
    def add_source_ip(self, source_ip):
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)

    def __add__(self, other):
        for source_ip in other.source_ips:
            self.add_source_ip(source_ip)
        self.cmdlog_hashes.update(other.cmdlog_hashes)
        self.malware.update(other.malware)

        return self
    
    @property
    #@staticmethod
    def split_commands(self):
        split_commands = []
        ifor_regex = re.compile(r"if .+?; then.+?fi;?|for .+?; do.+?done;?")


        for command in self.commands:

            while match := ifor_regex.search(command):
                split_cmd = ifor_regex.split(command, 1)
                split_commands.extend(cmd_part for cmd_part in split_cmd[0].split(";") if cmd_part.strip())
                split_commands.append(match.group(0))
                command = split_cmd[1].strip()

            if ";" in command:
                split_commands.extend(cmd_part.strip() for cmd_part in command.split(";") if cmd_part.strip())
            elif command:
                split_commands.append(command)


        return split_commands

    @property
    def sessions(self):
        sessions = [session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions
    
    @property
    def login_sessions(self):
        return [session for session in self.sessions if session.login_success]
    

    @property
    def first_session(self):
        return self.sessions[0]
    
    @property
    def last_session(self):
        return self.sessions[-1]
    
    @property
    def start_time(self):
        return min([session.start_time for session in self.sessions])
    
    @property
    def end_time(self):
        return max([session.end_time for session in self.sessions if session.end_time])

    @property
    def successful_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.successful_login_pairs]
    
    @property
    def all_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_login_pairs]

    @property
    def all_usernames(self):
        return [login_pair[0] for login_pair in self.all_login_pairs]
    
    @property
    def all_passwords(self):
        return [login_pair[1] for login_pair in self.all_login_pairs]
    
    @property
    def successful_usernames(self):
        return [login_pair[0] for login_pair in self.successful_login_pairs]
    
    @property
    def successful_passwords(self):
        return [login_pair[1] for login_pair in self.successful_login_pairs]

    @property
    def all_src_ips(self):
        return [session.src_ip for session in self.sessions]
    
    @property
    def all_dst_ips(self):
        return [session.src_ip for session in self.sessions]

    @property
    def all_src_ports(self):
        return [session.src_port for session in self.sessions]
    
    @property
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions]
    
    @property
    def all_cmdlog_urls(self):
        return [url for session in self.sessions for url in session.cmdlog_urls]

    @property
    def all_cmdlog_ips(self):
        return [ip for session in self.sessions for ip in session.cmdlog_ips]
    
    @property
    def all_malware_urls(self):
        return [url for malware in self.malware.values() for url in malware.urls]

    @property
    def all_malware_ips(self):
        return [ip for malware in self.malware.values() for ip in malware.ips]
    
    @property
    def all_ips(self):
        return self.all_src_ips + self.all_cmdlog_ips + self.all_malware_ips
    
    @property
    def all_ips_and_urls (self):
        return self.all_ips + self.all_cmdlog_urls + self.all_malware_urls

    @property
    def counts(self):
        counts = defaultdict(Counter)
        props = ["successful_login_pairs", "successful_usernames", "successful_passwords",
                 "all_login_pairs", "all_usernames", "all_passwords",
                 "all_src_ips", "all_dst_ips",
                 "all_src_ports", "all_dst_ports",
                 "all_cmdlog_urls", "all_cmdlog_ips",
                 "all_malware_urls", "all_malware_ips"
                 ]
        
        for prop in props:
            counts[prop].update(getattr(self, prop))

        return counts


    def __repr__(self):
        return f"Attack ({self.attack_id_type}: {self.attack_id[:10]}) with {len(self.source_ips)} source IPs and {len(self.sessions)} sessions, {len(self.successful_login_pairs)} successful logins, {len(self.commands)} commands, {len(self.cmdlog_hashes)} cmdlog hashes, {len(self.malware)} malware hashes"    




class Malware:
    malware_path = test_logs_path / "malware" / "downloads"
    def __init__(self, shasum) -> None:
        self.shasum = shasum
        self.filepath = self.malware_path / shasum

    @property
    def text(self):
        if self.filepath.exists():
            return self.filepath.open().read()
        else:
            return ""

    @property
    def lines(self):
        return self.text.split("\n")

    @property
    def urls(self):
        return extract_urls(self.text)
    

    @property
    def ips(self):
        return extract_ips(self.text)
    

    def __repr__(self) -> str:
        return f"Malware {self.shasum[:10]} with {len(self.lines)} lines, {len(self.urls)} urls, {len(self.ips)} ips"



class CowrieLogAnalyzer(Cowrie):

    def __init__(self, overwrite=True, log_path=test_logs_path, attacks_path=test_attacks_path, remove_ips=MYIPS):
        super().__init__()
        
        
        self.source_ips = {}
        self.attacks = {}
        self.remove_ips = remove_ips
        #self.reader = Cowrie()
        self.exceptions = []
        self.auth_random = json.loads((self.log_path / "malware" / "auth_random.json").read_bytes())
        self.overwrite = overwrite

    def process(self):
        for event in self.logs:#self.reader.logs:
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

                    else:
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
            print("Commands:\n\t" + "\n\t".join(self.attacks[attack_id].commands)+ "\n")

        self.attacks = sorted_attacks

        print("Done")


    def manual_merge(self):
        attack_sigs ={
            re.compile(r">A@/ X'8ELFXLL"): None,
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


    # def organize_logs_by_attack(self, attacks_path=test_attacks_path):
        
    #     for attack_id, attack in self.attacks.items():
    #         attack_dir = attacks_path / attack_id
    #         attack_dir.mkdir(exist_ok=True, parents=True)
            
    #         all_src_ips = set(attack.all_src_ips)
    #         all_src_ips_regex = re.compile(rb"|".join(ip.encode().replace(b".", rb"\.") for ip in all_src_ips))
    #         src_ip_regexes = {ip: re.compile(ip.encode().replace(b".", rb"\.")) for ip in all_src_ips}

    #         for src_ip in all_src_ips:
    #             source_ip_dir = attack_dir / src_ip
    #             source_ip_dir.mkdir(exist_ok=True, parents=True)

    #         for file in self.all_logs:
    #             if file.name == "auth_random.json":
    #                 combined_auth_random = {}
    #                 for src_ip in all_src_ips:
    #                     src_ip_auth_random = self.auth_random[src_ip]
    #                     combined_auth_random.update(src_ip_auth_random)

    #                     out_file = attack_dir / src_ip / file.name
    #                     json.dump(src_ip_auth_random, out_file.open('w+'), indent=4)
                    
    #                 out_file = attack_dir / file.name    
    #                 json.dump(combined_auth_random, out_file.open('w+'), indent=4)    
    #                 continue

    #             elif all_src_ips_regex.search(file.read_bytes()):
    #                 out_file = attack_dir / file.name
    #                 self.write_matching_lines(file, out_file, all_src_ips_regex)

    #                 for src_ip, regex in src_ip_regexes.items():
                        
    #                     if regex.search(file.read_bytes()):
    #                         out_file = attack_dir / src_ip / file.name
    #                         self.write_matching_lines(file, out_file, regex)
                
                
                

                    
    
                


            

if __name__ == "__main__":    
    la = CowrieLogAnalyzer(overwrite=True)
    la.process()
    la.analyze()
    #la.organize_logs_by_attack() # 1076.96s user 78.03s system 99% cpu 19:20.38 total
    la.organize_logs_by_attack_multi() 
    #la.print_shared_ips()
    #la.print_shared_cmdlog_hashes()
    #la.print_shared_malware_hashes()

print()


