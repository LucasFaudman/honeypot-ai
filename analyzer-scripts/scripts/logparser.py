import os
import pathlib
import json
import re
import hashlib 
from collections import defaultdict

test_logs_path, test_attacks_path = "/Users/lucasfaudman/Documents/SANS/internship/tests/logs", "/Users/lucasfaudman/Documents/SANS/internship/tests/attacks"

class LogParser:
    def __init__(self, logs_path, attacks_path, log_exts=(".log", ".json", ".zeek")):
        self.logs_path = pathlib.Path(logs_path)
        self.attacks_path = pathlib.Path(attacks_path)
        self._all_logs = []

        self.attckers = defaultdict(set)

        self.auth_random = json.loads((self.logs_path / "malware" / "auth_random.json").read_bytes())
        

    def get_log_paths(self, sub_path="", pattern="*"):
        sub_path  = self.logs_path / sub_path
        for file in sub_path.rglob(pattern):
            if file.is_file():
                yield file
        
    @property
    def all_logs(self):
        if not self._all_logs:
            self._all_logs = list(self.get_log_paths())
        yield from self._all_logs
        

    def get_matching_lines(self, file, pattern, flags=0):

        cmpld_pattern = re.compile(pattern, flags)
        # read_mode = "r" if isinstance(pattern, str) else "rb"
        read_mode = "rb"

        with open(file, read_mode) as f:
            for line in f:
                if cmpld_pattern.search(line):
                    yield line


    def write_matching_lines(self, from_file, to_file, pattern, flags=0):
        #write_mode = "w+" if isinstance(pattern, str) else "wb+"
        write_mode = "wb+"
        with open(to_file, write_mode) as f:
            for line in self.get_matching_lines(from_file, pattern, flags):
                f.write(line)


    def load_matching_json(self, file, pattern, flags=0):
        return list(self.get_matching_lines(file, pattern, flags))


    def load_matching_json_lines(self, file, pattern, flags=0, remove_keys=()):
        for line in self.get_matching_lines(file, pattern, flags):
            event = json.loads(line)
            self.popkeys(event, remove_keys)
            yield event 

    def load_json_logs(self, file):
        with open(file, "r") as f:
            for line in f:
                yield json.loads(line)


    # def load_log_as_list(self, file):
    #     return list(self.load_json_logs(file))

    def popkeys(self, dict, keys):
        for key in keys:
            dict.pop(key, None)
    
    def get_cowrie_events(self, pattern, remove_keys=()):
        for file in self.get_log_paths("cowrie", "*.json"):
            yield from self.load_matching_json_lines(file, pattern)

    def get_malware_download_events(self):
        remove_keys = ("message", "eventid", "sensor", "outfile")
        for file in self.get_log_paths("cowrie", "*.json"):
            yield from self.load_matching_json_lines(file, b"cowrie.session.file_", remove_keys=remove_keys)

    def get_tty_events(self):
        remove_keys = ()#("message", "eventid", "sensor", "outfile")
        yield from self.get_cowrie_events(b"ttylog", remove_keys=remove_keys)



    @property
    def malware_hashes(self):
        return [event for event in self.get_malware_download_events()]
    
    @property
    def ttylog_hashes(self):
        return [event for event in self.get_tty_events()]


    def organize_logs_by_discovery_key(self, discovery_key):
        events = self.__getattribute__(discovery_key)

        for event in events:
            attack_uuid = event.get("shasum") or event.get('url').replace('/', '_')
            attack_dir = self.attacks_path / discovery_key / attack_uuid 

            attack_dir.mkdir(parents=True, exist_ok=True)            
            event["attack_dir"] = attack_dir 

            event["cmpld_pattern"] = re.compile(attack_uuid.replace('_', '/').encode())
            event["attack_uuid"] = attack_uuid.encode()
            event["src_ip"] = event["src_ip"].encode()
            event["session"] = event["session"].encode()

        for file in self.all_logs:
            file_bytes = file.read_bytes()
            for event in events:
                if event["cmpld_pattern"].search(file_bytes):

                    #Add attacker to list of attackers
                    self.attckers[event["src_ip"]].update((event["attack_uuid"],))
                    
                    if event["src_ip"] in file_bytes:
                        logs_by_src_file = event["attack_dir"] / f"{event['src_ip'].decode()}-{file.name}"
                        self.write_matching_lines(file, logs_by_src_file, event["src_ip"])


                    if file.suffix == '.json' and event["session"] in file_bytes:
                        logs_by_session_file = event["attack_dir"] / f"{event['session'].decode()}-{file.name}"
                        self.write_matching_lines(file, logs_by_session_file, event["session"])

                    #TODO ADD Zeek Parsers Here

    def organize_logs_by_tty(self):
        self.organize_logs_by_discovery_key("ttylog_hashes")


    def organize_logs_by_hash(self):
        self.organize_logs_by_discovery_key("malware_hashes")


    def orgainze_logs_by_src_ips(self, src_ips):
        for file in self.all_logs:
            for src_ip in src_ips:
                src_ip_str = src_ip.decode() 
                attacker_dir = self.attacks_path / "src_ips" / src_ip_str
                attacker_dir.mkdir(parents=True, exist_ok=True)

                logs_by_src_file = attacker_dir / file.name

                if file.name == "auth_random.json":
                    logs_by_src_file.write_bytes(json.dumps(self.auth_random[src_ip_str]).encode())

        
                elif src_ip in file.read_bytes():
                    # logs_by_src_file = attacker_dir / file.name
                    #logs_by_src_file.touch()
                    self.write_matching_lines(file, logs_by_src_file, src_ip)
        
    def rw_cowrie_messages(self):
        for file in self.attacks_path.rglob("*cowrie*.json"):
            message_file = str(file) + ".messages"
            
            with open(message_file, "w+") as f:
                for event in self.load_json_logs(file):
                    if event.get("message"):
                        f.write(f'{event["message"]}\n')
                    

if __name__ == "__main__":
    lp = LogParser(test_logs_path, test_attacks_path)
    #print(list(lp.get_malware_download_events()))
    # print(lp.malware_hashes)

    # print(lp.organize_logs_by_hash())



    #print(list((e['session'], e['src_ip']) for e in lp.get_tty_events()))
    print(lp.organize_logs_by_hash())
    print(lp.organize_logs_by_tty())
    print(lp.attckers)
    print(lp.orgainze_logs_by_src_ips(lp.attckers))    
    print(lp.rw_cowrie_messages())









