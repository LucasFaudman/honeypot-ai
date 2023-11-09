import re
import hashlib 
from collections import defaultdict, OrderedDict
import os
import pathlib
import json
from datetime import datetime
from pprint import pprint

from logreader import Cowrie



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
        #command = standardize_ttylog(event["input"]) 

        self.commands.append(event["input"])
        self.contains_commands = True

    def add_malware(self, event):
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
    def ttylog(self):
        ttylog = "\n".join(self.commands)
        return ttylog 
            
    @property
    def ttylog_hash(self):
        if self.commands:
            standardized_ttylog = standardize_ttylog(self.ttylog)
            return hashlib.sha256(standardized_ttylog.encode()).hexdigest()


    def __repr__(self) -> str:
        return f"Session {self.session_id} with {len(self.commands)} commands, {len(self.malware)} malware, {len(self.uploads)} uploads, {len(self.downloads)} downloads, {len(self.login_attempts)} login attempts, {self.login_success} login success, {self.duration} seconds"


def standardize_ttylog(command):
    regexes = [
        re.compile(r"/bin/busybox (\w+)"),
        #re.compile(r"/tmp/([\w\d]+)"),

    ]

    for regex in regexes:
        match = regex.search(command)
        if match:
            random_str = match.group(1)
            replacement_str = "X" * len(random_str)
            return command.replace(random_str, replacement_str)
    
    return command
        
     


class SourceIP:
    def __init__(self, ip):
        self.ip = ip
        self.sessions = {}

        #self.login_attempts = []
        self.failed_logins = 0
        self.successful_logins = 0
        self.uploaded_malware = 0
        self.downloaded_malware = 0
        self.commands = 0

    def add_session(self, event):
        self.sessions[event["session"]] = Session(event["session"], event)

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
    def all_commands(self):
        return [command for session in self.sessions.values() for command in session.commands]

    @property
    def all_ttylog_hashes(self):
        return [session.ttylog_hash for session in self.sessions.values()]

    @property
    def all_malware_hashes(self):
        return [malware for session in self.sessions.values() for malware in session.malware]
    
    def __repr__(self):
        return f"SourceIP {self.ip} with {len(self.sessions)} sessions, {self.successful_logins} successful logins, {self.commands} commands, {self.uploaded_malware} uploads, {self.downloaded_malware} downloads"

class Attack:
    def __init__(self, attack_id, attack_id_type, source_ip) -> None:
        self.attack_id = attack_id
        self.attack_id_type = attack_id_type
        self.source_ips = [source_ip,]

        self.commands = list(source_ip.all_commands)
        self.ttylog_hashes = set(source_ip.all_ttylog_hashes)
        self.malware_hashes = set(source_ip.all_malware_hashes)
        #self.logins = list(source_ip.successful_login_pairs)

    
    def add_source_ip(self, source_ip):
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)



    @property
    def sessions(self):
        return [session for source_ip in self.source_ips for session in source_ip.sessions.values()]
    
    @property
    def successful_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.successful_login_pairs]
    
    @property
    def all_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_login_pairs]
    
    @property
    def start_time(self):
        return min([session.start_time for session in self.sessions])
    
    @property
    def end_time(self):
        return max([session.end_time for session in self.sessions])
    
    
    
    def __repr__(self):
        return f"Attack ({self.attack_id_type}: {self.attack_id[:10]}) with {len(self.source_ips)} source IPs"    

        #return f"Attack {self.attack_id} with {len(self.source_ips)} source IPs"
    


class CowrieLogAnalyzer:

    def __init__(self):
        self.source_ips = {}
        self.attacks = {}
        self.reader = Cowrie()
        
    def process(self):
        for event in self.reader.logs:
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
                        attack_ids = source_ip.all_ttylog_hashes
                        attack_id_type = "ttylog_hash"
                        

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


        print(f"Number of IPs with successful logins: {len(ips_with_successful_logins)}")
        print(f"Number of IPs with commands: {len(ips_with_commands)}")
        print(f"Number of IPs with commands only: {len(ips_with_commands_only)}")
        print(f"Number of IPs with malware: {len(ips_with_malware)}")
        print(f"Number of attacks: {len(self.attacks)}")


        attacks_sorted_by_source_ips = sorted(self.attacks.keys(), key=lambda uuid: len(self.attacks[uuid].source_ips), reverse=True)
        for attack_id in attacks_sorted_by_source_ips:
            print(self.attacks[attack_id])
        
        print("Done")
        #for attack in self.attacks.values():
        #    print(attack)

        

        
la = CowrieLogAnalyzer()
la.process()
la.analyze()


print()

#for event in enumerate(Dshield().events):
#    print(event)
#    continue
