from .common import *
from .util import extract_ips, extract_urls, standardize_cmdlog, sha256hex
from .malware import Malware

class Session:
    def __init__(self, connect_event):
        self.session_id = connect_event["session"]
        self.src_ip = connect_event["src_ip"]
        self.dst_ip = connect_event["dst_ip"]
        self.src_port = connect_event["src_port"]
        self.dst_port = connect_event["dst_port"]
        self.start_time = connect_event["timestamp"]
        self.protocol = connect_event["protocol"]

        self.end_time = None
        self.duration = 0

        self.ssh_hassh = None
        self.ssh_version = None
        self.client_vars = {}

        self.username = None
        self.password = None
        self.login_attempts = []

        self.commands = []
        self.malware = []
        self.uploads = []
        self.downloads = []
    
        self.contains_commands = False
        self.contains_malware = False
        self.login_success = False
        
        self.ttylog = None
        

    def add_client_info(self, event):
        if event["eventid"] == "cowrie.client.version":
            self.ssh_version = event["version"]
        elif event["eventid"] == "cowrie.client.kex":
            self.ssh_hassh = event["hassh"]
        elif event["eventid"] == "cowrie.client.var":
            self.client_vars[event["name"]] = event["value"]
        

    def add_login_attempt(self, event):
        login = event["username"], event["password"]
        self.login_attempts.append(login)

        if event["eventid"] == "cowrie.login.success":
            self.username, self.password = login
            self.login_success = True
        

    def add_command(self, event):
        self.commands.append(event["input"])
        self.contains_commands = True


    def add_malware(self, event):
        malware = Malware(event)
        self.malware.append(malware)

        if event["eventid"].startswith("cowrie.session.file_download"):
            self.downloads.append(malware)
        elif event["eventid"] == "cowrie.session.file_upload":
            self.uploads.append(malware)


    def add_ttylog(self, event):
        self.ttylog = event["ttylog"]
        self.ttylog_shasum = event["shasum"]
    

    def close_session(self, event):
        self.end_time = event["timestamp"]
        self.duration = event["duration"]
        

    @property
    def cmdlog(self):
        cmdlog = "\n".join(self.commands)
        
        return cmdlog
    
            
    @property
    def cmdlog_hash(self):
        if self.commands:
            # See .util.standardize_cmdlog for why this is necessary before hashing
            standardized_cmdlog = standardize_cmdlog(self.cmdlog)
            return sha256hex(standardized_cmdlog)
        


    @property
    def cmdlog_ips(self):
        return extract_ips(self.cmdlog)


    @property
    def cmdlog_urls(self):
        return extract_urls(self.cmdlog)
    

    def __repr__(self) -> str:
        return ''.join([
            f"Session {self.session_id} "
            f"{self.protocol.upper()} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ",
            f"Login: {self.username}:{self.password} " if self.login_success else "",
            f"Commands: {len(self.commands)}, " if self.commands else "",
            f"Malware: {len(self.malware)}, " if self.malware else "",
            f"Duration: {self.duration:.2f}s"
        ])


        