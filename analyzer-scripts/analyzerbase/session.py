from .common import *
from .util import extract_ips, extract_urls, standardize_cmdlog

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



        