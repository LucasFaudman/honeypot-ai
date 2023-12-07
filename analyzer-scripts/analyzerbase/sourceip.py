from .common import *
from .session import Session

class SourceIP:
    def __init__(self, ip):
        self.ip = ip
        self.sessions = {}

        self.failed_logins = 0
        self.successful_logins = 0
        self.uploaded_malware = 0
        self.downloaded_malware = 0
        self.commands = 0

    def add_session(self, event):
        self.sessions[event["session"]] = Session(event)
        

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
    def all_successful_login_pairs(self):
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
        return [malware.shasum for session in self.sessions.values() for malware in session.malware]
    
    @property
    def all_malware(self):
        return [malware for session in self.sessions.values() for malware in session.malware]

    @property
    def all_src_ports(self):
        return [session.src_port for session in self.sessions.values()]
    
    @property
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions.values()]

    def __repr__(self):
        return f"SourceIP {self.ip} with {len(self.sessions)} sessions, {len(set(self.all_dst_ports))} dst_ports {self.successful_logins} successful logins, {self.commands} commands, {self.uploaded_malware} uploads, {self.downloaded_malware} downloads"
