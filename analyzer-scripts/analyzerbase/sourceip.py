from .baseobjects import *
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
        self.http_requests = 0
        self.zeek_events = 0


    def add_session(self, event):
        self.sessions[event["session"]] = Session(event)
        

    def process_sessions(self):
        for session in self.sessions.values():
            session.process_events()

            if session.login_success:
                self.successful_logins += 1
                self.failed_logins += len(session.login_attempts) - 1
            else:
                self.failed_logins += len(session.login_attempts)

            self.uploaded_malware += len(session.uploads)
            self.downloaded_malware += len(session.downloads)
            self.commands += len(session.commands)

            #session.process_zeek_events()
            if session.http_request_events:
                session.process_http_requests()
                self.http_requests += len(session.http_requests)
            
            if session.session_type == "zeek":
                self.zeek_events += len(session.events)

        self.sort_sessions()
        
    def sort_sessions(self):
        self.sessions = dict(sorted(self.sessions.items(), key=lambda session: session[1].start_time))
        return self.sessions

    @property
    def is_attacker(self):
        return self.commands > 0 or self.http_requests > 1
        #return self.successful_logins > 0 and self.commands > 0

    @property
    def all_src_ports(self):
        return [session.src_port for session in self.sessions.values()]
    
    @property
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions.values()]


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
               
    # @property
    # def session_commands(self):
    #     return [session.commands for session in self.sessions.values() if session.commands]

    @property
    def all_commands(self):
        return [command for session in self.sessions.values() for command in session.commands]

    @property
    def all_cmdlog_hashes(self):
        return [session.cmdlog_hash for session in self.sessions.values() if session.commands]

    @property
    def all_malware_hashes(self):
        return [malware.shasum for session in self.sessions.values() for malware in session.malware if malware.shasum]
    
    @property
    def all_malware(self):
        return [malware for session in self.sessions.values() for malware in session.malware]

    @property
    def all_http_requests(self):
        return [http_request for session in self.sessions.values() for http_request in session.http_requests]

    @property
    def all_http_request_events(self):
        return [http_request_event for session in self.sessions.values() for http_request_event in session.http_request_events]

    @property
    def all_httplogs(self):
        return [session.httplog for session in self.sessions.values() if session.httplog]

    @property
    def all_httplog_hashes(self):
        return [session.httplog_hash for session in self.sessions.values() if session.httplog_hash]
    
    @property
    def all_http_uris(self):
        return [uri for session in self.sessions.values() for uri in session.http_uris]

    @property
    def all_zeek_events(self):
        return [zeek_event for session in self.sessions.values() 
                for zeek_event in session.events if session.session_type == "zeek"]

    @property
    def all_events(self):
        return [event for session in self.sessions.values() for event in session.events]


    def __repr__(self):
        return ''.join([
            f"SourceIP {self.ip} "
            f"Sessions: {len(self.sessions)}, " if self.sessions else "",
            #f"dst_ports: {len(set(self.all_dst_ports))}, ",
            f"Successful Logins: {self.successful_logins}, " if self.successful_logins else "",
            f"Commands: {self.commands}, " if self.commands else "",
            f"Uploads: {self.uploaded_malware}, " if self.uploaded_malware else "",
            f"Downloads {self.downloaded_malware}, " if self.downloaded_malware else "",
            f"HTTP Requests: {self.http_requests}, " if self.http_requests else "",
            f"Zeek Events: {self.zeek_events}, " if self.zeek_events else "",
         ])
        

       