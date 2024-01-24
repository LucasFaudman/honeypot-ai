from .baseobjects import *
from .common import *
from .session import Session

class SourceIP(SmartAttrObject, CachedPropertyObject):
    def __init__(self, ip):
        SmartAttrObject.__init__(self)
        CachedPropertyObject.__init__(self)
        
        self.ip = ip
        self.sessions = {}

        self.failed_logins = 0
        self.successful_logins = 0
        self.uploaded_malware = 0
        self.downloaded_malware = 0
        self.total_malware = 0
        self.commands = 0
        self.http_requests = 0
        self.zeek_events = 0
        self.first_seen = None


    def add_session(self, event):
        """Initializes new Session from event and adds it to self.sessions"""
        self.sessions[event["session"]] = Session(event)
        

    def sort_sessions(self):
        """Sorts sessions by start_time"""
        self.sessions = dict(sorted(self.sessions.items(), key=lambda session: session[1].start_time))
        return self.sessions


    def process_sessions(self, discard_events=True):
        """
        Processes all sessions in self.session. First sorts sessions by start_time, 
        then processes events for each session and updates self attributes with new values
        """

        self.sort_sessions()

        for session in self.sessions.values():
            if not self.first_seen:
                self.first_seen = session.start_time
            else:
                self.first_seen = min(self.first_seen, session.start_time)

            if session.login_success:
                self.successful_logins += 1
                self.failed_logins += len(session.login_attempts) - 1
            else:
                self.failed_logins += len(session.login_attempts)

            self.uploaded_malware += len(session.uploads)
            self.downloaded_malware += len(session.downloads)
            self.commands += len(session.commands)

            session.process_events()
            if session.http_request_events:
                session.process_http_requests()
                self.http_requests += len(session.http_requests)
            
            if session.session_type == "zeek":
                self.zeek_events += len(session.events)
            
            if discard_events:
                session.events = []

        self.total_malware = self.uploaded_malware + self.downloaded_malware
        
           

    @property
    def is_attacker(self):
        """Returns True if SourceIP has any sessions with commands, http_requests, or zeek_events"""
        return self.commands > 0 or self.http_requests > 0 or self.zeek_events > 0
        

    # Begin CachedPropertyObject properties @cachedproperty methods 
    @cachedproperty
    def all_src_ports(self):
        """Returns list of all src_ports from all sessions"""
        return [session.src_port for session in self.sessions.values()]
    

    @cachedproperty
    def all_dst_ports(self):
        """Returns list of all dst_ports from all sessions"""
        return [session.dst_port for session in self.sessions.values()]


    @cachedproperty
    def all_successful_login_pairs(self):
        """Returns list of all successful login pairs from all sessions as (username, password) tuples"""
        return [(session.username, session.password) for session in self.sessions.values() if session.login_success]


    @cachedproperty
    def all_login_pairs(self):
        """Returns list of all login pairs from all sessions as (username, password) tuples"""
        all_login_pairs = []
        for session in self.sessions.values():
            for userpass in session.login_attempts:
                all_login_pairs.append(userpass)  #yield attempt
        return all_login_pairs
               
    
    @cachedproperty
    def all_commands(self):
        """Returns list of all commands from all sessions"""
        return [command for session in self.sessions.values() for command in session.commands]


    @cachedproperty
    def all_cmdlog_hashes(self):
        """Returns list of all cmdlog hashes from all sessions"""
        return [session.cmdlog_hash for session in self.sessions.values() if session.commands]


    @cachedproperty
    def all_malware_hashes(self):
        """Returns list of all malware hashes from all sessions"""
        return [malware.shasum for session in self.sessions.values() for malware in session.malware if malware.shasum]


    @cachedproperty
    def all_malware(self):
        """Returns list of all Malware objects from all sessions"""
        return [malware for session in self.sessions.values() for malware in session.malware]


    @cachedproperty
    def all_http_requests(self):
        """Returns list of all http_requests from all sessions"""
        return [http_request for session in self.sessions.values() for http_request in session.http_requests]


    @cachedproperty
    def all_http_request_events(self):
        """Returns list of all http_request_events from all sessions"""
        return [http_request_event for session in self.sessions.values() for http_request_event in session.http_request_events]


    @cachedproperty
    def all_httplogs(self):
        """Returns list of all httplogs from all sessions"""
        return [session.httplog for session in self.sessions.values() if session.httplog]


    @cachedproperty
    def all_httplog_hashes(self):
        """Returns list of all httplog hashes from all sessions"""
        return [session.httplog_hash for session in self.sessions.values() if session.httplog_hash]


    @cachedproperty
    def all_http_uris(self):
        """Returns list of all http_uris from all sessions"""
        return [uri for session in self.sessions.values() for uri in session.http_uris]


    @cachedproperty
    def all_zeek_events(self):
        """Returns list of all zeek_events from all sessions"""
        return [zeek_event for session in self.sessions.values() 
                for zeek_event in session.events if session.session_type == "zeek"]


    @cachedproperty
    def all_events(self):
        """Returns list of all events from all sessions"""
        return [event for session in self.sessions.values() for event in session.events]


    def __str__(self):
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
        

    def __repr__(self) -> str:
        return self.__str__()