from .baseobjects import *
from .common import *

from .util import extract_ips, extract_urls, standardize_cmdlog, sha256hex, extract_hosts_from_parsed_urls
from .malware import Malware

class Session(SmartAttrObject, CachedPropertyObject):
    def __init__(self, event):
        SmartAttrObject.__init__(self)
        CachedPropertyObject.__init__(self)
        
        self.session_id = event["session"]
        self.session_type = event["eventid"].split(".")[0]

        self.src_ip = event.get("src_ip", "")
        self.dst_ip = event.get("dst_ip", "")
        self.src_port = event.get("src_port", 0)
        self.dst_port = event.get("dst_port", 0)
        self.protocol = event.get("protocol", "").upper()

        self.start_time = event["timestamp"]
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
        

        self.events = [event]
        self.http_request_events = []
        self._http_requests = []


    @staticmethod
    def event_handler(func):
        def wrapper(self, event):
            # TODO add event validation and merging w/ events from other log sources of same session
            self.events.append(event)
            return func(self, event)
        return wrapper


    @event_handler
    def add_client_info(self, event):
        if event["eventid"] == "cowrie.client.version":
            self.ssh_version = event["version"]
        elif event["eventid"] == "cowrie.client.kex":
            self.ssh_hassh = event["hassh"]
        elif event["eventid"] == "cowrie.client.var":
            self.client_vars[event["name"]] = event["value"]
        
    @event_handler
    def add_login_attempt(self, event):
        login = event["username"], event["password"]
        self.login_attempts.append(login)

        if event["eventid"] == "cowrie.login.success":
            self.username, self.password = login
            self.login_success = True
        
    @event_handler
    def add_command(self, event):
        self.commands.append(event["input"])
        self.contains_commands = True

    @event_handler
    def add_malware(self, event):
        malware = Malware(event)
        self.malware.append(malware)

        if event["eventid"].startswith("cowrie.session.file_download"):
            self.downloads.append(malware)
        elif event["eventid"] == "cowrie.session.file_upload":
            self.uploads.append(malware)

    @event_handler
    def add_ttylog(self, event):
        self.ttylog = event["ttylog"]
        self.ttylog_shasum = event["shasum"]
    

    @event_handler
    def close_session(self, event):
        self.end_time = event["timestamp"]
        self.duration = event["duration"]


    @event_handler
    def add_zeek_event(self, event):
        if event["eventid"] == "zeek.http.log.event":
            self.add_http_request(event)

    
    def process_events(self):
        if self.events:
            self.events.sort(key=lambda event: event["timestamp"])
            
            self.start_time = self.events[0]["timestamp"]
            self.end_time = self.events[-1]["timestamp"]
            self.duration = (self.end_time - self.start_time).microseconds / 1000000
            
            
            self.src_ip = self.events[0].get("src_ip", self.src_ip)
            self.dst_ip = self.events[0].get("dst_ip", self.dst_ip)
            self.src_port = self.events[0].get("src_port", self.src_port)
            self.dst_port = self.events[0].get("dst_port", self.dst_port)
            self.protocol = self.events[0].get("protocol", self.protocol).upper()


    
    def add_http_request(self, event):
        request_keys = ("timestamp", "method", "uri", "version", "user_agent", "host", "referrer", "cookies")
        http_request = {key: event[key] for key in request_keys if key in event}
        self._http_requests.append(http_request)
        self.http_request_events.append(event)


    def process_http_requests(self):
        if self._http_requests:
            self._http_requests.sort(key=lambda event: event["timestamp"])


    
    @cachedproperty
    def cmdlog(self):
        cmdlog = "\n".join(self.commands)
        return cmdlog
    
            
    @cachedproperty
    def cmdlog_hash(self):
        if self.commands:
            # See .util.standardize_cmdlog for why this is necessary before hashing
            standardized_cmdlog = standardize_cmdlog(self.cmdlog)
            return sha256hex(standardized_cmdlog)
        


    @cachedproperty
    def cmdlog_ips(self):
        return extract_ips(self.cmdlog)


    @cachedproperty
    def cmdlog_urls(self):
        return extract_urls(self.cmdlog)
    

    @cachedproperty
    def cmdlog_hosts(self):
        return extract_hosts_from_parsed_urls(self.cmdlog_urls.values()) + self.cmdlog_ips
    
    
    @cachedproperty
    def http_request_strs(self):
        http_request_strs = []
        skip_keys = ("timestamp", "method", "uri", "version")
        prev_version = "" 
        for event in self._http_requests:

                        
            event['version'] = event.get('version', prev_version)
            event['method'] = event.get('method', "")
            event['uri'] = event.get('uri', "")

            http_request = f"{event['method']} {event['uri']} HTTP/{event['version']}\n" 
            http_request += "\n".join([f"{key.title().replace('_','-')}: {event[key]}" for key in event if not key in skip_keys])
            http_request_strs.append(http_request)
    
        return http_request_strs

    @cachedproperty
    def httplog(self):
        return "\n\n".join(self.http_request_strs)


    @cachedproperty
    def httplog_hash(self):
        if self._http_requests:
            return sha256hex(self.httplog)


    @cachedproperty
    def httplog_ips(self):
        return extract_ips(self.httplog)
    
    @cachedproperty
    def httplog_urls(self):
        return extract_urls(self.httplog)
    
    @cachedproperty
    def httplog_hosts(self):
        return extract_hosts_from_parsed_urls(self.httplog_urls.values()) + self.httplog_ips
    

    @cachedproperty
    def http_uris(self):
        return [event["uri"] for event in self._http_requests if event.get("uri")]

    @cachedproperty
    def http_urilog(self):
        return "\n".join(self.http_uris)
    
    @cachedproperty
    def http_urilog_hash(self):
        if self.http_uris:
            return sha256hex(self.http_urilog)


    @cachedproperty
    def http_requests(self):
        """Verbose property name and OrderedSet wrapper for _http_requests to expose to AI model tools"""
        return SetReprOrderedSet(self.http_request_strs)


    @cachedproperty
    def hosts(self):
        return self.cmdlog_hosts + self.httplog_hosts


    def __str__(self) -> str:
        return ''.join([
            f"Session {self.session_id} "
            f"{self.protocol.upper()} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ",
            f"Login: {self.username}:{self.password} " if self.login_success else "",
            f"Commands: {len(self.commands)}, " if self.commands else "",
            f"Malware: {len(self.malware)}, " if self.malware else "",
            f"HTTP Requests: {len(self._http_requests)}, " if self._http_requests else "",
            f"Duration: {self.duration:.2f}s"
        ])

    
    def __repr__(self) -> str:
        return self.__str__()