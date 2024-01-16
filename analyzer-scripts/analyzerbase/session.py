from .common import *
from .util import extract_ips, extract_urls, standardize_cmdlog, sha256hex, extract_hosts_from_parsed_urls
from .malware import Malware

class Session:
    def __init__(self, connect_event):
        self.session_id = connect_event["session"]
        self.src_ip = connect_event["src_ip"]
        self.dst_ip = connect_event["dst_ip"]
        self.src_port = connect_event["src_port"]
        self.dst_port = connect_event["dst_port"]
        self.start_time = connect_event["timestamp"]
        self.protocol = connect_event["protocol"].upper()

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
        

        self.zeek_events = []
        self.http_request_events = []
        self._http_requests = []
        


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




    def add_zeek_event(self, event):
        self.zeek_events.append(event)

        if event["eventid"] == "zeek.http.log.event":
            self.add_http_request(event)

    

    def process_zeek_events(self):
        if self.zeek_events:
            self.zeek_events.sort(key=lambda event: event["timestamp"])
            self.start_time = self.zeek_events[0]["timestamp"]
            self.end_time = self.zeek_events[-1]["timestamp"]
            self.duration = (self.end_time - self.start_time).microseconds / 1000000
    

    def add_http_request(self, event):

        request_keys = ("timestamp", "method", "uri", "version", "user_agent", "host", "referrer", "cookies")
        http_request = {key: event[key] for key in request_keys if key in event}
        self._http_requests.append(http_request)
        self.http_request_events.append(event)

    
    def process_http_requests(self):
        if self._http_requests:
            self._http_requests.sort(key=lambda event: event["timestamp"])


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
    

    @property
    def cmdlog_hosts(self):
        return extract_hosts_from_parsed_urls(self.cmdlog_urls.values()) + self.cmdlog_ips
    
    
    @property
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

    @property
    def httplog(self):
        return "\n\n".join(self.http_request_strs)


    @property
    def httplog_hash(self):
        if self._http_requests:
            return sha256hex(self.httplog)


    @property
    def httplog_ips(self):
        return extract_ips(self.httplog)
    
    @property
    def httplog_urls(self):
        return extract_urls(self.httplog)
    
    @property
    def httplog_hosts(self):
        return extract_hosts_from_parsed_urls(self.httplog_urls.values()) + self.httplog_ips
    

    @property
    def http_uris(self):
        return [event["uri"] for event in self._http_requests if event.get("uri")]

    @property
    def http_urilog(self):
        return "\n".join(self.http_uris)
    
    @property
    def http_urilog_hash(self):
        if self.http_uris:
            return sha256hex(self.http_urilog)


    @property
    def http_requests(self):
        """Verbose property name and OrderedSet wrapper for _http_requests to expose to AI model tools"""
        return SetReprOrderedSet(self.http_request_strs)


    @property
    def hosts(self):
        return self.cmdlog_hosts + self.httplog_hosts


    def __repr__(self) -> str:
        return ''.join([
            f"Session {self.session_id} "
            f"{self.protocol.upper()} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ",
            f"Login: {self.username}:{self.password} " if self.login_success else "",
            f"Commands: {len(self.commands)}, " if self.commands else "",
            f"Malware: {len(self.malware)}, " if self.malware else "",
            f"HTTP Requests: {len(self._http_requests)}, " if self._http_requests else "",
            f"Duration: {self.duration:.2f}s"
        ])


        