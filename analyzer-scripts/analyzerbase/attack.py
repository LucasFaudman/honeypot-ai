from .baseobjects import *
from .common import *
from .malware import Malware
from .util import split_commands, extract_hosts_from_parsed_urls




class Attack(SmartAttrObject, CachedPropertyObject, PostprocessableObject):
    ATTACKS_PATH = Path("./attacks")

    def __init__(self, attack_id, attack_id_type, source_ip) -> None:
        SmartAttrObject.__init__(self)
        CachedPropertyObject.__init__(self)
        PostprocessableObject.__init__(self)

        self.attack_id = attack_id
        self.attack_id_type = attack_id_type
        self.attack_dir = self.ATTACKS_PATH / self.attack_id
        
        self.source_ips = [source_ip,]

        self.commands = list(source_ip.all_commands)
        self.split_commands = split_commands(self.commands)

        self.cmdlog_hashes = {
            session.cmdlog_hash: session.commands for session in source_ip.sessions.values() if session.commands}

        self.httplog_hashes = {
            session.httplog_hash: session.httplog for session in source_ip.sessions.values() if session.httplog
            }

        
        self._malware = {malware.id: malware for malware in source_ip.all_malware}        
        self.log_paths = {}
        self._log_counts = {}
        self.command_explanations = {}
        self.standardized_malware_explanations = {}
        self.ipdata = {}
        self.mwdata = {}
        self.questions = {}
        self.question_run_logs = {}
        self.answers = {}
        
        

    def add_source_ip(self, source_ip):
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)


    def merge(self, other):
        for source_ip in other.source_ips:
            self.add_source_ip(source_ip)

        self.cmdlog_hashes.update(other.cmdlog_hashes)
        self._malware.update(other._malware)

        for malware in other._malware.values():
            self.standardized_malware[malware.standardized_hash].append(
                malware)
        
        return self


    def __add__(self, other):
        return self.merge(other)



    def get_session_by_id(self, session_id):
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        return None
    
    def get_malware_by_id(self, malware_id):
        return self._malware.get(malware_id)

    
    @cachedproperty
    def malware(self):
        return list(self._malware.values())
    
    @cachedproperty
    def standardized_malware(self):
        self._standardized_malware = defaultdict(list)
        for malware in self._malware.values():
            self._standardized_malware[malware.standardized_hash].append(malware)
        return self._standardized_malware


    @cachedproperty
    def sessions(self):
        sessions = [
            session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions

    @cachedproperty
    def login_sessions(self):
        return [session for session in self.sessions if session.login_success]

    @cachedproperty
    def command_sessions(self):
        return [session for session in self.sessions if session.commands]
    
    @cachedproperty
    def malware_sessions(self):
        return [session for session in self.sessions if session.malware]


    @cachedproperty
    def ssh_sessions(self):
        return [session for session in self.sessions if session.protocol == "SSH"]

    @cachedproperty
    def telnet_sessions(self):
        return [session for session in self.sessions if session.protocol == "TELNET"]

    @cachedproperty
    def http_sessions(self):
        return [session for session in self.sessions if session.protocol == "HTTP"]


    @cachedproperty
    def start_time(self):
        return min([session.start_time for session in self.sessions])

    @cachedproperty
    def end_time(self):
        return max([session.end_time for session in self.sessions if session.end_time])

    @cachedproperty
    def all_successful_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_successful_login_pairs]

    @cachedproperty
    def all_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_login_pairs]

    @cachedproperty
    def all_usernames(self):
        return [login_pair[0] for login_pair in self.all_login_pairs]

    @cachedproperty
    def all_passwords(self):
        return [login_pair[1] for login_pair in self.all_login_pairs]

    @cachedproperty
    def all_successful_usernames(self):
        return [login_pair[0] for login_pair in self.all_successful_login_pairs]

    @cachedproperty
    def all_successful_passwords(self):
        return [login_pair[1] for login_pair in self.all_successful_login_pairs]

    @cachedproperty
    def all_ssh_hasshs(self):
        return [session.ssh_hassh for session in self.sessions if session.ssh_hassh]

    @cachedproperty
    def all_ssh_versions(self):
        return [session.ssh_version for session in self.sessions if session.ssh_version]

    @cachedproperty
    def all_src_ips(self):
        return [session.src_ip for session in self.sessions]

    @cachedproperty
    def all_dst_ips(self):
        return [session.dst_ip for session in self.sessions]

    @cachedproperty
    def all_src_ports(self):
        return [session.src_port for session in self.sessions]

    @cachedproperty
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions]

    @cachedproperty
    def all_cmdlog_urls(self):
        return [url for session in self.sessions for url in session.cmdlog_urls]

    @cachedproperty
    def all_cmdlog_ips(self):
        return [ip for session in self.sessions for ip in session.cmdlog_ips]


    @cachedproperty
    def all_cmdlog_hosts(self):
        return [host for session in self.sessions for host in session.cmdlog_hosts]
    

    @cachedproperty
    def all_malware_urls(self):
        return [url for malware in self._malware.values() for url in malware.urls]

    @cachedproperty
    def all_malware_ips(self):
        return [ip for malware in self._malware.values() for ip in malware.ips]
    
    @cachedproperty
    def all_malware_source_addresses(self):
        return [malware.source_address for malware in self._malware.values() if malware.source_address]

    @cachedproperty
    def all_malware_hosts(self):
        return [host for malware in self._malware.values() for host in malware.hosts]


    @cachedproperty
    def all_malware_shasums(self):
        return [malware.shasum for malware in self._malware.values() if malware.shasum]


    @cachedproperty
    def all_http_requests(self):
        return [http_request_str for session in self.sessions for http_request_str in session.http_request_strs]    

    @cachedproperty
    def all_http_request_events(self):
        return [http_request_event for session in self.sessions for http_request_event in session.http_request_events]
    
    @cachedproperty
    def all_http_request_uris(self):
        return [http_request_event["uri"] for http_request_event in self.all_http_request_events if http_request_event.get("uri")]


    @cachedproperty
    def all_urls(self):
        return self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses

    @cachedproperty
    def all_ips(self):
        return self.all_src_ips + self.all_cmdlog_ips + self.all_malware_ips

    @cachedproperty
    def all_ips_and_urls(self):
        return self.all_ips + self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses

    @cachedproperty
    def all_non_src_ip_hosts(self):
        return self.all_cmdlog_hosts + self.all_malware_hosts

    @cachedproperty
    def all_hosts(self):
        return self.all_non_src_ip_hosts + self.all_src_ips


    @cachedproperty
    def counts(self):
        self._counts = defaultdict(Counter)
        props = ["successful_login_pairs", "successful_usernames", "successful_passwords",
                 "login_pairs", "usernames", "passwords",
                 "ssh_hasshs", "ssh_versions",
                 "src_ips", "dst_ips",
                 "src_ports", "dst_ports",
                 "cmdlog_urls", "cmdlog_ips",
                 "malware_urls", "malware_ips"
                 ]

        for prop in props:
            self._counts[prop].update(getattr(self, prop))

        return self._counts


    @cachedproperty
    def log_counts(self):
        if self._log_counts:
            return self._log_counts
        else:
            return {'all': {}}
        

    @cachedproperty
    def log_types(self, ip="all"):
        return [log_name for log_name in self.log_counts[ip] if log_name != "_lines" and log_name != "_files"]



    def update_ipdata(self, ipdata):
        self.ipdata = ipdata

    def update_mwdata(self, mwdata):
        self.mwdata = mwdata

    def update_command_explanations(self, command_explanations):
        self.command_explanations = command_explanations

    def update_malware_explanations(self, standardized_malware_explanations):
        self.standardized_malware_explanations.update(standardized_malware_explanations)
    
    
    def __str__(self):
        return ''.join([
            f"Attack ({self.attack_id_type[0]}hash: {self.attack_id}), "
            f"SourceIPs: {len(self.source_ips)}, " if self.source_ips else "",
            f"Sessions: {len(self.sessions)}, " if self.sessions else "",
            f"SSH: {len(self.ssh_sessions)}, " if self.ssh_sessions else "",
            f"Telnet: {len(self.telnet_sessions)}, " if self.telnet_sessions else "",
            f"HTTP: {len(self.http_sessions)}, " if self.http_sessions else "",
            f"Commands: {len(self.commands)}, " if self.commands else "",
            f"Cmdlogs: {len(self.cmdlog_hashes)}, " if self.cmdlog_hashes else "",
            f"Malware: {len(self._malware)} " if self._malware else "",
            f"Httplogs: {len(self.httplog_hashes)} " if self.httplog_hashes else "",
         ])
    
    def __repr__(self) -> str:
        return self.__str__()