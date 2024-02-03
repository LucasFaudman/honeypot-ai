from .baseobjects import *
from .common import *
from .malware import Malware
from .util import print_box, pprint_str

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
        """Adds source_ip to self.source_ips if not already present"""
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)


    def merge(self, other):
        """Merges other Attack into self combining attributes and source_ips"""
        for source_ip in other.source_ips:
            self.add_source_ip(source_ip)

        self.cmdlog_hashes.update(other.cmdlog_hashes)
        self._malware.update(other._malware)

        for malware in other._malware.values():
            self.standardized_malware[malware.standardized_hash].append(
                malware)
        
        return self


    def __add__(self, other):
        """Adds other Attack to self combining attributes and source_ips. Alias for self.merge(other)"""
        return self.merge(other)



    def get_session_by_id(self, session_id):
        """Returns Session object with session_id or None if not found in Attack.sessions"""
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        return None


    def get_malware_by_id(self, malware_id):
        """Returns Malware object with malware_id or None if not found in Attack._malware"""
        return self._malware.get(malware_id)

    
    # Begin CachedPropertyObject @cachedproperty methods
    @cachedproperty
    def split_commands(self):
        """Returns list of all commands in Attack split into individual commands"""
        return recursive_split_commands(self.commands)
    

    @cachedproperty
    def malware(self):
        """Returns list of Malware objects in Attack"""
        return list(self._malware.values())
    

    @cachedproperty
    def standardized_malware(self):
        """Returns dict of lists of Malware objects in Attack keyed by standardized_hash"""
        self._standardized_malware = defaultdict(list)
        for malware in self._malware.values():
            self._standardized_malware[malware.standardized_hash].append(malware)
        return self._standardized_malware


    @cachedproperty
    def sessions(self):
        """Returns list of all Session objects in Attack sorted by start_time"""
        sessions = [
            session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions


    @cachedproperty
    def login_sessions(self):
        """Returns list of all Session objects in Attack that were successful logins"""
        return [session for session in self.sessions if session.login_success]


    @cachedproperty
    def command_sessions(self):
        """Returns list of all Session objects in Attack that have commands"""
        return [session for session in self.sessions if session.commands]
    

    @cachedproperty
    def malware_sessions(self):
        """Returns list of all Session objects in Attack that have malware"""
        return [session for session in self.sessions if session.malware]


    @cachedproperty
    def ssh_sessions(self):
        """Returns list of all Session objects in Attack that have protocol "SSH" """
        return [session for session in self.sessions if session.protocol == "SSH"]

    
    @cachedproperty
    def telnet_sessions(self):
        """Returns list of all Session objects in Attack that have protocol "TELNET" """
        return [session for session in self.sessions if session.protocol == "TELNET"]

    
    @cachedproperty
    def http_sessions(self):
        """Returns list of all Session objects in Attack that have protocol "HTTP" """
        return [session for session in self.sessions if session.protocol == "HTTP"]


    @cachedproperty
    def start_time(self):
        """Returns earliest start_time of all Session objects in Attack as datetime.datetime object"""
        return min([session.start_time for session in self.sessions])

    
    @cachedproperty
    def end_time(self):
        """Returns latest end_time of all Session objects in Attack as datetime.datetime object"""
        return max([session.end_time for session in self.sessions if session.end_time])


    @cachedproperty
    def all_successful_login_pairs(self):
        """Returns all successful login pairs in Attack as list of tuples (username, password)"""
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_successful_login_pairs]

    
    @cachedproperty
    def all_login_pairs(self):
        """Returns all login pairs in Attack as list of tuples (username, password)"""
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_login_pairs]

    
    @cachedproperty
    def all_usernames(self):
        """Returns all usernames in Attack as list of strings"""
        return [login_pair[0] for login_pair in self.all_login_pairs]

    
    @cachedproperty
    def all_passwords(self):
        """Returns all passwords in Attack as list of strings"""
        return [login_pair[1] for login_pair in self.all_login_pairs]

    
    @cachedproperty
    def all_successful_usernames(self):
        """Returns all successful usernames in Attack as list of strings"""
        return [login_pair[0] for login_pair in self.all_successful_login_pairs]

    
    @cachedproperty
    def all_successful_passwords(self):
        """Returns all successful passwords in Attack as list of strings"""
        return [login_pair[1] for login_pair in self.all_successful_login_pairs]

    
    @cachedproperty
    def all_ssh_hasshs(self):
        """Returns all SSH hasshs in Attack as list of strings"""
        return [session.ssh_hassh for session in self.sessions if session.ssh_hassh]

    
    @cachedproperty
    def all_ssh_versions(self):
        """Returns all SSH versions in Attack as list of strings"""
        return [session.ssh_version for session in self.sessions if session.ssh_version]

    
    @cachedproperty
    def all_src_ips(self):
        """Returns all source IP addresses in Attack as list of strings"""
        return [session.src_ip for session in self.sessions]

    
    @cachedproperty
    def all_dst_ips(self):
        """Returns all destination IP addresses in Attack as list of strings"""
        return [session.dst_ip for session in self.sessions]

    
    @cachedproperty
    def all_src_ports(self):
        """Returns all source ports in Attack as list of ints"""
        return [session.src_port for session in self.sessions]

    
    @cachedproperty
    def all_dst_ports(self):
        """Returns all destination ports in Attack as list of ints"""
        return [session.dst_port for session in self.sessions]

    
    @cachedproperty
    def all_cmdlog_urls(self):
        """Returns all urls found in Attack commands as list of strings"""
        return [url for session in self.sessions for url in session.cmdlog_urls]

    
    @cachedproperty
    def all_cmdlog_ips(self):
        """Returns all ips found in Attack commands as list of strings"""
        return [ip for session in self.sessions for ip in session.cmdlog_ips]


    @cachedproperty
    def all_cmdlog_hosts(self):
        """Returns all hosts found in Attack commands as list of strings"""
        return [host for session in self.sessions for host in session.cmdlog_hosts]
    

    @cachedproperty
    def all_malware_urls(self):
        """Returns all urls found in Attack malware as list of strings"""
        return [url for malware in self._malware.values() for url in malware.urls]


    @cachedproperty
    def all_malware_ips(self):
        """Returns all ips found in Attack malware as list of strings"""
        return [ip for malware in self._malware.values() for ip in malware.ips]
    
    
    @cachedproperty
    def all_malware_source_addresses(self):
        """Returns all source_addresses found in Attack malware as list of strings"""
        return [malware.source_address for malware in self._malware.values() if malware.source_address]

    
    @cachedproperty
    def all_malware_hosts(self):
        """Returns all hosts found in Attack malware as list of strings"""
        return [host for malware in self._malware.values() for host in malware.hosts]


    @cachedproperty
    def all_malware_shasums(self):
        """Returns sha256 hashes of all malware in Attack as list of strings"""
        return [malware.shasum for malware in self._malware.values() if malware.shasum]


    @cachedproperty
    def all_http_requests(self):
        """Returns all http_requests in Attack as list of strings"""
        return [http_request_str for session in self.sessions for http_request_str in session.http_request_strs]    

    
    @cachedproperty
    def all_http_request_events(self):
        """Returns all http_request_events in Attack as list of dicts"""
        return [http_request_event for session in self.sessions for http_request_event in session.http_request_events]
    
    
    @cachedproperty
    def all_http_request_uris(self):
        """Returns all http_request_uris in Attack as list of strings"""
        return [http_request_event["uri"] for http_request_event in self.all_http_request_events if http_request_event.get("uri")]


    @cachedproperty
    def all_urls(self):
        """Returns all urls found in Attack as list of strings"""
        return self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses


    @cachedproperty
    def all_ips(self):
        """Returns all ips found in Attack as list of strings"""
        return self.all_src_ips + self.all_cmdlog_ips + self.all_malware_ips


    @cachedproperty
    def all_ips_and_urls(self):
        """Returns all ips and urls found in Attack as list of strings"""
        return self.all_ips + self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses


    @cachedproperty
    def all_non_src_ip_hosts(self):
        """Returns all hosts found in Attack as list of strings excluding source_ips"""
        return self.all_cmdlog_hosts + self.all_malware_hosts


    @cachedproperty
    def all_hosts(self):
        """Returns all hosts found in Attack as list of strings including source_ips"""
        return self.all_non_src_ip_hosts + self.all_src_ips


    @cachedproperty
    def counts(self):
        """Returns defaultdict of Counters of other Attack attributes"""
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
        """Returns dict of log file and log event counts for each source_ip in Attack with the additional key "all" for holding totals for all source_ips"""
        if self._log_counts:
            return self._log_counts
        else:
            return {'all': {}}
        

    @cachedproperty
    def log_types(self, ip="all"):
        """Returns list of log types present in Attack"""
        return [log_name for log_name in self.log_counts[ip] if log_name != "_lines" and log_name != "_files"]



    def update_ipdata(self, ipdata):
        """Updates self.ipdata with ipdata"""
        self.ipdata.update(ipdata)

    def update_mwdata(self, mwdata):
        """Updates self.mwdata with mwdata"""
        self.mwdata.update(mwdata)

    def update_command_explanations(self, command_explanations):
        """Updates self.command_explanations with command_explanations"""
        self.command_explanations.update(command_explanations)

    def update_malware_explanations(self, standardized_malware_explanations):
        """Updates self.standardized_malware_explanations with standardized_malware_explanations"""
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
    

    def print_attrs(self, *attrs):
        """Prints self then attributes of self"""
        # print(f"\n{self}")
        print()
        for attr in attrs:
            print(self)
            print_box(pprint_str(getattr(self, attr)), title=attr)
        print()


def recursive_split_commands(commands):
    """Recursively splits long chained commands into individual commands and returns flat list of split commands"""
    split_commands = []
    block_regex = re.compile(r"if .+?; then.+?fi;?|(?:for|while) .+?; do.+?done;?|case .+?esac;?")
    
    for command in commands:    
        while match := block_regex.search(command):
            split_cmd = block_regex.split(command, 1)
            # Recursively split commands in blocks
            split_commands.extend(recursive_split_commands([split_cmd[0],]))

            if split_cmd[1] and split_cmd[1].strip()[0] in ("<", ">", "|"):
                split_commands.append(match.group(0) + split_cmd[1])
                command = ""
            else:
                split_commands.append(match.group(0))
                # Second part of the split_cmd is the command after the block and will be split again if matched
                command = split_cmd[1].strip()

        #TODO FIX awk
        if ";" in command and not 'awk' in command:
            split_commands.extend(cmd_part.strip() for cmd_part in command.split(";") if cmd_part.strip())
        elif command:
            split_commands.append(command)
    
    return split_commands