from .common import *
from .malware import Malware

class Attack:
    attacks_path = test_attacks_path
    def __init__(self, attack_id, attack_id_type, source_ip) -> None:
        self.attack_id = attack_id
        self.attack_id_type = attack_id_type
        self.source_ips = [source_ip,]

        self.commands = list(source_ip.all_commands)

        self.cmdlog_hashes = {session.cmdlog_hash: session.commands for session in source_ip.sessions.values() if session.commands}
        self.malware = {shasum: Malware(shasum) for  shasum in source_ip.all_malware_hashes} #set(source_ip.all_malware)
        

        self.log_paths = {}
        self.command_explainations = {}
        self._log_counts = {}

    
    def add_source_ip(self, source_ip):
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)


    def update_log_paths(self, log_paths):
        self.log_paths = log_paths

    def update_command_explainations(self, command_explainations):
        self.command_explainations = command_explainations

    def __add__(self, other):
        for source_ip in other.source_ips:
            self.add_source_ip(source_ip)
        self.cmdlog_hashes.update(other.cmdlog_hashes)
        self.malware.update(other.malware)

        return self
    
    @property
    #@staticmethod
    def split_commands(self):
        split_commands = []
        ifor_regex = re.compile(r"if .+?; then.+?fi;?|for .+?; do.+?done;?")


        for command in self.commands:

            while match := ifor_regex.search(command):
                split_cmd = ifor_regex.split(command, 1)
                split_commands.extend(cmd_part for cmd_part in split_cmd[0].split(";") if cmd_part.strip())
                split_commands.append(match.group(0))
                command = split_cmd[1].strip()

            if ";" in command:
                split_commands.extend(cmd_part.strip() for cmd_part in command.split(";") if cmd_part.strip())
            elif command:
                split_commands.append(command)


        return split_commands

    def get_session(self, session_id):
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        return None

    @property
    def sessions(self):
        sessions = [session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions
    
    @property
    def login_sessions(self):
        return [session for session in self.sessions if session.login_success]
    
    @property
    def command_sessions(self):
        return [session for session in self.sessions if session.commands]
    
    @property
    def first_session(self):
        return self.sessions[0]
    
    @property
    def last_session(self):
        return self.sessions[-1]
    
    @property
    def first_login_session(self):
        return self.login_sessions[0]
    
    @property
    def last_login_session(self):
        return self.login_sessions[-1]
    
    @property
    def first_command_session(self):
        return self.command_sessions[0]
    
    @property
    def last_command_session(self):
        return self.command_sessions[-1]
    
    @property
    def start_time(self):
        return min([session.start_time for session in self.sessions])
    
    @property
    def end_time(self):
        return max([session.end_time for session in self.sessions if session.end_time])

    @property
    def successful_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.successful_login_pairs]
    
    @property
    def all_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_login_pairs]

    @property
    def all_usernames(self):
        return [login_pair[0] for login_pair in self.all_login_pairs]
    
    @property
    def all_passwords(self):
        return [login_pair[1] for login_pair in self.all_login_pairs]
    
    @property
    def successful_usernames(self):
        return [login_pair[0] for login_pair in self.successful_login_pairs]
    
    @property
    def successful_passwords(self):
        return [login_pair[1] for login_pair in self.successful_login_pairs]

    @property
    def all_src_ips(self):
        return [session.src_ip for session in self.sessions]
    
    @property
    def all_dst_ips(self):
        return [session.dst_ip for session in self.sessions]

    @property
    def all_src_ports(self):
        return [session.src_port for session in self.sessions]
    
    @property
    def all_dst_ports(self):
        return [session.dst_port for session in self.sessions]
    
    @property
    def all_cmdlog_urls(self):
        return [url for session in self.sessions for url in session.cmdlog_urls]

    @property
    def all_cmdlog_ips(self):
        return [ip for session in self.sessions for ip in session.cmdlog_ips]
    
    @property
    def all_malware_urls(self):
        return [url for malware in self.malware.values() for url in malware.urls]

    @property
    def all_malware_ips(self):
        return [ip for malware in self.malware.values() for ip in malware.ips]
    
    @property
    def all_ips(self):
        return self.all_src_ips + self.all_cmdlog_ips + self.all_malware_ips
    
    @property
    def all_ips_and_urls (self):
        return self.all_ips + self.all_cmdlog_urls + self.all_malware_urls

    @property
    def counts(self):
        counts = defaultdict(Counter)
        props = ["successful_login_pairs", "successful_usernames", "successful_passwords",
                 "all_login_pairs", "all_usernames", "all_passwords",
                 "all_src_ips", "all_dst_ips",
                 "all_src_ports", "all_dst_ports",
                 "all_cmdlog_urls", "all_cmdlog_ips",
                 "all_malware_urls", "all_malware_ips"
                 ]
        
        for prop in props:
            counts[prop].update(getattr(self, prop))

        return counts

    def get_log_paths(self, ip="all", log_type="all", ext="all"):
        return [log_path for log_path in self.log_paths.get(ip,()) 
                if (log_type == "all" or log_type in log_path.name) 
                and (ext == "all" or log_path.suffix == ext)
                ]
    
    def get_log_names(self, ip="all", log_type="all", ext="all"):
        return [log_path.name for log_path in self.log_paths.get(ip,()) 
                if (log_type == "all" or log_type in log_path.name) 
                and (ext == "all" or log_path.suffix == ext)
                ]
    
    def get_log_counts(self, ips="all", log_filter="all"):
        if log_filter == "all":
            log_filters = ["cowrie.log", "cowrie.json", "web.json", "dshield.log", "zeek.log"]
        else:
            log_filters = (log_filter,)

        if ips == "all":
            ips = ["all",] + [src_ip.ip for src_ip in self.source_ips]
        elif isinstance(ips, str):
            ips = [ips,]
        else:
            ips = ips

        #log_counts =  defaultdict(lambda: defaultdict(Counter))
        log_counts = defaultdict(dict)
        #{'all': {'lines':1000,'files':100, 'cowrie.log': {'lines','files'}, 'cowrie.json': {'lines','files'}, 'web.json': {'lines','files'}, 'dshield.log': {'lines','files'}, 'zeek.log': {'lines','files'}}, '

        for ip in ips:
            for log_filter in log_filters:
                log_type, ext = log_filter.rsplit(".", 1)
                ext = "." + ext
                
                log_counts[ip][log_filter] = {}
                log_counts[ip][log_filter]["files"] = 0
                log_counts[ip][log_filter]["lines"] = 0
                for log_path in self.get_log_paths(ip, log_type, ext): 
                    #log_counts[ip][log_filter].update(("files",))
                    log_counts[ip][log_filter]["files"] += 1

                    with log_path.open("rb") as f:
                        log_counts[ip][log_filter][log_path.name] = sum(1 for line in f)
                        log_counts[ip][log_filter]["lines"] += log_counts[ip][log_filter][log_path.name]
                        #log_counts[ip][log_filter].update("lines" for line in f)

                if log_counts[ip][log_filter]["files"] == 0:
                    del log_counts[ip][log_filter]

            found_log_filters = list(log_counts[ip].keys())
            log_counts[ip]["lines"] = sum(log_counts[ip][log_filter]["lines"] for log_filter in found_log_filters)
            log_counts[ip]["files"] = sum(log_counts[ip][log_filter]["files"] for log_filter in found_log_filters)
        
        self._log_counts = log_counts
        return log_counts
    

    @property
    def log_counts(self):
        if self._log_counts:
            return self._log_counts
        else:
            return self.get_log_counts()
        
    @property
    def log_types(self, ip="all"):
        return [log_name for log_name in self.log_counts[ip] if log_name != "lines" and log_name != "files"]
        

    def get_log_lines(self, ip, log_filter, n_lines=-1, session_id=None):
        log_type, ext = log_filter.rsplit(".", 1)
        ext = "." + ext
        

        log_paths = self.get_log_paths(ip, log_type, ext)
        if log_paths:
            log_path = log_paths[0]
            with log_path.open("r") as f:
                lines = [line for line in f if session_id is None or session_id in line]
                if n_lines and n_lines > len(lines):
                    n_lines = None

                return "\n".join(lines[:n_lines])
        else:
            return f"No {log_filter} logs found"





    def __repr__(self):
        return f"Attack ({self.attack_id_type}: {self.attack_id[:10]}) with {len(self.source_ips)} source IPs and {len(self.sessions)} sessions, {len(self.successful_login_pairs)} successful logins, {len(self.commands)} commands, {len(self.cmdlog_hashes)} cmdlog hashes, {len(self.malware)} malware hashes"    




        # log_counts =  defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
        # for ip in ips:
        #     for log_type in log_types:
        #         for log_path in self.get_log_paths(ip, log_type): 
        #             log_counts[ip][log_type]["files"].update((log_path.name,))
        #             with log_path.open("rb") as f:
        #                 for line in f:
        #                     log_counts[ip][log_type]["lines"].update((1,))
                        
        #             #log_counts[ip][log_type]["lines"].update(log_path.read_text().splitlines())
        
        
        # return log_counts