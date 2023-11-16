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

    @property
    def sessions(self):
        sessions = [session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions
    
    @property
    def login_sessions(self):
        return [session for session in self.sessions if session.login_success]
    

    @property
    def first_session(self):
        return self.sessions[0]
    
    @property
    def last_session(self):
        return self.sessions[-1]
    
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
        return [session.src_ip for session in self.sessions]

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

    def get_log_paths(self, ip="all", log_type="all"):
        return [log_path for log_path in self.log_paths.get(ip,()) if log_type == "all" or log_type in log_path.name]
        
    

    def __repr__(self):
        return f"Attack ({self.attack_id_type}: {self.attack_id[:10]}) with {len(self.source_ips)} source IPs and {len(self.sessions)} sessions, {len(self.successful_login_pairs)} successful logins, {len(self.commands)} commands, {len(self.cmdlog_hashes)} cmdlog hashes, {len(self.malware)} malware hashes"    
