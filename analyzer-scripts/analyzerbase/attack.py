from .baseobjects import *
from .common import *
from .malware import Malware
from .util import split_commands, extract_hosts_from_parsed_urls
from functools import partial



class Attack:
    ATTACKS_PATH = Path("./attacks")

    def __init__(self, attack_id, attack_id_type, source_ip) -> None:
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

        self.malware = {malware.id: malware for malware in source_ip.all_malware}
        # self.malware = {malware.id: malware for malware in source_ip.all_malware 
        #                 if not malware.failed and not malware.is_duplicate}

        self.standardized_malware = defaultdict(list)
        for malware in self.malware.values():
            self.standardized_malware[malware.standardized_hash].append(malware)


        self.postprocessors = []

        
        self.log_paths = {}
        self._log_counts = {}
        self.command_explanations = {}
        self.standardized_malware_explanations = {}
        self.ipdata = {}
        self.questions = {}
        self.answers = {}
        


    def add_source_ip(self, source_ip):
        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)



    def merge(self, other):
        for source_ip in other.source_ips:
            self.add_source_ip(source_ip)

        self.cmdlog_hashes.update(other.cmdlog_hashes)
        self.malware.update(other.malware)

        for malware in other.malware.values():
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
        return self.malware.get(malware_id)


    @property
    def sessions(self):
        sessions = [
            session for source_ip in self.source_ips for session in source_ip.sessions.values()]
        sessions.sort(key=lambda session: session.start_time)
        return sessions


    @property
    def login_sessions(self):
        return [session for session in self.sessions if session.login_success]

    @property
    def command_sessions(self):
        return [session for session in self.sessions if session.commands]
    
    @property
    def malware_sessions(self):
        return [session for session in self.sessions if session.malware]


    @property
    def ssh_sessions(self):
        return [session for session in self.sessions if session.protocol == "SSH"]

    @property
    def telnet_sessions(self):
        return [session for session in self.sessions if session.protocol == "TELNET"]

    @property
    def http_sessions(self):
        return [session for session in self.sessions if session.protocol == "HTTP"]


    @property
    def start_time(self):
        return min([session.start_time for session in self.sessions])

    @property
    def end_time(self):
        return max([session.end_time for session in self.sessions if session.end_time])

    @property
    def all_successful_login_pairs(self):
        return [login_pair for source_ip in self.source_ips for login_pair in source_ip.all_successful_login_pairs]

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
    def all_successful_usernames(self):
        return [login_pair[0] for login_pair in self.all_successful_login_pairs]

    @property
    def all_successful_passwords(self):
        return [login_pair[1] for login_pair in self.all_successful_login_pairs]

    @property
    def all_ssh_hasshs(self):
        return [session.ssh_hassh for session in self.sessions if session.ssh_hassh]

    @property
    def all_ssh_versions(self):
        return [session.ssh_version for session in self.sessions if session.ssh_version]

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
    def all_cmdlog_hosts(self):
        return [host for session in self.sessions for host in session.cmdlog_hosts]
    

    @property
    def all_malware_urls(self):
        return [url for malware in self.malware.values() for url in malware.urls]

    @property
    def all_malware_ips(self):
        return [ip for malware in self.malware.values() for ip in malware.ips]
    
    @property
    def all_malware_source_addresses(self):
        return [malware.source_address for malware in self.malware.values() if malware.source_address]

    @property
    def all_malware_hosts(self):
        return [host for malware in self.malware.values() for host in malware.hosts]


    @property
    def all_malware_shasums(self):
        return [malware.shasum for malware in self.malware.values() if malware.shasum]


    @property
    def all_http_requests(self):
        return [http_request_str for session in self.sessions for http_request_str in session.http_request_strs]    

    @property
    def all_http_request_events(self):
        return [http_request_event for session in self.sessions for http_request_event in session.http_request_events]
    
    @property
    def all_http_request_uris(self):
        return [http_request_event["uri"] for http_request_event in self.all_http_request_events if http_request_event.get("uri")]


    @property
    def all_urls(self):
        return self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses

    @property
    def all_ips(self):
        return self.all_src_ips + self.all_cmdlog_ips + self.all_malware_ips

    @property
    def all_ips_and_urls(self):
        return self.all_ips + self.all_cmdlog_urls + self.all_malware_urls + self.all_malware_source_addresses

    @property
    def all_non_src_ip_hosts(self):
        return self.all_cmdlog_hosts + self.all_malware_hosts

    @property
    def all_hosts(self):
        return self.all_non_src_ip_hosts + self.all_src_ips


    @property
    def counts(self):
        if hasattr(self, "_counts"):
            return self._counts

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

    def refresh_counts(self):
        del self._counts
        return self.counts



    @property
    def log_counts(self):
        if self._log_counts:
            return self._log_counts
        else:
            return {'all': {}}
        

    @property
    def log_types(self, ip="all"):
        return [log_name for log_name in self.log_counts[ip] if log_name != "_lines" and log_name != "_files"]



    def __getattr__(self, attr):
        
        outfn = lambda x: x
        if attr.startswith("num_"):
            outfn = len
            attr = attr.replace("num_", "")

        elif attr.startswith("min_"):
            outfn = min
            attr = attr.replace("min_", "")

        elif attr.startswith("max_"):
            outfn = max
            attr = attr.replace("max_", "")

        elif attr.endswith("counter"):
            outfn = Counter
            attr = attr.replace("_counter", "")

        
        elif attr.startswith("most_common"):
            n_str = attr.split("_")[1].replace("common", "")

            
            if n_str:
                n = int(n_str)
                outfn = lambda x: Counter(x).most_common(n)
                attr = attr.replace(f"most_common{n_str}_", "")
            else:
                n = 1
                outfn = lambda x: Counter(x).most_common(n)[0][0]
                attr = attr.replace("most_common_", "") + ("s" if not attr.endswith("s") else "")

            

        elif attr.startswith("first"):
            # Allow for first_<attr> and first<n>_<attr> to get the first n items
            end_slice = attr.split("_")[0].replace("first", "")
            if end_slice:
                outfn = lambda x: x[:int(end_slice)]
                attr = attr.replace(f"first{end_slice}_", "")
            else:
                outfn = lambda x: x[0] if x else None
                attr = attr.replace("first_", "") + ("s" if not attr.endswith("s") else "")


        elif attr.startswith("last"):
            # Allow for last_<attr> and last<n>_<attr> to get the last n items
            start_slice = attr.split("_")[0].replace("last", "")
            if start_slice:
                outfn = lambda x: x[-int(start_slice):]
                attr = attr.replace(f"last{start_slice}_", "")
            else:
                outfn = lambda x: x[-1] if x else None
                attr = attr.replace("last_", "") + ("s" if not attr.endswith("s") else "")


       
        infn = lambda x: x
        if attr.startswith("uniq_"):
            infn = SetReprOrderedSet
            attr = attr.replace("uniq_", "")
        
        # Hanndle common typos/abbreviations by AI
        if not attr.startswith("all_") and "all_" + attr in dir(self):
            attr = "all_" + attr
        elif not attr.endswith("s") and attr + "s" in dir(self):
            attr += "s"
        elif attr.endswith("s") and attr[:-1] in dir(self):
            attr = attr[:-1]

        
        return outfn(infn(super().__getattribute__(attr)))
        

    def add_postprocessor(self, postprocessor_obj):

        # Add the attack to the postprocessor.attacks list so _all_ methods can access it
        postprocessor_obj.attacks[self.attack_id] = self

        # Add the postprocessor to the attack.postprocessors dict so it can be accessed by name
        self.postprocessors.append(postprocessor_obj)
        self._update_postprocessor_attrs()
        return True


    def _update_postprocessor_attrs(self):
        # self.postprocessor_fns = {}
        for postprocessor_obj in self.postprocessors:

            for attr in set(dir(postprocessor_obj)) - set(dir(self)):

                # Dont add private attributes
                if attr.startswith("_"):
                    continue

                # If the postprocessor has a function with the same name as the attack, add it to the attack
                # but rename it remove _attack_ for clarity and replace the function with a lambda that
                # puts self as the first argument. For example:
                # AttackLogReader.update_attack_log_paths(attack, *args, **kwargs) -> Attack.update_log_paths(self, *args, **kwargs)))

                postprocesor_function = getattr(postprocessor_obj, attr)
                if callable(postprocesor_function):
                    if "_attack_" in attr:

                        fn_name = attr.replace("_attack_", "_", )
                        fn = partial(getattr(postprocessor_obj, attr), self)

                        setattr(self, fn_name, fn)
                        print(f"Added {fn} {fn_name} to {self.attack_id} from {postprocessor_obj}")
        
        return True
    


    def update_ipdata(self, ipdata):
        self.ipdata = ipdata

    def update_mwdata(self, mwdata):
        self.mwdata = mwdata

    def update_command_explanations(self, command_explanations):
        self.command_explanations = command_explanations

    def update_malware_explanations(self, standardized_malware_explanations):
        self.standardized_malware_explanations.update(standardized_malware_explanations)
    
    

    def __repr__(self):
#        return f"Attack ({self.attack_id_type[0]}hash: {self.attack_id[:10]}) with {len(self.source_ips)} source IPs and {len(self.sessions)} sessions, {len(self.successful_login_pairs)} successful logins, {len(self.commands)} commands, {len(self.cmdlog_hashes)} cmdlog hashes, {len(self.malware)} malware hashes"
        return ''.join([
            f"Attack ({self.attack_id_type[0]}hash: {self.attack_id[:10]}), "
            f"SourceIPs: {len(self.source_ips)}, " if self.source_ips else "",
            f"Sessions: {len(self.sessions)}, " if self.sessions else "",
            f"SSH: {len(self.ssh_sessions)}, " if self.ssh_sessions else "",
            f"Telnet: {len(self.telnet_sessions)}, " if self.telnet_sessions else "",
            f"HTTP: {len(self.http_sessions)}, " if self.http_sessions else "",
            f"Commands: {len(self.commands)}, " if self.commands else "",
            f"Cmdlogs: {len(self.cmdlog_hashes)}, " if self.cmdlog_hashes else "",
            f"Malware: {len(self.malware)} " if self.malware else "",
            f"Httplogs: {len(self.httplog_hashes)} " if self.httplog_hashes else "",

        
         ])