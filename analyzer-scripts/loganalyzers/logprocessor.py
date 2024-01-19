from analyzerbase import *

from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor

from time import time
from itertools import combinations

class LogProcessor:
    """
    Processes logs from parsers to creates SourceIP and Session objects. Then analyzes the objects to find attacks. 
    """

    def __init__(self, 
                 parsers, 
                 remove_ips=[],
                 min_commands=0,
                 min_malware=0,
                 min_successful_logins=0,
                 min_http_requests=1,
                 http_attack_regexes={
                     "uri": [
                        r'(\||\$|\`|;|\-\-|\{|\}|\[|\]|\(|\)|<|>|\\|\^|\~|\!|\$?\{?IFS\}?|\.\/)',
                     ],

                     "httplog": [
                        r'(\||\$|\`|\{|\}|<|>|\\[^n]|\^|\!|\$?\{?IFS\}?|\.\/)',
                    ]
                 },
                merge_shared_attrs=[
                    "src_ips", 
                    "malware", 
                    "cmdlog_ips", 
                    "cmdlog_urls", 
                    "malware_ips", 
                    "malware_urls",
                ],
                 merge_sig_regexes={
                     "commands": [
                         r">\??A@/ ?X'8ELFX",
                        r"cat /proc/mounts; /bin/busybox [\w\d]+",
                        r"cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+",
                        r"cd ~; chattr -ia .ssh; lockr -ia .ssh",
                    ],
                    "malware": [],
                    "httplog": [],
                 },
                 sort_attrs=["src_ips", "sessions", "commands", "malware", "http_requests"],
                 sort_order = "desc",
                 ):

        self.parsers = parsers
        self.remove_ips = remove_ips
        self.min_commands = min_commands
        self.min_malware = min_malware
        self.min_successful_logins = min_successful_logins
        self.min_http_requests = min_http_requests
        
        self.merge_shared_attrs = merge_shared_attrs

        self.http_attack_regexes = {
            key: list(map(re.compile, http_attack_regexes[key])) for key in http_attack_regexes
            }
        self.merge_sig_regexes = {
            key: list(map(re.compile, merge_sig_regexes[key])) for key in merge_sig_regexes
            }
        
        self.sort_attrs = sort_attrs
        self.sort_order = sort_order

        self.source_ips = {}
        self.attacks = {}
        self.attacks_by_src_ip = {}

        self.exceptions = []


    def set_parsers(self, parsers):
        "Used to change parser after initialization when needed to load attacks for an attack dir"
        self.parsers = parsers


    def load_attacks_from_logs(self):
        """Reads logs from parsers, creates SourceIP and Session objects, analyzes objects to find attacks"""

        self.process_logs_into_source_ips()
        self.process_source_ips_into_attacks()
        self.merge_and_remove_attacks()
        self.sort_attacks()
        return self.attacks
    

    def load_attacks_from_attacks_dir(self, attacks_dir, only_attacks=[], skip_attacks=[]):
        """Loads attacks from organized attack dirs created by AttackOrganizer"""

        for attack_dir in attacks_dir.glob("*"):
            if only_attacks and attack_dir.name not in only_attacks:
                continue
            if skip_attacks and attack_dir.name in skip_attacks:
                continue
            
            # Set logs_path for each parser to the attack_dir
            for parser in self.parsers:
                parser.set_logs_path(attack_dir)

            # Then process logs for the Attack into SourceIP and Session objects
            self.process_logs_into_source_ips()

        # After processing all the logs for each attack in source ips, process them into attacks
        self.process_source_ips_into_attacks()
        self.merge_and_remove_attacks()
        self.sort_attacks()
        return self.attacks
    


    def process_logs_into_source_ips(self):
        """Processes log events into SourceIPs containing Session and Malware objects"""

        total_events = 0
        cowrie_events = 0
        zeek_events = 0
        source_ips_found = 0

        for parser_num, parser in enumerate(self.parsers):
            print(f"Processing Events from Parser {parser_num + 1} of {len(self.parsers)}: {parser}")

            for event in parser.logs():
                total_events += 1
                try:
                    # Init new SourceIP if not already in source_ips
                    if event["src_ip"] not in self.source_ips:
                        source_ips_found += 1
                        self.source_ips[event["src_ip"]] = SourceIP(event["src_ip"])

                    # Init new Session if not already in source_ip.sessions
                    if event["session"] not in self.source_ips[event["src_ip"]].sessions:
                        self.source_ips[event["src_ip"]].add_session(event)

                    # Handle Cowrie Events
                    if event["eventid"].startswith("cowrie"):
                        cowrie_events += 1
                        # Preform relevant action for each eventid on the Session object
                        if event["eventid"].startswith("cowrie.client."):
                            self.source_ips[event["src_ip"]].sessions[event["session"]].add_client_info(event)
                        elif event["eventid"].startswith("cowrie.login."):
                            self.source_ips[event["src_ip"]].sessions[event["session"]].add_login_attempt(event)
                        elif event["eventid"] == "cowrie.command.input":
                            self.source_ips[event["src_ip"]].sessions[event["session"]].add_command(event)
                        elif event["eventid"].startswith("cowrie.session.file_"):
                            self.source_ips[event["src_ip"]].sessions[event["session"]].add_malware(event)
                        elif event["eventid"] == "cowrie.log.closed":
                            self.source_ips[event["src_ip"]].sessions[event["session"]].add_ttylog(event)
                        elif event["eventid"] == "cowrie.session.closed":
                            self.source_ips[event["src_ip"]].sessions[event["session"]].close_session(event)

                    # Handle Zeek Events
                    elif event["eventid"].startswith("zeek"):
                        zeek_events += 1
                        # All Zeek events are added to the Session object and handled the same way for now
                        # More specific handling can be added later as needed
                        self.source_ips[event["src_ip"]].sessions[event["session"]].add_zeek_event(event)

                except Exception as e:
                    self.exceptions.append((event, e))

                print(f"Processed {total_events} events ({cowrie_events} cowrie events, {zeek_events} zeek events). Found {source_ips_found} source ips", end='\r')


        # Process all Sessions for all SourceIPs
        for source_ip in self.source_ips.values():
            source_ip.process_sessions()

        return self.source_ips
    

    def process_source_ips_into_attacks(self):
        """Processes SourceIP and Session objects to find attacks"""

        self.ips_with_successful_logins = []
        self.ips_with_commands = []
        self.ips_with_malware = []
        self.ips_with_commands_only = []
        self.ips_with_http_requests = []
        self.ips_with_flagged_http_requests = []


        for ip, source_ip in self.source_ips.items():

            attack_ids_by_type = defaultdict(OrderedSet)
            
            if source_ip.successful_logins >= self.min_successful_logins:
                self.ips_with_successful_logins.append(ip)

            if source_ip.commands >= self.min_commands:
                self.ips_with_commands.append(ip)

                if source_ip.downloaded_malware + source_ip.uploaded_malware >= self.min_malware:
                    self.ips_with_malware.append(ip)
                    attack_ids_by_type['malware_hash'].update(source_ip.all_malware_hashes)
                else:

                    self.ips_with_commands_only.append(ip)
                    attack_ids_by_type['cmdlog_hash'].update(source_ip.all_cmdlog_hashes)


            if source_ip.http_requests >= self.min_http_requests:
                self.ips_with_http_requests.append(ip)
                
                pairs = [('uri', source_ip.all_http_uris), 
                         ('httplog', source_ip.all_httplogs)]
                
                flagged = False
                for regex_key, values in pairs:
                    if flagged:
                            break
                    
                    for compiled_regex in self.http_attack_regexes[regex_key]:
                        if flagged:
                            break
                        
                        for value in set(values):
                            match = compiled_regex.search(value)
                            if match:
                                flagged = True
                                break
                    
                if flagged:
                    self.ips_with_flagged_http_requests.append(ip)
                    attack_ids_by_type['httplog_hash'].update(source_ip.all_httplog_hashes)            
                

            
            for attack_id_type, attack_ids in attack_ids_by_type.items():
                for attack_id in attack_ids:

                    if attack_id in self.attacks:
                        self.attacks[attack_id].add_source_ip(source_ip)
                    elif ip not in self.attacks_by_src_ip:
                        self.attacks[attack_id] = Attack(attack_id, attack_id_type, source_ip)
                    
                    # A
                    if ip not in self.attacks_by_src_ip:
                        self.attacks_by_src_ip[ip] = self.attacks[attack_id]

        return self.attacks


    def merge_and_remove_attacks(self):
        attacks_before = len(self.attacks)
        self.remove_attacks_with_ips(self.remove_ips)
        print(f"({attacks_before}->{len(self.attacks)}) - Removed {attacks_before - len(self.attacks)} attacks with ips {self.remove_ips}")

        attacks_before = len(self.attacks)
        self.merge_attacks_by_shared_attrs()
        print(f"({attacks_before}->{len(self.attacks)}) - Merged {attacks_before - len(self.attacks)} attacks with shared attrs")

        attacks_before = len(self.attacks)
        self.merge_attacks_by_sig_regexes()
        print(f"({attacks_before}->{len(self.attacks)}) - Merged {attacks_before - len(self.attacks)} attacks with manual merge")

        #self.sort_attacks()
        return self.attacks


    def remove_attacks_with_ips(self, ips_to_remove):
        """Removes attacks that have any of the ips_to_remove"""

        for attack_id, attack in list(self.attacks.items()):

            for src_ip in attack.all_src_ips:
                if src_ip in ips_to_remove:
                    self.attacks.pop(attack_id)
                    print(f"Removed {attack_id} with src_ip {src_ip}")
                    break
    
    

    def merge_attacks_by_shared_attrs(self):
        """Merges attacks that have shared ips, command hashes or malware hashes"""
        start_time = time()

        merge_attempts = 0
        merge_successes = 0

        merged_attack_ids = set()

        attack_combos = combinations(self.attacks.items(), 2)
        for (attack_id, attack), (attack_id2, attack2) in attack_combos:            
            
            # Skip if already merged
            if {attack_id, attack_id2} & merged_attack_ids:
                continue

            for attr in self.merge_shared_attrs:
                merge_attempts += 1
                print(f"Attempting merge {merge_attempts}: {attack_id} <- {attack_id2} by {attr}", end='\r')

                shared_attr = getattr(attack, "uniq_" + attr) & getattr(attack2, "uniq_" + attr)
                if shared_attr:
                    merge_successes += 1
                    
                    attack += attack2
                    del self.attacks[attack_id2]
                    merged_attack_ids.update({attack_id2})
                    
                    print(f"Merged {attack_id} <- {attack_id2} by {attr}: {shared_attr}")                        
                    break
        
        if merge_attempts:
            print(f"\nMerged {merge_successes} attacks by out of {merge_attempts} attempts ({merge_successes/merge_attempts*100:.4f}%) ")
        
        print(f"Merge Attacks Time: {time() - start_time:.4f}s")

        # #TEST   
        # for attack1 in self.attacks.values():
        #     for attack2 in self.attacks.values():
        #         if attack1.attack_id == attack2.attack_id:
        #             continue
                
        #         for attr in self.merge_shared_attrs:
        #             shared_attr = getattr(attack1, "uniq_" + attr).intersection(getattr(attack2, "uniq_" + attr))
        #             if shared_attr:
        #                 print(f"Shared {attr}: {shared_attr}")
        #                 print(f"Attack1: {attack1.attack_id}")
        #                 print(f"Attack2: {attack2.attack_id}")
        #                 raise Exception("Shared attr after merge")


        return self.attacks
    
    def merge_attacks_by_sig_regexes(self):
        """Merges attacks that have the same signature regexes in their commands, malware or httplogs"""

        attack_sigs = {
            attack_attr: {compiled_regex: None for compiled_regex in compiled_regexes}
                for attack_attr, compiled_regexes in self.merge_sig_regexes.items()
        }

        value_to_regexes = {}

        for attack_id, attack in list(self.attacks.items()):
            for attack_attr, compiled_regexes in attack_sigs.items():
                for value in getattr(attack, attack_attr):
                    if value not in value_to_regexes:
                        value_to_regexes[value] = [compiled_regex for compiled_regex in compiled_regexes if compiled_regex.match(value)]

                    for compiled_regex in value_to_regexes[value]:
                        if not attack_sigs[attack_attr][compiled_regex]:
                            attack_sigs[attack_attr][compiled_regex] = attack
                        else:
                            attack_sigs[attack_attr][compiled_regex] += attack
                            if attack_id in self.attacks:
                                del self.attacks[attack_id]

                            print(f"Regex merged {attack.attack_id} into {attack_sigs[attack_attr][compiled_regex].attack_id} on {attack_attr}: {str(compiled_regex)}")
                        break

        return self.attacks
    
    # def merge_attacks_by_sig_regexes(self):
    #     """Merges attacks that have the same signature regexes in their commands, malware or httplogs"""

        
    #     attack_sigs = {
    #         attack_attr: {compiled_regex: None for compiled_regex in compiled_regexes}
    #             for attack_attr, compiled_regexes in self.merge_sig_regexes.items()
    #     }

    #     for attack_id, attack in list(self.attacks.items()):
    #         for attack_attr, compiled_regexes in attack_sigs.items():
    #             for compiled_regex in compiled_regexes:
    #                 for value in getattr(attack, attack_attr):
    #                     if compiled_regex.match(value):
    #                         if not attack_sigs[attack_attr][compiled_regex]:
    #                             attack_sigs[attack_attr][compiled_regex] = attack
    #                         else:
    #                             attack_sigs[attack_attr][compiled_regex] += attack                                
    #                             self.attacks.pop(attack_id)

    #                             print(f"Regex merged {attack.attack_id} into {attack_sigs[attack_attr][compiled_regex].attack_id} on {attack_attr}: {str(compiled_regex)}")
                            
    #                         break
        
        
    #     return self.attacks



    # def set_sort_attrs(self, attr_order):
    #     self.sort_attrs = attr_order


    def sort_by_attrs(self, attack, attr_order=None):
        attr_order = attr_order or self.sort_attrs
        return tuple(getattr(attack, attr) for attr in attr_order)
        #return tuple(getattr(attack, 'num_' + attr) for attr in attr_order)

    
    def sort_attacks(self, key=None, reverse=None):
        """Sorts attacks by key function, default is number of unique source ips"""
        key = key or self.sort_by_attrs
        reverse = reverse or self.sort_order.startswith("desc")

        self.attacks = OrderedDict((attack.attack_id, attack)
                                    for attack in sorted(self.attacks.values(), key=key, reverse=reverse))

        return self.attacks



    def print_stats(self):
        print("\nStats:")
        print(f" {len(self.ips_with_successful_logins)} IPs with >{self.min_successful_logins} successful logins")
        print(f" {len(self.ips_with_commands)} IPs with >{self.min_commands} commands")
        print(f" {len(self.ips_with_commands_only)} IPs with >{self.min_commands} commands and no malware")
        print(f" {len(self.ips_with_malware)} IPs with >{self.min_commands} commands and >{self.min_malware} malware")
        print(f" {len(self.ips_with_http_requests)} IPs with >{self.min_http_requests} http requests")
        print(f" {len(self.ips_with_flagged_http_requests)} IPs with flagged http requests")
        print(f"Total attacks: {len(self.attacks)}")

    
    def print_attacks(self):
        print("\nAttacks:")
        for n, attack in enumerate(self.attacks.values()):
            print(f"{n + 1}: {attack}")

        print(f"Total: {len(self.attacks)}")

    def print_exceptions(self):
        print("\nExceptions:")
        for n, (event, e) in enumerate(self.exceptions):
            print(f"{n + 1}: {event['eventid']} - {e}\n{event}")

        print(f"Total: {len(self.exceptions)}")

    
    def print_stats_and_attacks(self):
        self.print_exceptions()
        self.print_stats()
        self.print_attacks()
        

if __name__ == "__main__":
    pass
