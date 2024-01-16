from analyzerbase import *

from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor


class CowrieLogAnalyzer:
    """
    Analyzes cowrie logs to find attacks. Use a CowrieParser to parse the logs first into a list of dicts.
    Then use the process() method to create SourceIP and Session objects for the logs. 
    Then use the analyze() method to find attacks and merge them together by shared attributes including:
    src_ip, ssh_hassh, malware hashes, command hashes, ips/urls found in malware.
    Malware and command logs are standardized before being hashed and compared.
    """

    def __init__(self, 
                 parsers, 
                 remove_ips=MYIPS,
                 min_commands=0,
                 min_malware=0,
                 min_successful_logins=0,
                 min_http_requests=1,
                 http_flag_regexes={
                     "uri": [
                        r'(\||\$|\`|;|\-\-|\{|\}|\[|\]|\(|\)|<|>|\\|\^|\~|\!|\$?\{?IFS\}?|\.\/)',
                     ],

                     "httplog": [
                        #r'(\||\$|\`|;|\-\-|\{|\}|\[|\]|\(|\)|<|>|\\|\^|\*|\~|\!)',
                        r'(\||\$|\`|\{|\}|<|>|\\[^n]|\^|\!|\$?\{?IFS\}?|\.\/)',
                    ]
                 },
                 attack_sig_regexes=[
                    r">\??A@/ ?X'8ELFX",
                    r"cat /proc/mounts; /bin/busybox [\w\d]+",
                    r"cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+",
                    r"cd ~; chattr -ia .ssh; lockr -ia .ssh",
                 ],


                 ):

        self.parsers = parsers
        self.remove_ips = remove_ips
        self.min_commands = min_commands
        self.min_malware = min_malware
        self.min_successful_logins = min_successful_logins
        self.min_http_requests = min_http_requests


        self.http_flag_regexes = {
            key: list(map(re.compile, http_flag_regexes[key])) for key in http_flag_regexes
            }
        self.attack_sig_regexes = list(map(re.compile, attack_sig_regexes))

        self.source_ips = {}
        self.attacks = {}
        self.attacks_by_src_ip = {}

        self.exceptions = []

    def set_parsers(self, parsers):
        "Used to change parser after initialization when needed to load attacks for an attack dir"
        self.parsers = parsers


    def process_cowrie_event(self, event):
        if event["eventid"] == "cowrie.session.connect":
            self.source_ips[event["src_ip"]].add_session(event)

        elif event["eventid"].startswith("cowrie.client."):
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
            #self.source_ips[event["src_ip"]].process_session(event["session"])


    def process_zeek_event(self, event):
        if event["session"] not in self.source_ips[event["src_ip"]].sessions:
            self.source_ips[event["src_ip"]].add_session(event)

        self.source_ips[event["src_ip"]].sessions[event["session"]].add_zeek_event(event)


    def process(self):
        """Reads cowrie logs and creates SourceIP and Session objects"""

        for parser in self.parsers:
            for event in parser.logs():
                try:
                    if event["src_ip"] not in self.source_ips:
                        self.source_ips[event["src_ip"]
                                        ] = SourceIP(event["src_ip"])

                    if event["eventid"].startswith("cowrie"):
                        self.process_cowrie_event(event)

                    elif event["eventid"].startswith("zeek"):
                        self.process_zeek_event(event)

                except Exception as e:
                    self.exceptions.append((event, e))

        for source_ip in self.source_ips.values():
            source_ip.process_sessions()

        return self.source_ips

    def analyze(self):
        """Analyzes SourceIP and Session objects to find attacks"""

        self.ips_with_successful_logins = []
        self.ips_with_commands = []
        self.ips_with_malware = []
        self.ips_with_commands_only = []
        self.ips_with_http_requests = []
        self.ips_with_flagged_http_requests = []

        for ip, source_ip in self.source_ips.items():
            # attack_ids = []
            # attack_id_type = None
            attack_ids_by_type = defaultdict(SetReprOrderedSet)
            
            if source_ip.successful_logins > 0:
                self.ips_with_successful_logins.append(ip)

            if source_ip.commands > 0:
                self.ips_with_commands.append(ip)

                if source_ip.downloaded_malware + source_ip.uploaded_malware > 0:
                    self.ips_with_malware.append(ip)
                    attack_ids_by_type['malware_hash'].update(source_ip.all_malware_hashes)
                else:

                    self.ips_with_commands_only.append(ip)
                    attack_ids_by_type['cmdlog_hash'].update(source_ip.all_cmdlog_hashes)


            if source_ip.http_requests > 0:
                self.ips_with_http_requests.append(ip)
                flagged = False
                
                combined_urilog = ''.join(set(source_ip.all_http_uris))
                for compiled_regex in self.http_flag_regexes['uri']:

                    match = compiled_regex.search(combined_urilog)
                    if match:
                        flagged = True
                        break

                combined_httplog = ''.join(set(source_ip.all_httplogs)) if not flagged else ''
                for compiled_regex in self.http_flag_regexes['httplog']:
                    if flagged:
                        break

                    match = compiled_regex.search(combined_httplog)
                    if match:
                        flagged = True
                        

                if flagged:
                    self.ips_with_flagged_http_requests.append(ip)
                    attack_ids_by_type['httplog_hash'].update(source_ip.all_httplog_hashes)



            
            for attack_id_type, attack_ids in attack_ids_by_type.items():
                for attack_id in attack_ids:
                    if not attack_id or source_ip.ip in self.attacks_by_src_ip: 
                        continue
                    
                    # if source_ip.ip in self.attacks_by_src_ip:
                    #     continue
                    #     #self.attacks_by_src_ip[source_ip.ip].add_source_ip(source_ip)


                    elif attack_id in self.attacks:
                        self.attacks[attack_id].add_source_ip(source_ip)
                    
                    else:
                        self.attacks[attack_id] = Attack(attack_id, attack_id_type, source_ip)
                        self.attacks_by_src_ip[source_ip.ip] = self.attacks[attack_id]






        attacks_before = len(self.attacks)
        self.remove_attacks_with_ips(self.remove_ips)
        print(f"({attacks_before}->{len(self.attacks)}) - Removed {attacks_before - len(self.attacks)} attacks with ips {self.remove_ips}")

        attacks_before = len(self.attacks)
        self.merge_attacks_shared_ips_or_hashes()
        print(f"({attacks_before}->{len(self.attacks)}) - Merged {attacks_before - len(self.attacks)} attacks with shared ips or hashes")

        attacks_before = len(self.attacks)
        # Merge using attack signature regex patterns
        self.manual_merge()
        print(f"({attacks_before}->{len(self.attacks)}) - Merged {attacks_before - len(self.attacks)} attacks with manual merge")


        self.sort_attacks()
        self.print_stats()
        self.print_attacks()

        print("Done")

        return self.attacks

    def remove_attacks_with_ips(self, ips_to_remove):
        """Removes attacks that have any of the ips_to_remove"""

        for attack_id, attack in list(self.attacks.items()):

            for src_ip in attack.all_src_ips:
                if src_ip in ips_to_remove:
                    self.attacks.pop(attack_id)
                    print(f"Removed {attack_id} with src_ip {src_ip}")
                    break

    def sort_attacks(self, key=lambda attack: len(attack.uniq_src_ips), reverse=True):
        """Sorts attacks by key function, default is number of unique source ips"""

        attacks_sorted_by_key_fn = sorted(
            self.attacks.values(), key=key, reverse=reverse)
        self.attacks = OrderedDict((attack.attack_id, attack)
                                   for attack in attacks_sorted_by_key_fn)

        return self.attacks

    def manual_merge(self):
        """Manually merges attacks that have the same signature"""

        # attack_sigs = {
        #     re.compile(r">\??A@/ ?X'8ELFX"): None,
        #     re.compile(r"cat /proc/mounts; /bin/busybox [\w\d]+"): None,
        #     re.compile(r"cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+"): None,
        #     re.compile(r"cd ~; chattr -ia .ssh; lockr -ia .ssh"): None,
        # }
        attack_sigs = {compiled_regex: None for compiled_regex in self.attack_sig_regexes}


        for attack_id, attack in list(self.attacks.items()):
            for attack_sig in attack_sigs:
                if any(attack_sig.match(command) for command in attack.commands):
                    if not attack_sigs[attack_sig]:
                        attack_sigs[attack_sig] = attack
                    else:
                        print(
                            f"Manual merge {attack.attack_id} into {attack_sigs[attack_sig].attack_id} on {str(attack_sig)}")
                        attack_sigs[attack_sig] += attack
                        self.attacks.pop(attack_id)

        return self.attacks

    def merge_attacks_shared_ips_or_hashes(self):
        """Merges attacks that have shared ips, command hashes or malware hashes"""

        merge_on_attrs = ["src_ips", "malware", #"cmdlog_hashes",  "ssh_hasshs",
                          "cmdlog_ips", "cmdlog_urls", 
                          "malware_ips", "malware_urls",
                          ]

        pop_attacks = []
        tested_pairs = defaultdict(list)


        for attack_id, attack in list(self.attacks.items()):
            for attack_id2, attack2 in list(self.attacks.items()):
                if (attack_id == attack_id2
                    #or attack_id in tested_pairs[attack_id2]
                    or attack_id2 in tested_pairs[attack_id]
                    or attack_id in pop_attacks 
                    or attack_id2 in pop_attacks):
                    continue
                
                
                tested_pairs[attack_id].append(attack_id2)
                tested_pairs[attack_id2].append(attack_id)

                for attr in merge_on_attrs:
                    shared_attr = getattr(attack, "uniq_" + attr).intersection(getattr(attack2, "uniq_" + attr))
                    if shared_attr:
                        attack += attack2
                        pop_attacks.append(attack_id2)

                        print(
                            f"\nMerged {attack_id} <- {attack_id2} by {attr}: {shared_attr}")
                        
                        break
                    else:
                        print(f"Failed to merge {attack_id} <- {attack_id2} by {attr}", end='\r')

        for attack_id in pop_attacks:
            self.attacks.pop(attack_id)
        
        print('\nMerged', len(pop_attacks), 'attacks')
        return self.attacks

    def print_stats(self):
        print("Stats:")
        print(
            f"Number of IPs with successful logins: {len(self.ips_with_successful_logins)}")
        print(f"Number of IPs with commands: {len(self.ips_with_commands)}")
        print(
            f"Number of IPs with commands only: {len(self.ips_with_commands_only)}")
        print(f"Number of IPs with malware: {len(self.ips_with_malware)}")
        print(
            f"Number of IPs with http requests: {len(self.ips_with_http_requests)}")
        print(
            f"Number of IPs with flagged http requests: {len(self.ips_with_flagged_http_requests)}")
        print(f"Number of attacks: {len(self.attacks)}")

    def print_attacks(self, include_commands=False):

        print("Attacks:")
        for attack_id in self.attacks:
            print(self.attacks[attack_id])
            if include_commands:
                print("Commands:\n\t" +
                      "\n\t".join(self.attacks[attack_id].commands) + "\n")


if __name__ == "__main__":
    pass
