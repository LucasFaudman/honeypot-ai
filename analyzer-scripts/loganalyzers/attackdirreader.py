from analyzerbase import *
from .logparser import CowrieParser


class AttackDirReader:
    """Reads and counts logs from attack directory"""

    log_types = ("cowrie", "firewall", "zeek", "web")

    def __init__(self, parser: CowrieParser, attacks_path=test_attacks_path, attacks={}, overwrite=True):        
        self.parser = parser
        self.attacks_path = Path(attacks_path)
        self.overwrite = overwrite
        self.attacks = attacks


    def set_attacks(self, attacks):
        self.attacks = attacks


    def update_all_log_paths_and_counts(self):
        self.update_all_log_paths()
        self.update_all_log_counts()

    def update_all_log_paths(self):
        self.log_paths = defaultdict(lambda: defaultdict(list))
        for attack_id, attack in self.attacks.items():
            self.update_attack_log_paths(attack)

    def update_all_log_counts(self):
        for attack_id, attack in self.attacks.items():
            self.update_attack_log_counts(attack)


    def update_attack_log_paths(self, attack):
        attack_id = attack.attack_id
        attack_dir = self.attacks_path / attack_id
        for path in attack_dir.rglob("*"):
            if path.is_file() and "malware" not in path.parts:
                self.log_paths[attack_id][path.parent.name].append(path)
                

                if path.parent.name in self.log_types:
                   self.log_paths[attack_id]["all"].append(path)
                else:
                   ip = path.parent.name
                   self.log_paths[attack_id][ip].append(path)
        
        
        attack.log_paths = self.log_paths[attack_id]
        return self.log_paths
    

    def get_attack_log_paths(self, attack, ip="all", log_type="all", ext="all"):


        return [log_path for log_path in self.log_paths[attack.attack_id].get(ip, ()) 
                if (log_type == "all" or log_type in log_path.parent.name + log_path.name) 
                and (ext == "all" or log_path.suffix == ext)
                ]
    


    def get_attack_log_names(self, attack, ip="all", log_type="all", ext="all"):
        return [log_path.name for log_path in self.get_attack_log_paths(attack, ip, log_type, ext)]


    def update_attack_log_counts(self, attack, ips="all", log_filter="all"):
        if log_filter == "all":
            log_filters = ["cowrie.log", "cowrie.json", "web.json", "dshield.log", "zeek.log"]
        else:
            log_filters = (log_filter,)

        if ips == "all":
            ips = ["all",] + [src_ip.ip for src_ip in attack.source_ips]
        elif isinstance(ips, str):
            ips = [ips,]
        else:
            ips = ips

        log_counts = defaultdict(dict)

        for ip in ips:
            for log_filter in log_filters:
                log_type, ext = log_filter.rsplit(".", 1)
                ext = "." + ext
                
                log_counts[ip][log_filter] = {}
                log_counts[ip][log_filter]["files"] = 0
                log_counts[ip][log_filter]["lines"] = 0
                #for log_path in attack.get_log_paths(ip, log_type, ext): 
                for log_path in self.get_attack_log_paths(attack, ip, log_type, ext): 
                    log_counts[ip][log_filter]["files"] += 1

                    with log_path.open("rb") as f:
                        log_counts[ip][log_filter][log_path.name] = len(f.readlines())#sum(1 for line in f)
                        log_counts[ip][log_filter]["lines"] += log_counts[ip][log_filter][log_path.name]
                    

                if log_counts[ip][log_filter]["files"] == 0:
                    del log_counts[ip][log_filter]

            found_log_filters = list(log_counts[ip].keys())
            log_counts[ip]["lines"] = sum(log_counts[ip][log_filter]["lines"] for log_filter in found_log_filters)
            log_counts[ip]["files"] = sum(log_counts[ip][log_filter]["files"] for log_filter in found_log_filters)
        
        attack._log_counts = log_counts
        return log_counts
    



    def get_attack_log_lines(self, attack, ip, log_filter, line_filter=None, n_lines=None):
        """Attack Postprocessor function for reading logs from attack directory"""

        log_type, ext = log_filter.rsplit(".", 1)
        ext = "." + ext
        

        log_paths = attack.get_log_paths(ip, log_type, ext)
        if not log_paths:
            return f"No {log_filter} logs found"


        match_lines = []
        for log_path in log_paths:
            with log_path.open("rb") as f:
                    
                for line in f:
                    if n_lines and n_lines > 0 and len(match_lines) >= n_lines:
                        break
                    
                    if line_filter is None or line_filter in line.decode():
                        match_lines.append(line)

            # Break loop to prefent reading more files than necessary            
            if n_lines and n_lines > 0 and len(match_lines) >= n_lines:
                break
                        

        return b"".join(match_lines).decode()