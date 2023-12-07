
from analyzerbase import *
from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Executor


class AttackPostProcessor:
    def __init__(self, parser: CowrieParser, attacks_path=test_attacks_path, attacks={}, overwrite=True):        
        self.parser = parser
        self.attacks_path = Path(attacks_path)
        self.overwrite = overwrite
        self.attacks = attacks


    def set_attacks(self, attacks):
        self.attacks = attacks



class AttackLogOrganizer(AttackPostProcessor):


    @property
    def src_ip_attack_ids(self):
        """A dict of {src_ip: attack_id} for all src_ips in all attacks"""

        if not hasattr(self, "_src_ip_attack_ids"):
            self._src_ip_attack_ids = {}
            for attack_id, attack in self.attacks.items():
                self._src_ip_attack_ids.update({src_ip: attack_id for src_ip in attack.uniq_src_ips})
        
        return self._src_ip_attack_ids


    
    def organize(self, iterby='attacks', executor_cls=ProcessPoolExecutor, max_workers=10, chunksize=1):
        """
        Organizes logs into attack directories. Can iterate through attacks or logs and supports both 
        single-threaded, multithreaded and multiprocessed execution by setting the executor_cls.
        
        """
        

        if iterby == "attacks":
            iterable = self.attacks.values()
            organizer_fn = self._organize_attack
        elif iterby == "logs":
            iterable = self.parser.all_logs
            organizer_fn = self._organize_log
            # prepare all attack dirs before iterating through logs
            yield from self._prepare_all_attack_dirs()
        else:
            raise ValueError(f"iterby must be 'attacks' or 'logs' not {iterby}")

        if isinstance(executor_cls, Executor):
            yield from map(organizer_fn, iterable)
        else:
            with executor_cls(max_workers=max_workers) as executor:
                yield from executor.map(organizer_fn, iterable, chunksize=chunksize)



    # Using organize_by_iter_logs can faster on certain systems so both are here
    def _organize_attack(self, attack):


            
        print(f"Start organizing {attack}")
        attack_dir = self.attacks_path / attack.attack_id
        attack_malware_dir = (attack_dir / "malware")

        if attack_dir.exists() and not self.overwrite:
            return f"Attack {attack} already exists. Skipping"
            
        
        self._prepare_attack_dir(attack)
        

        for src_ip in attack.uniq_src_ips:
            source_ip_dir = attack_dir / src_ip
            source_ip_dir.mkdir(exist_ok=True, parents=True)

        for file in self.parser.all_logs:
            print(f"Organizing {file}")

            if file.name == "auth_random.json":
                combined_auth_random = {}
                    
                for src_ip in attack.uniq_src_ips:
                    src_ip_auth_random = self.parser.auth_random[src_ip]
                    combined_auth_random.update(src_ip_auth_random)

                    out_file = attack_dir / src_ip / file.name              
                    with out_file.open('w+') as f:
                        json.dump(src_ip_auth_random, f, indent=4)


                out_file = attack_dir / file.name  
                with out_file.open('w+') as f:
                    json.dump(combined_auth_random, f, indent=4)    
                

                continue

            
            outfiles = {src_ip: (attack_dir / src_ip / file.name) for src_ip in attack.uniq_src_ips}
            attack_log_subdir = attack_dir / file.parent.name
            outfiles["all"] =  attack_log_subdir / file.name 
           
            #capture any ip in attack only
            attack_src_ips_regex = re.compile(b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in attack.uniq_src_ips) + b")" )

            
            with file.open("rb") as infile:
                for line in infile:
                    match = attack_src_ips_regex.search(line)
                    if match:
                        # Decode match bytes to str
                        src_ip = match.group(1).decode()

                        with outfiles[src_ip].open("ab+") as f:
                            f.write(line)

                        if not attack_log_subdir.exists():
                            attack_log_subdir.mkdir(exist_ok=True, parents=True)

                        with outfiles["all"].open("ab+") as f:
                            f.write(line)
                            

            print("Done organizing", file)
        
        
        return f"Done organizing {attack}"


    def _prepare_attack_dir(self, attack):
        
        attack_dir = self.attacks_path / attack.attack_id
        attack_dir.mkdir(exist_ok=True, parents=True)

        with (attack_dir / "ips.txt").open("w+") as f:
            f.write("\n".join(attack.uniq_src_ips))


        if attack.commands:
            commands_file = attack_dir / "commands.txt"
            with commands_file.open("w+") as f:
                f.write("Raw Commands:\n")
                f.write("\n".join(attack.commands))
                f.write("\n\nSplit Commands:\n")
                f.write("\n".join(attack.split_commands))

        

        if attack.standardized_malware:
            attack_malware_dir = (attack_dir / "malware")
            attack_malware_dir.mkdir(exist_ok=True, parents=True)
            malware_downloads_dir = attack_malware_dir / "downloads"
            malware_downloads_dir.mkdir(exist_ok=True, parents=True)

            for standardized_hash, malware_list in attack.standardized_malware.items():
                standardized_malware_dir = malware_downloads_dir / standardized_hash
                standardized_malware_dir.mkdir(exist_ok=True, parents=True)

                standardized_malware_file = standardized_malware_dir / "standarized"

                with standardized_malware_file.open("wb+") as f:
                    f.write(malware_list[0].standarized_bytes)

                for malware in malware_list:
                    malware_outpath = standardized_malware_dir / malware.shasum
                    
                    with malware_outpath.open("wb+") as f:
                        f.write(malware.file_bytes)
        
        return attack_dir
        
    
    def _prepare_all_attack_dirs(self):
        src_ip_attack_ids = self.src_ip_attack_ids
        #capture any ip in attack only
        self.pattern = re.compile(b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in src_ip_attack_ids.keys()) + b")" )
        yield f"Prepared regex pattern: {self.pattern.pattern}"

        
        #malware_prepped = {}
        combined_auth_random_by_attack_id = defaultdict(dict)
        for src_ip, attack_id in src_ip_attack_ids.items():

            attack_dir = self.attacks_path / attack_id
            source_ip_dir = attack_dir / src_ip

            if attack_dir.exists() and not self.overwrite:
                yield f"Attack {src_ip}:{attack_id} already exists. Skipping"
                src_ip_attack_ids.pop(src_ip)
                continue
            

            if not source_ip_dir.exists():
                source_ip_dir.mkdir(exist_ok=True, parents=True)
                yield f"Created {source_ip_dir}"
            
            src_ip_auth_random = self.parser.auth_random[src_ip]
            combined_auth_random_by_attack_id[attack_id].update(src_ip_auth_random)            
            
            src_ip_auth_random_outfile = attack_dir / src_ip / "auth_random.json"
            with src_ip_auth_random_outfile.open('w+') as f:
                json.dump(src_ip_auth_random, f, indent=4)

            yield f"Created {src_ip_auth_random_outfile}"


        for attack_id, combined_auth_random in combined_auth_random_by_attack_id.items():
            attack_dir = self._prepare_attack_dir(self.attacks[attack_id])

            
            outfile = attack_dir / "auth_random.json"
            with outfile.open('w+') as f:
                json.dump(combined_auth_random, f, indent=4)
            
            yield f"Created {outfile}"
        
        
        yield f"Done preparing dirs for {len(set(src_ip_attack_ids.values()))} attacks"



    def _organize_log(self, file):
        print(f"Organizing {file}")
        
        with file.open("rb") as infile:
            for line in infile:
                match = self.pattern.search(line)
                if match:
                    # Decode match bytes to str
                    src_ip = match.group(1).decode()
                    attack_id = self.src_ip_attack_ids[src_ip]
                    attack_dir = self.attacks_path / attack_id

                    attack_log_subdir = attack_dir / file.parent.name
                    if not attack_log_subdir.exists():
                        attack_log_subdir.mkdir(exist_ok=True, parents=True)

                    with ( attack_dir / src_ip / file.name ).open("ab+") as f:
                        f.write(line)


                    with ( attack_log_subdir / file.name ).open("ab+") as f:
                        f.write(line)
                            
        
        return f"Done organizing {file}"
            




    



class AttackLogReader(AttackPostProcessor):
    log_types = ("cowrie", "firewall", "zeek", "web")


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


        return [log_path for src_ip in set(attack.all_src_ips) for log_path in self.log_paths[attack.attack_id].get(src_ip,()) 
                if (log_type == "all" or log_type in log_path.name) 
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