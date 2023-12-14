
from analyzerbase import *
from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Executor, as_completed



class AttackDirOrganizer:
    def __init__(self, parser: CowrieParser, attacks_path=test_attacks_path, attacks={}, overwrite=True):        
        self.parser = parser
        self.attacks_path = Path(attacks_path)
        self.overwrite = overwrite
        self.attacks = attacks


    def set_attacks(self, attacks):
        self.attacks = attacks


    @property
    def src_ip_attack_ids(self):
        """A dict of {src_ip: attack_id} for all src_ips in all attacks"""

        if not hasattr(self, "_src_ip_attack_ids"):
            self._src_ip_attack_ids = {}
            for attack_id, attack in self.attacks.items():
                self._src_ip_attack_ids.update({src_ip: attack_id for src_ip in attack.uniq_src_ips})
        
        return self._src_ip_attack_ids


    
    def organize(self, 
                 iterby='logs', 
                 executor_cls=ProcessPoolExecutor, 
                 max_workers=None, 
                 chunksize=1, 
                 yield_order="as_completed"):
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

        # Single-threaded execution if executor_cls is not an Executor
        if executor_cls not in (ThreadPoolExecutor, ProcessPoolExecutor, Executor):
            yield from map(organizer_fn, iterable)

    
        else:
            # Otherwise use executor_cls to execute organizer_fn on iterable and yield results in yield_order
            with executor_cls(max_workers=max_workers) as executor:

                if yield_order == "as_completed":
                    futures = {executor.submit(organizer_fn, item): item for item in iterable}
                    for future in as_completed(futures):
                        yield future.result()
                
                elif yield_order == "as_submitted":
                    yield from executor.map(organizer_fn, iterable, chunksize=chunksize)    


                
    
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
            #print(f"Organizing {file} for {attack}")

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
                            

            #print(f"Done organizing {file} for {attack}")
        
        
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
            




    



