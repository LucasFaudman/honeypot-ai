
from analyzerbase import *
from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor





class AttackLogOrganizer(CowrieParser):
    
    def set_attacks(self, attacks):
        self.attacks = attacks



    @property
    def src_ip_attack_ids(self):
        if not hasattr(self, "_src_ip_attack_ids"):
            self._src_ip_attack_ids = {}
            for attack_id, attack in self.attacks.items():
                self._src_ip_attack_ids.update({src_ip: attack_id for src_ip in attack.uniq_src_ips})
        
        return self._src_ip_attack_ids


    
    def organize(self):
        """
        test_organize_by_iter_attacks_multiprocess  Elapsed Time:11.957556009292603
        test_organize_by_iter_logs_multiprocess     Elapsed Time:12.045604705810547
        test_organize_by_iter_attacks_multithreaded Elapsed Time:14.502341032028198
        test_organize_by_iter_logs_multithreaded    Elapsed Time:15.098825931549072
        test_organize_by_iter_attacks               Elapsed Time:16.647027015686035
        test_organize_by_iter_logs                  Elapsed Time:18.170916080474854
        """
        
        #default is organize_by_iter_attacks_multiprocess
        yield from self.organize_by_iter_attacks_multiprocess()



    def organize_by_iter_logs(self):
        yield from self._prepare_attack_dirs()
        yield from (self._split_log_into_attack_dir(file) for file in self.all_logs)
        

    def _organize_by_iter_logs_multi(self, executor_cls, max_workers=10, chunksize=1):
        yield from self._prepare_attack_dirs()

        with executor_cls(max_workers=max_workers) as executor:
            yield from executor.map(self._split_log_into_attack_dir, self.all_logs, chunksize=chunksize)

    
    def organize_by_iter_logs_multithreaded(self, max_workers=10, chunksize=1):
        yield from self._organize_by_iter_logs_multi(ThreadPoolExecutor, max_workers, chunksize)

        # yield from self._prepare_attack_dirs()
        # with ThreadPoolExecutor(max_workers=max_workers) as executor:
        #     yield from executor.map(self._split_log_into_attack_dir, self.all_logs, chunksize=chunksize)


    def organize_by_iter_logs_multiprocess(self, max_workers=10, chunksize=1):
        yield from self._organize_by_iter_logs_multi(ProcessPoolExecutor, max_workers, chunksize)

        # yield from self._prepare_attack_dirs()
        # with ProcessPoolExecutor(max_workers=max_workers) as executor:
        #     yield from executor.map(self._split_log_into_attack_dir, self.all_logs, chunksize=chunksize)


    def organize_by_iter_attacks(self):
        yield from (self._organize_by_iter_attacks(attack) for attack in self.attacks.values())
            

    def organize_by_iter_attacks_multithreaded(self, max_workers=10, chunksize=1):

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            yield from executor.map(self._organize_by_iter_attacks, self.attacks.values(), chunksize=chunksize)


    def organize_by_iter_attacks_multiprocess(self, max_workers=10, chunksize=1):

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            yield from executor.map(self._organize_by_iter_attacks, self.attacks.values(), chunksize=chunksize)


    
    
    def _prepare_attack_dirs(self):
        src_ip_attack_ids = self.src_ip_attack_ids
        #capture any ip in attack only
        self.pattern = re.compile(b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in src_ip_attack_ids.keys()) + b")" )
        #self.pattern = re.compile(fr'\b(?:{"|".join(map(re.escape, src_ip_attack_ids.keys()))})\b')
        yield f"Prepared regex pattern: {self.pattern.pattern}"

        combined_auth_random_by_attack_id = defaultdict(dict)
        for src_ip, attack_id in src_ip_attack_ids.items():

            attack_dir = self.attacks_path / attack_id
            source_ip_dir = attack_dir / src_ip

            if attack_dir.exists() and not self.overwrite:
                yield f"Attack {src_ip}:{attack_id} already exists. Skipping"
                src_ip_attack_ids.pop(src_ip)
                continue
    
            elif not source_ip_dir.exists():
                source_ip_dir.mkdir(exist_ok=True, parents=True)
                yield f"Created {source_ip_dir}"
            
            src_ip_auth_random = self.auth_random[src_ip]
            combined_auth_random_by_attack_id[attack_id].update(src_ip_auth_random)            
            
            src_ip_auth_random_outfile = attack_dir / src_ip / "auth_random.json"
            with src_ip_auth_random_outfile.open('w+') as f:
                json.dump(src_ip_auth_random, f, indent=4)

            yield f"Created {src_ip_auth_random_outfile}"


        for attack_id, combined_auth_random in combined_auth_random_by_attack_id.items():
            attack_dir = self.attacks_path / attack_id
            attack_dir.mkdir(exist_ok=True, parents=True)

            outfile = attack_dir / "auth_random.json"
            with outfile.open('w+') as f:
                json.dump(combined_auth_random, f, indent=4)
            
            yield f"Created {outfile}"
        
        
        yield rprint(f"Done preparing dirs for {len(set(src_ip_attack_ids.values()))} attacks")



    def _split_log_into_attack_dir(self, file):
        print(f"Organizing {file}")
        
        src_ip_attack_ids = self.src_ip_attack_ids    
           

        with file.open("rb") as infile:
            for line in infile:
                match = self.pattern.search(line)
                if match:
                    # Decode match bytes to str
                    src_ip = match.group(1).decode()
                    attack_id = src_ip_attack_ids[src_ip]
                    attack_dir = self.attacks_path / attack_id

                    with ( attack_dir / src_ip / file.name ).open("ab+") as f:
                        f.write(line)
                        #print(f"Writing to {attack_dir / src_ip / file.name}")

                    with ( attack_dir / file.name ).open("ab+") as f:
                        f.write(line)
                            
        
        return rprint(f"Done organizing {file}")
            


    # Using organize_by_iter_logs can faster on certain systems so both are here
    def _organize_by_iter_attacks(self, attack):
        print(f"Start organizing {attack}")
        attack_dir = self.attacks_path / attack.attack_id
        
        if attack_dir.exists() and not self.overwrite:
            return rprint(f"Attack {attack} already exists. Skipping")
            
        
        attack_dir.mkdir(exist_ok=True, parents=True)
        uniq_src_ips = attack.uniq_src_ips
        

        #capture any ip in attack only
        uniq_src_ips_regex = re.compile(b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in uniq_src_ips) + b")" )
        

        for src_ip in uniq_src_ips:
            source_ip_dir = attack_dir / src_ip
            source_ip_dir.mkdir(exist_ok=True, parents=True)

        for file in self.all_logs:
            print(f"Organizing {file}")

            if file.name == "auth_random.json":
                combined_auth_random = {}
                    
                for src_ip in uniq_src_ips:
                    src_ip_auth_random = self.auth_random[src_ip]
                    combined_auth_random.update(src_ip_auth_random)

                    out_file = attack_dir / src_ip / file.name
                    with out_file.open('w+') as f:
                        json.dump(src_ip_auth_random, f, indent=4)


                out_file = attack_dir / file.name    
                with out_file.open('w+') as f:
                    json.dump(combined_auth_random, f, indent=4)    
                

                continue

            
            outfiles = {src_ip: (attack_dir / src_ip / file.name) for src_ip in uniq_src_ips}
            outfiles["all"] =  attack_dir / file.name
            
           
            pattern = uniq_src_ips_regex
            with file.open("rb") as infile:
                for line in infile:
                    match = pattern.search(line)
                    if match:
                        # Decode match bytes to str
                        src_ip = match.group(1).decode()

                        with outfiles[src_ip].open("ab+") as f:
                            f.write(line)

                        with outfiles["all"].open("ab+") as f:
                            f.write(line)
                            

            print("Done organizing", file)
        
        
        return rprint(f"Done organizing {attack}")

    



class AttackLogReader(CowrieParser):

    def set_attacks(self, attacks):
        self.attacks = attacks

    def update_all_log_paths_and_counts(self):
        self.update_all_log_paths()
        self.update_all_log_counts()

    def update_all_log_paths(self):
        self.log_paths = defaultdict(lambda: defaultdict(list))
        for attack_id, attack in self.attacks.items():
            self.update_attack_log_paths(attack)


    def update_attack_log_paths(self, attack):
        attack_id = attack.attack_id
        attack_dir = self.attacks_path / attack_id
        for path in attack_dir.rglob("*"):
            if path.is_file():
                if path.parent.name == attack_id:
                    self.log_paths[attack_id]["all"].append(path)
                else:
                    ip = path.parent.name
                    self.log_paths[attack_id][ip].append(path)
            

        attack.update_log_paths(self.log_paths[attack_id])
        return self.log_paths
    

    # def get_log_paths(self, attack, ip="all", log_type="all", ext="all"):
    #     return [log_path for src_ip in set(attack.all_src_ips) for log_path in self.log_paths.get(src_ip,()) 
    #             if (log_type == "all" or log_type in log_path.name) 
    #             and (ext == "all" or log_path.suffix == ext)
    #             ]
    

    # def get_log_names(self, attack, ip="all", log_type="all", ext="all"):
    #     return [log_path.name for log_path in self.get_log_paths(attack, ip, log_type, ext)]


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
                for log_path in attack.get_log_paths(ip, log_type, ext): 
                #for log_path in self.get_log_paths(attack, ip, log_type, ext): 
                    log_counts[ip][log_filter]["files"] += 1

                    with log_path.open("rb") as f:
                        log_counts[ip][log_filter][log_path.name] = sum(1 for line in f)
                        log_counts[ip][log_filter]["lines"] += log_counts[ip][log_filter][log_path.name]
                    

                if log_counts[ip][log_filter]["files"] == 0:
                    del log_counts[ip][log_filter]

            found_log_filters = list(log_counts[ip].keys())
            log_counts[ip]["lines"] = sum(log_counts[ip][log_filter]["lines"] for log_filter in found_log_filters)
            log_counts[ip]["files"] = sum(log_counts[ip][log_filter]["files"] for log_filter in found_log_filters)
        
        attack._log_counts = log_counts
        return log_counts
    

    def update_all_log_counts(self):
        for attack_id, attack in self.attacks.items():
            self.update_attack_log_counts(attack)

    

    def get_attack_log_lines(self, attack, ip, log_filter, line_filter=None, n_lines=None):
        log_type, ext = log_filter.rsplit(".", 1)
        ext = "." + ext
        

        log_paths = attack.get_log_paths(ip, log_type, ext)
        if not log_paths:
            return f"No {log_filter} logs found"


        # if len(log_paths) == 1:
        #     with log_paths[0].open("rb") as f:
        #         lines = [line for line in f if line_filter is None or line_filter in line.decode()]
        #         if n_lines and n_lines > len(lines):
        #             n_lines = None
                
        #         return (b"".join(lines[:n_lines])).decode()
        
        match_lines = []
        for log_path in log_paths:
            with log_path.open("rb") as f:
                #file_bytes = f.read()
                    
                for line in f:
                    if n_lines and n_lines > 0 and len(match_lines) >= n_lines:
                        break
                    
                    if line_filter is None or line_filter in line.decode():
                        match_lines.append(line)

            # Break loop to prefent reading more files than necessary            
            if n_lines and n_lines > 0 and len(match_lines) >= n_lines:
                break
                        

        return b"\n".join(match_lines).decode()