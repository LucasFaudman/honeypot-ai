
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
                    src_ip_auth_random = self.parser.auth_random.get(src_ip, {})
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
           
            #capture any ip in attack. Final re is in form: r'(1\.2\.3\.4|5\.6\.7\.8|9\.10\.11\.12)'
            attack_src_ips_regex = re.compile(b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in attack.uniq_src_ips) + b")" )

            
            headers = []
            headers_written = {}
            with file.open("rb") as infile:
                for line in infile:
                    files_to_write = OrderedSet(())
                    

                    if file.parent.name == "zeek" and line.startswith(b"#"):
                        if line.startswith(b"#separator"):
                            headers = []
                            headers_written = {}

                        headers.append(line)


                    if match := attack_src_ips_regex.search(line):
                        # Decode match bytes to str
                        src_ip = match.group(1).decode()

                        files_to_write.append(outfiles[src_ip])
                        files_to_write.append(outfiles["all"])


                    self._write_line_to_files(files_to_write, line, headers, headers_written)

        
        
        return f"Done organizing {attack}"


    def _prepare_attack_dir(self, attack):
        
        attack_dir = self.attacks_path / attack.attack_id
        attack_dir.mkdir(exist_ok=True, parents=True)

        with (attack_dir / "ips.txt").open("w+") as f:
             f.write("\n".join(attack.uniq_src_ips))


        
        commands_summary = ""
        malware_summary = ""
        http_summary = ""
        

        if attack.commands:
            commands_file = attack_dir / "commands.txt"
            with commands_file.open("w+") as f:
                commands_summary += "\nRaw Commands:\n"
                commands_summary += "\n".join(attack.commands)
                commands_summary += "\n\nSplit Commands:\n"
                commands_summary += "\n".join(attack.split_commands)
                f.write(commands_summary)
            
    
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

                malware_summary += f"{standardized_hash}:\n"
                for malware in malware_list:
                    malware_summary += f"\t- {malware}\n"
                    malware_outpath = standardized_malware_dir / malware.shasum
                    
                    with malware_outpath.open("wb+") as f:
                        f.write(malware.file_bytes)
        

        if attack.http_requests:
            http_requests_file = attack_dir / "http_requests.txt"
            with http_requests_file.open("w+") as f:
                http_summary += "\nHTTP Requests:\n"
                http_summary += "\n\n".join(attack.http_requests)
                f.write(http_summary)

        summary_file = attack_dir / "summary.txt"
        with summary_file.open("w+") as f:
            f.write(f"Attack Summary:\n{attack}\n")
            f.write(commands_summary + "\n\n")
            f.write(malware_summary + "\n\n")
            f.write(http_summary + "\n\n")
            f.write("SourceIPs:\n" + "\n".join(str(source_ip) for source_ip in attack.source_ips))
            f.write("\n\nSessions:\n" + "\n".join(str(session) for session in attack.sessions))


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
            
            src_ip_auth_random = self.parser.auth_random.get(src_ip, {})
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
            src_ips_in_file = OrderedSet(())

            headers = []
            headers_written = {}
            for line in infile:
                files_to_write = OrderedSet(())

                if file.parent.name == "zeek" and line.startswith(b"#"):
                    if line.startswith(b"#separator"):
                        headers = []
                        headers_written = {}

                    headers.append(line)
                    #files_to_write.union(self._get_paths_from_src_ips(src_ips_in_file, file))

                
                if match := self.pattern.search(line):
                    # Decode match bytes to str
                    src_ip = match.group(1).decode()
                    src_ips_in_file.add(src_ip)

                    attack_id = self.src_ip_attack_ids[src_ip]
                    attack_dir = self.attacks_path / attack_id


                    files_to_write.add(attack_dir / src_ip / file.name)
                    files_to_write.add(attack_dir / file.parent.name / file.name)
                    

                self._write_line_to_files(files_to_write, line, headers, headers_written)

                
        
        return f"Done organizing {file}"
            

    def _write_line_to_files(self, files_to_write, line, headers, headers_written):
        for file_to_write in files_to_write:
            if not file_to_write.parent.exists():
                file_to_write.parent.mkdir(exist_ok=True, parents=True)
            
            with file_to_write.open("ab+") as f:

                if headers and not headers_written.get(file_to_write):
                    f.write(b"".join(headers))
                    headers_written[file_to_write] = True

                f.write(line)


                
            
            



    



