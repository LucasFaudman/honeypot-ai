from analyzerbase import *
from .logparser import CowrieParser
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed


class AttackDirOrganizer:
    def __init__(self,
                 parser: CowrieParser,
                 attacks_path=Path("./attacks"),
                 attacks={},
                 src_ip_subdirs=False,
                 overwrite=True):

        self.parser = parser
        self.attacks_path = Path(attacks_path)
        self.attacks = attacks
        self.src_ip_subdirs = src_ip_subdirs
        self.overwrite = overwrite

    def set_attacks(self, attacks):
        self.attacks = attacks

    @property
    def src_ip_attack_ids(self):
        """A dict of {src_ip: attack_id} for all src_ips in all attacks"""

        if not hasattr(self, "_src_ip_attack_ids"):
            self._src_ip_attack_ids = {}
            for attack_id, attack in self.attacks.items():
                self._src_ip_attack_ids.update(
                    {src_ip: attack_id for src_ip in attack.uniq_src_ips})

        return self._src_ip_attack_ids

    def organize(self,
                 iterby='logs',
                 concurrency_type="processes",
                 max_workers=None,
                 chunksize=1,
                 yield_order="as_completed"):
        """
        Organizes logs into attack directories. Can iterate through attacks or logs and supports both 
        single-threaded, multithreaded and multiprocessed execution by setting the concurrency_type.

        """

        if iterby == "attacks":
            iterable = self.attacks.values()
            organizer_fn = self._organize_attack
        elif iterby == "logs":
            iterable = self.parser.all_log_filepaths()
            organizer_fn = self._organize_log
            # prepare all attack dirs before iterating through logs
            yield from self._prepare_all_attack_dirs()
        else:
            raise ValueError(
                f"iterby must be 'attacks' or 'logs' not {iterby}")

        executor_cls = None
        if "process" in concurrency_type.lower():
            executor_cls = ProcessPoolExecutor
        elif "thread" in concurrency_type.lower():
            executor_cls = ThreadPoolExecutor

        CachedPropertyObject.start_caching_all(*self.attacks.values())
        CachedPropertyObject.freeze_all(*self.attacks.values())

        if executor_cls:
            # Init executor_cls in context manager to execute organizer_fn on iterable and yield results in yield_order
            with executor_cls(max_workers=max_workers) as executor:
                if yield_order == "as_completed":
                    # type: ignore
                    for future in as_completed(executor.submit(organizer_fn, item) for item in iterable):
                        yield future.result()

                elif yield_order == "as_submitted":
                    yield from executor.map(organizer_fn, iterable, chunksize=chunksize)

                # Wait for all futures to complete
                executor.shutdown(wait=True)
        else:
            # Single-threaded execution if executor_cls is not an Executor
            yield from map(organizer_fn, iterable)

        CachedPropertyObject.stop_caching_all(*self.attacks.values())
        CachedPropertyObject.unfreeze_all(*self.attacks.values())
        CachedPropertyObject.empty_all(*self.attacks.values())

        yield f"Done organizing attack directories"

    def _prepare_attack_dir(self, attack):
        attack_dir = self.attacks_path / attack.attack_id
        attack_dir.mkdir(exist_ok=True, parents=True)

        with (attack_dir / "ips.txt").open("w+") as f:
            f.write("\n".join(attack.uniq_src_ips))

        commands_summary = ""
        if attack.commands:
            commands_file = attack_dir / "commands.txt"
            with commands_file.open("w+") as f:
                commands_summary += "\nRaw Commands:\n"
                commands_summary += "\n".join(attack.commands)
                commands_summary += "\n\nSplit Commands:\n"
                commands_summary += "\n".join(attack.split_commands)
                f.write(commands_summary)

        malware_summary = ""
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

                    malware_outpath = standardized_malware_dir / malware.id

                    with malware_outpath.open("wb+") as f:
                        f.write(malware.file_bytes)

        http_summary = ""
        if attack.http_requests:
            http_requests_file = attack_dir / "http_requests.txt"
            with http_requests_file.open("w+") as f:
                http_summary += "\nHTTP Requests:\n"
                http_summary += "\n\n".join(attack.http_requests)
                f.write(http_summary)

        # Write summary file
        summary_file = attack_dir / "summary.txt"
        with summary_file.open("w+") as f:
            f.write(f"Attack Summary:\n{attack}\n")
            f.write(commands_summary + "\n\n")
            f.write(malware_summary + "\n\n")
            f.write(http_summary + "\n\n")
            f.write("SourceIPs:\n" + "\n".join(str(source_ip)
                    for source_ip in attack.source_ips))
            f.write("\n\nSessions:\n" + "\n".join(str(session)
                    for session in attack.sessions))

        return attack_dir

    def _prepare_all_attack_dirs(self):
        src_ip_attack_ids = self.src_ip_attack_ids
        # capture any ip in attack only
        self.pattern = re.compile(
            b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in src_ip_attack_ids.keys()) + b")")
        yield f"Prepared regex pattern: {self.pattern.pattern}"

        combined_auth_random_by_attack_id = defaultdict(dict)
        for src_ip, attack_id in src_ip_attack_ids.items():
            attack_dir = self.attacks_path / attack_id

            if attack_dir.exists() and not self.overwrite:
                yield f"Attack {src_ip}:{attack_id} already exists. Skipping"
                src_ip_attack_ids.pop(src_ip)
                continue

            # Update combined_auth_random either way
            src_ip_auth_random = self.parser.auth_random.get(src_ip, {})
            combined_auth_random_by_attack_id[attack_id][src_ip] = src_ip_auth_random

            # Don't create subdir for each source ip if src_ip_subdirs is False
            if not self.src_ip_subdirs:
                continue

            # Create subdir for each source ip and add its auth_random to subdir
            source_ip_dir = attack_dir / src_ip
            if not source_ip_dir.exists():
                source_ip_dir.mkdir(exist_ok=True, parents=True)
                yield f"Created {source_ip_dir}"

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

    def _write_line_to_files(self, files_to_write, line, headers, headers_written):
        for file_to_write in files_to_write:
            if not file_to_write.parent.exists():
                file_to_write.parent.mkdir(exist_ok=True, parents=True)

            with file_to_write.open("ab+") as f:

                if headers and not headers_written.get(file_to_write):
                    f.write(b"".join(headers))
                    headers_written[file_to_write] = True

                f.write(line)

    def _organize_log(self, file):
        print(f"Started organizing {file}")

        with file.open("rb") as infile:
            headers = []
            headers_written = {}
            for line in infile:
                files_to_write = OrderedSet(())

                if file.parent.name == "zeek" and line.startswith(b"#"):
                    if line.startswith(b"#separator"):
                        headers = []
                        headers_written = {}

                    headers.append(line)

                if match := self.pattern.search(line):
                    # Decode match bytes to str
                    src_ip = match.group(1).decode()

                    attack_id = self.src_ip_attack_ids[src_ip]
                    attack_dir = self.attacks_path / attack_id

                    # Write to src_ip subdir if src_ip_subdirs is True
                    if self.src_ip_subdirs:
                        files_to_write.add(attack_dir / src_ip / file.name)

                    # Write to attack subdir always
                    files_to_write.add(
                        attack_dir / file.parent.name / file.name)

                self._write_line_to_files(
                    files_to_write, line, headers, headers_written)

        return f"Done organizing {file}"

    def _organize_attack(self, attack):
        print(f"Started organizing {attack}")
        attack_dir = self.attacks_path / attack.attack_id

        if attack_dir.exists() and not self.overwrite:
            return f"Attack {attack} already exists. Skipping"

        self._prepare_attack_dir(attack)

        for file in self.parser.all_log_filepaths():
            if file.name == "auth_random.json":
                combined_auth_random = {}

                for src_ip in attack.uniq_src_ips:
                    src_ip_auth_random = self.parser.auth_random.get(
                        src_ip, {})
                    combined_auth_random.update(src_ip_auth_random)

                    if self.src_ip_subdirs:
                        source_ip_dir = attack_dir / src_ip
                        source_ip_dir.mkdir(exist_ok=True, parents=True)
                        out_file = attack_dir / src_ip / file.name
                        with out_file.open('w+') as f:
                            json.dump(src_ip_auth_random, f, indent=4)

                out_file = attack_dir / file.name
                with out_file.open('w+') as f:
                    json.dump(combined_auth_random, f, indent=4)

                continue

            if self.src_ip_subdirs:
                outfiles = {src_ip: (attack_dir / src_ip / file.name)
                            for src_ip in attack.uniq_src_ips}
            else:
                outfiles = {}
            attack_log_subdir = attack_dir / file.parent.name
            outfiles["all"] = attack_log_subdir / file.name

            # capture any ip in attack. Final re is in form: r'(1\.2\.3\.4|5\.6\.7\.8|9\.10\.11\.12)'
            attack_src_ips_regex = re.compile(
                b"(" + rb"|".join(ip.encode().replace(b".", rb"\.") for ip in attack.uniq_src_ips) + b")")

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
                        files_to_write.append(outfiles["all"])
                        if self.src_ip_subdirs:
                            files_to_write.append(outfiles[src_ip])

                    self._write_line_to_files(
                        files_to_write, line, headers, headers_written)

        return f"Done organizing {attack}"
