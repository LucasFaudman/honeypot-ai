from analyzerbase import *
from .markdownwriterbase import *
from .visualizer import CounterGrapher


class AttackMarkdownWriter(MarkdownWriterBase):
    """Markdown writer for Attack objects"""

    def prepare(self):
        attack = self.data_object
        self.md += h1(attack.answers.get("title",
                      f"Attack: {attack.attack_id}"))
        self.md_editors.append(self.add_attack_summary)
        self.md_editors.append(self.add_time_and_date)
        self.md_editors.append(self.add_relevant_logs)
        self.md_editors.append(self.add_ip_and_port_tables)
        self.md_editors.append(self.add_ssh_analysis)
        self.md_editors.append(self.add_command_and_malware_analysis)
        self.md_editors.append(self.add_vuln_analysis)
        self.md_editors.append(self.add_questions)

    def session_table(self, sessions):
        session_headers = ["Session ID", "IP", "Src Port",
                           "Dst Port", "Start Time", "End Time", "Duration"]
        session_data = [(session.session_id, session.src_ip, session.src_port, session.dst_port,
                         session.start_time, session.end_time, session.duration) for session in sessions]
        return table(session_headers, session_data, style_fn=code)

    def add_time_and_date(self, md, attack: Attack):
        first_session = attack.first_session
        last_session = attack.last_session

        td_md = ""
        td_md += f"First activity logged: {code(str(attack.start_time))}" + "\n"
        td_md += bullet(f"First session: {code(first_session.session_id)}")
        td_md += bullet(code(attack.first_session)) + "\n"

        td_md += f"Last activity logged: {code(str(attack.end_time))}" + "\n"
        td_md += bullet(f"Last session: {code(last_session.session_id)}")
        td_md += bullet(code(attack.last_session)) + "\n"

        td_md += self.session_table([first_session, last_session])

        td_md += "\n" + attack.answers.get("sessions_summary", "") + "\n"

        td_md += collapseable_section(
            self.session_table(attack.sessions), "All Sessions", 3)

        md += collapseable_section(td_md, "Time and Date of Activity", 1)
        return md

    def add_attack_summary(self, md, attack: Attack):
        counts = attack.counts
        log_counts = attack.log_counts
        log_types = attack.log_types
        log_names = attack.get_log_names("all")

        uniq_src_ips = list(attack.uniq_src_ips)
        uniq_src_ports = list(attack.uniq_src_ports)
        if len(uniq_src_ips) <= 15:
            src_ip_summary = md_join(uniq_src_ips, code, ", ")

        else:
            src_ip_summary = md_join(
                uniq_src_ips[:15], code, ", ") + f" (and {code(len(uniq_src_ips)-15)} more)"

        if len(counts['src_ports']) <= 15:
            src_port_summary = md_join(counts['src_ports'], code, ", ")
        else:
            src_port_summary = f" Min: {min(counts['src_ports'])}, Max: {max(counts['src_ports'])}"

        summary = [
            f"This attack was carried out by a {code(attack.num_source_ips)} unique source IP address(es): {src_ip_summary}",
            f"A total of {code(attack.num_sessions)} sessions were logged. {code(attack.num_login_sessions)} sessions were successful logins.",
            f"{code(sum(counts['login_pairs'].values()))} login attempts were made. {code(sum(counts['successful_login_pairs'].values()))} were successful.",
            f"{code(len(counts['login_pairs']))} unique username/password pairs were attempted. {code(len(counts['successful_login_pairs']))} were successful.",
            f"{code(len(counts['dst_ports']))} unique destination ports were targeted: {', '.join([code(port) for port in counts['dst_ports']])}",
            f"{code(len(counts['src_ports']))} unique source ports were used: {src_port_summary}",
            f"{code(attack.num_commands)} commands were input in total. {code(len(counts['cmdlog_ips']))} IP(s) and {code(len(counts['cmdlog_urls']))} URL(s) were found in the commands",
            f"{code(attack.num_malware)} unique malware samples were downloaded. {code(len(counts['malware_ips']))} IP(s) and {code(len(counts['malware_urls']))} URL(s) were found in the malware samples",
            f"This attacks was recorded in {code(len(log_types))} log types: " + md_join(
                log_types, code, ', '),
            f"A total of {code(log_counts['all']['_lines'])} log events were logged in {code(len(log_names))} log files: " + md_join(
                log_names, code, ', '),
        ]

        summary_long = [
            f"This attack was carried out by a {code(attack.num_source_ips)} unique {bold('source IP')} address(es):",
            attack.source_ips[:15]
            + ([f"(and {code(attack.num_uniq_src_ips-15)} more)"]
               if len(uniq_src_ips) > 15 else []),

            f"{code(attack.num_uniq_src_ports)} unique {bold('source ports')} were used:",
            [*[f'Src Port: {port} Used {count} times'
               for port, count in attack.counts["src_ports"].items()
               ]
             ]
            + ([f"(and {code(attack.num_uniq_src_ports-15)} more)"]
               if len(uniq_src_ips) > 15 else []),

            f"{code(attack.num_uniq_dst_ports)} unique {bold('destination ports')} were targeted:",
            [f'Dst Port: {code(port)} Used {code(count)} times'
             for port, count in attack.counts["dst_ports"].items()
             ],

            f"A total of {code(attack.num_sessions)} sessions were logged:",
            attack.sessions[:15]
            + ([f"(and {code(attack.num_sessions-15)} more)"]
               if attack.num_sessions > 15 else []),

            f"{code(attack.num_login_sessions)} were {bold('successful logins')}, ",
            f"{code(attack.num_sessions - attack.num_login_sessions)} were {bold('failed logins')}, ",
            f"{code(attack.num_command_sessions)} had commands, ",
            f"{code(attack.num_malware_sessions)} had malware.",

            f"{code(attack.num_login_pairs)} unique username/password pairs were attempted. {code(attack.num_successful_login_pairs)} were successful.",

            f"{code(attack.num_commands)} commands were input in total. "
            f"{code(attack.num_cmdlog_ips)} IP(s) and {code(attack.num_cmdlog_urls)} URL(s) were found in the commands",


            f"{code(attack.num_malware)} unique malware samples were downloaded. ",
            f"{code(attack.num_uniq_malware_ips)} unique IP(s) and {code(attack.num_uniq_malware_urls)} unique URL(s) were found in the malware samples",


            f"This attacks was recorded in {code(attack.num_log_types)} log types: ",
            log_types,
            f"A total of {code(log_counts['all']['_lines'])} log events were logged in {code(log_counts['all']['_files'])} log files: ",
            log_names,
        ]

        quick_summary = nested_list(summary, style_dict={1: code})
        md += collapseable_section(quick_summary, "Quick Stats", 2)

        md += attack.answers["summary"] + "\n"

        long_summary = nested_list(summary_long, style_dict={1: code})
        md += collapseable_section(long_summary, "Extended Summary", 3)

        return md

    def add_relevant_logs(self, md, attack: Attack):
        log_counts = attack.log_counts
        log_types = attack.log_types

        logs_md = h2("Log Stats")

        log_table_headers = ["Log Name", "Lines"]
        ip = 'all'
        log_table_data = [(log_type, log_counts[ip][log_type]["_lines"])
                          for log_type in log_types]
        logs_md += table(log_table_headers, log_table_data) + "\n"

        if "cowrie.log" in log_types:
            logs_md = self.add_cowrie_logs(
                logs_md, attack, ip="all", n_lines=50)

        if "zeek.log" in log_types:
            logs_md = self.add_zeek_logs(
                logs_md, attack, ip="all", n_lines=50)

        if "web.json" in log_types:
            logs_md = self.add_web_logs(
                logs_md, attack, ip="all", n_lines=50)

        if "dshield.log" in log_types:
            logs_md = self.add_dshield_logs(
                logs_md, attack, ip="all", n_lines=50)

        md += collapseable_section(logs_md, "Relevant Logs, File or Email", 1)
        return md

    def add_dshield_logs(self, md, attack: Attack, ip="all", n_lines=None):
        md += h2("DShield Logs")
        # TODO ADD Log Descriptions
        md += f"Total DShield logs: {code(attack.log_counts[ip]['dshield.log']['_lines'])}\n"
        md += h4(f"The {code(attack.num_sessions)} sessions in this attack were logged as connection in the following DShield firewall logs:")

        md += f"Here is a sample of the {'first ' + code(n_lines) if n_lines else 'log'} lines:\n"
        md += codeblock(attack.get_log_lines(log_filter="dshield.log",
                        n_lines=n_lines), "log")

        return md

    def add_web_logs(self, md, attack: Attack, ip="all", n_lines=None):
        md += h2("Web Logs")
        # TODO ADD Log Descriptions
        md += f"Total Web logs: {code(attack.log_counts[ip]['web.json']['_lines'])}\n"
        md += h4(f"The {code(attack.num_http_sessions)} sessions in this attack were logged as connection in the following Web logs:")
        md += f"Here is a sample of the {'first ' + code(n_lines) if n_lines else 'log'} lines:\n"
        md += codeblock(attack.get_log_lines(log_filter="web.json",
                        n_lines=n_lines), 'json')

        return md

    def add_zeek_logs(self, md, attack: Attack, ip="all", n_lines=None):
        md += h2("Zeek Logs")
        md += f"Total Zeek logs: {code(attack.log_counts[ip]['zeek.log']['_lines'])}\n"
        md += h4(f"The {code(attack.num_zeek_sessions)} Zeek sessions in this attack were logged in the following Zeek logs:")
        md += unordered_list(attack.zeek_log_types, style_fn=code)
        for zeek_log_type in attack.zeek_log_types:
            zeek_log_md = f"Here is a sample of the {'first ' + code(n_lines) if n_lines else 'log'} lines:\n"
            zeek_log_md += codeblock(attack.get_log_lines(
                log_filter=f"zeek.{zeek_log_type}", n_lines=n_lines), 'log')
            md += collapseable_section(zeek_log_md,
                                       f"Zeek {zeek_log_type} Logs", 3)

        return md

    def add_cowrie_logs(self, md, attack: Attack, ip="all", n_lines=None):
        first_command_session = attack.first_command_session

        for ext in ('.log', '.json'):
            md += h2(f"Cowrie {ext} Logs")
            # TODO ADD Log Descriptions
            md += f"Total Cowrie logs: {code(attack.log_counts[ip][f'cowrie{ext}']['_lines'])}\n"

            md += h4(
                f"First Session With Commands {first_command_session.session_id} Cowrie {ext} Logs")
            md += f"This sample shows the Cowrie {code(ext)} Logs for session_id {code(first_command_session.session_id)} the first session in this attack where the attacker exectuted commands in on the honeypot system."
            if n_lines and n_lines > 0:
                md += f"Here is a sample of the first {code(n_lines)} lines:\n"
            else:
                md += f"Here is the full log:\n"

            if ext == '.log':
                session_filter = f",{first_command_session.src_ip}"
                codeblock_lang = 'verilog'
            else:
                session_filter = first_command_session.session_id
                codeblock_lang = 'json'

            log_lines = attack.get_log_lines(
                log_filter=f"cowrie{ext}", line_filter=session_filter, n_lines=n_lines)
            codeblock_md = codeblock(log_lines, codeblock_lang)

            md += collapseable_section(
                codeblock_md, f"Cowrie {ext} Logs for {first_command_session.session_id}", 3)

        return md

    def add_ssh_analysis(self, md, attack: Attack):
        if not attack.ssh_sessions or not attack.telnet_sessions:
            return md

        n = 10

        pairs = {"Username": "usernames",
                 "Password": "passwords",
                 "Username/Password Pair": "login_pairs",
                 "Successful Username": "successful_usernames",
                 "Successful Password": "successful_passwords",
                 "Successful Username/Password Pair": "successful_login_pairs",
                 "SSH Version": "ssh_versions",
                 "SSH Hassh": "ssh_hasshs", }

        most_common_tables_md = ""
        graph_type = "pie"
        for title, counter_key in pairs.items():
            counter = attack.counts[counter_key]
            most_common_tables_md += most_common_table(title, counter, n)
            graph_file = self.filepath.parent / \
                f"graphs/{attack.attack_id}/{graph_type}-{counter_key}.png"
            if not graph_file.exists():
                graph_file.parent.mkdir(parents=True, exist_ok=True)

            counter_grapher = CounterGrapher(outpath=graph_file,
                                             counter=counter,
                                             title=title)
            # Make graph
            # getattr(counter_grapher, graph_type)()
            most_common_tables_md += "\n" + image(title, str(graph_file))

        ssh_md = attack.answers["ssh_analysis"] + "\n"
        if attack.ssh_sessions:
            ssh_md += collapseable_section(
                self.session_table(attack.ssh_sessions), "SSH Sessions", 3)

        if attack.telnet_sessions:
            ssh_md += collapseable_section(
                self.session_table(attack.telnet_sessions), "Telnet Sessions", 3)

        ssh_md += most_common_tables_md
        md += collapseable_section(ssh_md, "SSH/Telnet Sessions Analysis", 1)
        return md

    def add_ip_and_port_tables(self, md, attack: Attack):
        ip_md = attack.answers['ips_and_ports'] + '\n'
        n = 10

        ip_md += most_common_table("Source IP", attack.counts["src_ips"], n)
        ip_md += most_common_table("Destination IP",
                                   attack.counts["dst_ips"], n)
        ip_md += most_common_table("Source Port",
                                   attack.counts["src_ports"], n)
        ip_md += most_common_table("Destination Port",
                                   attack.counts["dst_ports"], n)

        md += collapseable_section(ip_md, "IP and Ports", 1)
        return md

    def command_analysis(self, attack: Attack):
        commands = attack.commands
        split_commands = attack.split_commands
        command_explanations = attack.command_explanations

        md = h1("Commands Used")
        md += f"This attack used a total of {code(len(commands))} inputs to execute the following {code(len(split_commands))} commands:\n"
        md += attack.answers['commands_analysis'] + '\n'

        raw_inputs_md = f"The attacker entered the following {code(len(commands))} inputs on the honeypot system:\n"

        for n, command in enumerate(commands):
            raw_inputs_md += "\n" + bold(f"Input {n + 1}:")
            raw_inputs_md += codeblock(command, "bash")

        md += collapseable_section(raw_inputs_md, "Raw Command Inputs", 2)

        commands_explained_md = f"The following {code(len(split_commands))} commands were executed on the honeypot system:\n"

        for command, explanation in command_explanations.items():
            commands_explained_md += codeblock(command, "bash")
            commands_explained_md += explanation

        md += collapseable_section(commands_explained_md,
                                   "Commands Explained", 2) + "\n"

        return md

    def malware_analysis(self, attack: Attack):
        malware = attack.malware
        standardized_malware = attack.standardized_malware
        standardized_malware_explanations = attack.standardized_malware_explanations

        md = h1("Malware Analysis")
        md += '\n' + attack.answers["malware_analysis"] + '\n'

        md += f"This attack downloaded {code(len(malware))} raw malware samples which can be standardized into {code(len(standardized_malware))} samples:\n"

        plural = "s" if len(standardized_malware) > 1 else ""

        md += h3(f"Raw Malware Sample{plural}")
        for n, sample in enumerate(standardized_malware.items()):
            standardized_shasum, mwobj_list = sample
            mwobj0 = mwobj_list[0]
            malware_language = standardized_malware_explanations[
                mwobj0.standardized_hash]["malware_language"]

            mw_md = f"{bold('Standardized')} Sha256 HASH: {code(standardized_shasum)}\n\n"
            mw_md += f"{bold('Sample Below')} Sha256 HASH: {code(mwobj0.shasum)}"
            mw_md += codeblock(remove_null_bytes(mwobj0.text),
                               malware_language)

            if len(mwobj_list) > 1:
                mw_md += f"{len(mwobj_list) - 1} more samples with the same {bold('Standardized')} Sha256 HASH were found:\n"
                mw_md += unordered_list(
                    [mwobj.shasum for mwobj in mwobj_list[1:]], style_fn=code)

            label = f"Raw Malware Sample {n}/{len(standardized_malware)} Sha256 HASH: {mwobj0.shasum}"
            md += collapseable_section(mw_md, label, 4)

        md += h3(f"Commented Malware Sample{plural} & Explanation{plural}")
        for n, sample in enumerate(standardized_malware_explanations.items()):
            standardized_shasum, result = sample

            commented_code = result["commented_code"]
            malware_language = result["malware_language"]
            malware_explanation = result["malware_explanation"]

            mw_md = codeblock(commented_code, malware_language)
            label = f"\nStandardized Malware Sample {n}/{len(standardized_malware)} Sha256 HASH: {standardized_shasum}"

            md += collapseable_section(mw_md, label, 4)
            md += malware_explanation + "\n"

        return md

    def http_analysis(self, attack: Attack):
        md = h1("HTTP Sessions Analysis")
        md += '\n' + attack.answers.get("http_sessions", "") + "\n"
        md += collapseable_section(
            self.session_table(attack.http_sessions), "HTTP Sessions", 3)

        md += '\n' + attack.answers.get("http_analysis", "") + "\n"
        return md

    def add_command_and_malware_analysis(self, md, attack: Attack):
        if attack.http_requests:
            md += self.http_analysis(attack)

        if attack.commands:
            md += self.command_analysis(attack)

        md += h1("Malware OSINT")
        md += '\n' + attack.answers["malware_osint_summary"] + '\n'

        if attack.malware:
            md += self.malware_analysis(attack)

        return md

    def add_vuln_analysis(self, md, attack: Attack):
        md += h1("Which vulnerability does the attack attempt to exploit?")
        md += attack.answers["vuln_analysis"] + "\n\n"
        md += h1("MITRE ATT&CK")
        md += attack.answers['mitre_attack'] + "\n"

        return md

    def add_questions(self, md, attack: Attack):
        add_keys = ['goal_of_attack', 'would_attack_be_successful',
                    'how_to_protect', 'what_iocs']

        for key in add_keys:
            question = attack.questions[key]
            md += h1(question.title())
            md += attack.answers[key] + "\n"

        return md
