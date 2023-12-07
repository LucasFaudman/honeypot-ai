

"""
Functions for OpenAI Analyzer tool_calls

https://platform.openai.com/docs/assistants/tools/function-calling
https://platform.openai.com/docs/guides/function-calling
https://cookbook.openai.com/examples/how_to_call_functions_with_chat_models
"""

TOOLS = [

        #     {
        #     "type": "function",
        #     "function": {
        #         "name": "select_function",
        #         "description": "Select a function to call next based on current context",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {
        #                 "function_name": {
        #                     "type": "string", 
        #                     "description": "The name of the function to call next",
        #                     "enum": ["get_attack_attr", "list_attack_files", "get_file_content", "get_data_for_ips",]
        #                 },
        #             },
        #             "required": ["function_name"]
        #         }
        #     }
        # },

            {
            "type": "function",
            "function": {
                "name": "get_attack_attrs",
                "description": "Get an attributes of the Attack object",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "attrs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": 
                            "Attributes of the Attack object to get. Available attrs include: "
                             "src_ips, src_ports, dst_ips, dst_ports, all_login_pairs, successful_login_pairs, ssh_hasshs, ssh_versions, "
                             "commands, "
                             "sessions: Session object ids that can be queried with get_session_attrs,"
                             "malware: Malware object ids that can be queried with get_malware_attrs"
                             "All attrs return a list of items when called unmodified in chronological order with duplicates. "
                             "All attrs can be called with the following modifiers and modifiers may be combined: "
                             "uniq_<attr>: unique items, num_attr: number of items, min_<attr>: minimum value, max_<attr>: maximum value, "
                             "most_common_<attr>: most common value, most_commonN_<attr>: N most common values, "
                             "first<attr>: first item (chronologically), last_<attr>: last item, "
                             "firstN_<attr>: first N items, lastN_<attr>: last N items. ",
                                 
                            },
                    },
                    "required": ["attrs"]

                }
            }
        },

            {
            "type": "function",
            "function": {
                "name": "get_session_attrs",
                "description": "Get an attributes of a Session object by id",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "The id of the Session object to get attributes of"
                        },
                        "attrs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": 
                            "Attributes of the Session object to get. Available attrs include: "
                             "src_ip, src_port, dst_ip, dst_port, "
                             "username, password, start_time, end_time, duration, "
                             "ssh_hassh, ssh_version, client_vars, "
                             "commands"    
                            },
                    },
                    "required": ["session_id", "attr"]

                }
            }
        },

        {
            "type": "function",
            "function": {
                "name": "get_malware_attrs",
                "description": "Get an attributes of a Malware object by id",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "malware_id": {
                            "type": "string",
                            "description": "The id of the Malware object to get attributes of"
                        },
                        "attrs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": 
                            "Attributes of the Malware object to get. Available attrs include: "
                             "text: the text of the file, "
                             "source_address: the url or ip address where the file is from, "
                             "destfile: the name of the file on the honeypot, "
                             "shasum: the sha256 hash of the file, "
                             "ips: ips found in the file, "
                             "urls: urls found in the file, " 
                            },
                    },
                    "required": ["malware_id", "attrs"]

                }
            }
        },

        
        # {
        #     "type": "function",
        #     "function": {
        #         "name": "list_attack_files",
        #         "description": "Get a list of files of the specified type that available for analysis. Log files are presorted and only contain IPs used in the attack.",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {
        #                 "ftype": {
        #                     "type": "string", 
        #                     "description": 
        #                         "The the file type to get a list of. Available files types include: "
        #                         "files_from_attacker: files uploaded/downloaded to the honeypot by the attacker, "
        #                         "cowrie_SSH_session.log: logs from the SSH service running on the honeypot including auth attempts and command sessions, "
        #                         "webserver.log: logs from the simulated WordPress webserver running on the honeypot, "
        #                         "firewall.log: linux firewall logs, "
        #                         "zeek.log: logs produced by the Zeek/Bro tool breaking down network traffic by protocol.",

        #                     "enum": ["files_from_attacker", "cowrie_SSH_session.log", "webserver.log", "firewall.log", "zeek.log"]
        #                 },
        #             },
        #             "required": ["ftype"]
        #         }
        #     }
        # },

        # {
        #     "type": "function",
        #     "function": {
        #         "name": "get_file_content",
        #         "description": "Get the contents of a file",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {
        #                 "filename": {"type": "string", "description": "Name of file to get contents of"},
        #             },
        #             "required": ["filename"]
        #         }
        #     }
        # }, 



            {
            "type": "function",
            "function": {
                "name": "get_data_for_ips",
                "description": "Get data about an IP address from OSINT sources",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ips": {"type": "array", 
                                "description": "The IP address(es) to get data for",
                                "items": {"type": "string"}},
                        "sources": {"type": "array", 
                                    "description": 
                                        "The source(s) to get data from: "
                                        "cybergordon: list of report summaries from a variety of threat intel sources, "
                                        "shodan: port & geolocation data, "
                                        "threatfox: malware/IOC reports, "
                                        "isc: attack report counts from other honeypots",
                                        #"whois data: , ",
                                    "items": {
                                        "type": "string",
                                        "enum": ["cybergordon", "shodan", "threatfox", "isc"]
                                        }},
                    },
                    "required": ["ip", "source"]
                }
            }
        },

        ]