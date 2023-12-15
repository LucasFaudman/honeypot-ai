

"""
Functions for OpenAI Analyzer tool_calls

https://platform.openai.com/docs/assistants/tools/function-calling
https://platform.openai.com/docs/guides/function-calling
https://cookbook.openai.com/examples/how_to_call_functions_with_chat_models
"""

TOOLS = [
            # Tool function schema for getting attrs of Attack object
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
                             "src_ips, src_ports, dst_ips, dst_ports, login_pairs, successful_login_pairs, ssh_hasshs, ssh_versions, "
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

            # Tool function schema for getting attrs of Session object
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

        # Tool function schema for getting attrs of Malware object
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
                            "description": 
                            "Attributes of the Malware object to get. Available attrs include: "
                            
                            "text: the text of the file, "
                            "shasum: the sha256 hash of the file, "
                            "source_address: the url or ip address where the was uploaded/downloaded from, "
                            "destfile: the name of the file on the honeypot, "
                            "urls: urls found in the file, "
                            "hosts: ips and domains found in the file, "
                            "num_bytes: the size of the file in bytes, "
                            "mime_type: the mime type of the file, ",
                             #"file_cmd_output: the output of the linux file command on the file, "
                             #"strings_cmd_output: the output of the linux strings command on the file. Only use this AFTER trying to get text first if file cannot be read as text., "

                            "items": {
                                "type": "string",
                                "enum": ["text", "shasum", "source_address", "destfile", "urls", "hosts", "num_bytes", "mime_type"]#, "file_cmd_output", "strings_cmd_output"]
                                      },

                            },
                    },
                    "required": ["malware_id", "attrs"]

                }
            }
        },

        
            # Tool function schema for querying IP data from OSINT sources: CyberGordon, Shodan, and ISC
            {
            "type": "function",
            "function": {
                "name": "query_ip_data",
                "description": "Query IP address data from OSINT sources.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ips": {"type": "array", 
                                "description": "A list of IP address(es) to query data for.",
                                "items": {"type": "string"}},
                        "sources": {"type": "array", 
                                    "description": 
                                        "The source(s) to get data from: "
                                        "cybergordon: IP data summaries from a variety of other OSINT sources, "
                                        "shodan: port & geolocation data, "
                                        "isc: geolocation & attack report counts from other honeypots",
                                    "items": {
                                        "type": "string",
                                        "enum": ["cybergordon", "shodan", "isc"]
                                        }},
                    },
                    "required": ["ip", "sources"]
                }
            }
        },


            # Tool function schema for querying IOC data from OSINT sources: ThreatFox, MalwareBazaar, and URLhaus
            {
            "type": "function",
            "function": {
                "name": "query_ioc_data",
                "description": "Query Indicator of Compromise data from OSINT sources. IOC(s) can be hashes, urls, domains, or ips.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ioc_type": {"type": "string",
                                    "description": "The type of IOC(s) to query data for",
                                    "enum": ["hash", "url", "domain", "ip"]}, 

                        "iocs": {"type": "array", 
                                "description": "A list of IOC(s) of type ioc_type to query data for",
                                "items": {"type": "string"}},


                        "sources": {"type": "array", 
                                    "description": 
                                        "The source(s) to get data from: "
                                        "threatfox: accepts all IOC types, "
                                        "urlhaus: accepts urls, domains, and ips only, "
                                        "malwarebazaar: accepts hashes only, ",
     
                                    "items": {
                                        "type": "string",
                                        "enum": ["threatfox", "urlhaus", "malwarebazaar"]
                                        }},
                    },
                    "required": ["ip", "ioc_type", "sources"]
                }
            }
        },
            # Tool function schema for querying Malpedia for malware descriptions
            {
            "type": "function",
            "function": {
                "name": "query_malpedia",
                "description": "Query Malpedia for detailed description of malware",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "malpedia_name": {
                            "type": "string", 
                            "description": "The malpedia_name of the malware to query for. (eg win.lumma, elf.mirai, etc). "
                            "malpedia_names to query can be found in the output of query_ioc_data function calls."
                        },
                    },  
                    "required": ["malpedia_name"]
                }
            }
        },
      ]

### UNUSED FOR NOW BUT ALL WORK AND MAY USE LATER FOR FLOW CONTROL ###

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



        #     {
        #     "type": "function",
        #     "function": {
        #         "name": "get_data_for_ips",
        #         "description": "Get data about an IP address from OSINT sources",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {
        #                 "ips": {"type": "array", 
        #                         "description": "The IP address(es) to get data for",
        #                         "items": {"type": "string"}},
        #                 "sources": {"type": "array", 
        #                             "description": 
        #                                 "The source(s) to get data from: "
        #                                 "cybergordon: list of report summaries from a variety of threat intel sources, "
        #                                 "shodan: port & geolocation data, "
        #                                 "threatfox: malware/IOC reports, "
        #                                 "isc: attack report counts from other honeypots",
        #                                 #"whois data: , ",
        #                             "items": {
        #                                 "type": "string",
        #                                 "enum": ["cybergordon", "shodan", "threatfox", "isc"]
        #                                 }},
        #             },
        #             "required": ["ip", "sources"]
        #         }
        #     }
        # },





  