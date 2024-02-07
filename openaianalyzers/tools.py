

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
                                "commands, http_requests, "
                                "sessions: Session object ids that can be queried with get_session_attrs, "
                                "malware: Malware object ids that can be queried with get_malware_attrs. "
                                "All attrs return items in chronological order and with duplicates when called without a modifier. "
                                "All attrs can be called with the following modifiers: "
                                "uniq_<attr>: unique items, "
                                "num_<attr>: number of items, "
                                "min_<attr>: minimum value, "
                                "max_<attr>: maximum value, "
                                "most_common_<attr>: most common value, "
                                "most_common<N>_<attr>: N most common values, "
                                "first<attr>: first item (chronologically), "
                                "last_<attr>: last item, "
                                "first<N>_<attr>: first N items, "
                                "last<N>_<attr>: last N items. "
                                "uniq_<attr> can be combined with any other modifier. "
                                "For example, 'first5_uniq_src_ips' returns the first 5 unique source IPs "
                                "and 'num_uniq_http_requests' returns the number of unique HTTP requests. "

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
                                "src_ip, src_port, dst_ip, dst_port, protocol, "
                                "username, password, start_time, end_time, duration, "
                                "ssh_hassh, ssh_version, client_vars, "
                                "commands, http_requests "
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
                            # "file_cmd_output: the output of the linux file command on the file, "
                            # "strings_cmd_output: the output of the linux strings command on the file. Only use this AFTER trying to get text first if file cannot be read as text., "

                            "items": {
                                "type": "string",
                                # , "file_cmd_output", "strings_cmd_output"]
                                "enum": ["text", "shasum", "source_address", "destfile", "urls", "hosts", "num_bytes", "mime_type"]
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


    # Tool function schema for querying ExploitDB for exploit search results
    {
        "type": "function",
        "function": {
                "name": "search_exploitdb",
                "description": "Search ExploitDB for exploit code containing the specified text",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "search_text": {
                            "type": "string",
                            "description": "The text to search for in the ExploitDB database. "
                            "The text should be code or a string literal that would be found in an exploit "
                            "and must be as specific as possible to avoid false positives. "
                            "(eg minio/admin/v3/update?updateURL=, pearcmd.php, )"
                        },
                    },
                    "required": ["search_text"]
                }
        }
    },


    # Tool function schema for querying ExploitDB for exploit details
    {
        "type": "function",
        "function": {
                "name": "get_exploitdb_exploit",
                "description": "Get details about an exploit from ExploitDB",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exploit_id": {
                            "type": "string",
                            "description": "The id of the exploit to get details for. "
                            "exploit_ids can be found in the output of search_exploitdb function calls."
                        },
                    },
                    "required": ["exploit_id"]
                }
        }
    },

]
